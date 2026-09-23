// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Buffers.Binary;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;

namespace Tmds.Ssh;

// Implements X11 forwarding for an SshSession.
// For each forwarded display, a fake authentication cookie is sent to the server.
// When the server opens an 'x11' channel, the fake cookie in the X11 connection setup message
// is replaced by the real cookie before the connection is forwarded to the local display.
sealed partial class X11Forwarding
{
    public const string AuthenticationProtocol = "MIT-MAGIC-COOKIE-1";

    // Address families from Xauth.h.
    internal const ushort FamilyInternet = 0; // internal for testing
    internal const ushort FamilyInternet6 = 6; // internal for testing
    internal const ushort FamilyLocal = 256; // internal for testing
    internal const ushort FamilyWild = 65535; // internal for testing

    private const int SetupHeaderLength = 12;
    private const int FakeCookieLength = 16;
    private const int BaseTcpPort = 6000;
    private const string UnixSocketDirectory = "/tmp/.X11-unix";

    // Like OpenSSH, the xauth timeout is extended so the cookie outlives ForwardX11Timeout.
    private const int UntrustedTimeoutSlackSeconds = 60;

    private static TimeSpan XAuthTimeout => TimeSpan.FromSeconds(30);

    private static readonly byte[] AuthenticationProtocolBytes = Encoding.ASCII.GetBytes(AuthenticationProtocol);

    internal sealed class AuthBinding
    {
        public required bool IsTrusted { get; init; }
        public required byte[] Cookie { get; init; }
        public required byte[] FakeCookie { get; init; }
        public long RefuseTimestamp { get; init; } // 0: connections are never refused.

        public string FakeCookieHex => Convert.ToHexString(FakeCookie).ToLowerInvariant();

        public bool IsExpired => RefuseTimestamp != 0 && Stopwatch.GetTimestamp() >= RefuseTimestamp;
    }

    internal readonly record struct XAuthorityEntry(ushort Family, byte[] Address, string Number, string Name, byte[] Data); // internal for testing

    private readonly ILogger<SshClient> _logger;
    private readonly Lock _gate = new();
    private readonly SemaphoreSlim _authBindingSemaphore = new(initialCount: 1); // Serializes GetOrCreateAuthBindingAsync.
    private readonly List<AuthBinding> _authBindings = new();

    // displayName: the display to forward to, or 'null' to use the DISPLAY environment variable.
    public X11Forwarding(string? displayName, ILogger<SshClient> logger)
    {
        if (string.IsNullOrEmpty(displayName))
        {
            displayName = Environment.GetEnvironmentVariable("DISPLAY");
        }
        if (string.IsNullOrEmpty(displayName))
        {
            throw new SshOperationException("X11 forwarding requires a display: DISPLAY is not set.");
        }
        if (!X11Display.TryParse(displayName, out X11Display? display))
        {
            throw new SshOperationException($"X11 forwarding failed: can not parse display '{displayName}'.");
        }

        Display = display;
        _logger = logger;
    }

    public X11Display Display { get; }

    public bool HasAuthBindings
    {
        get
        {
            lock (_gate)
            {
                return _authBindings.Count > 0;
            }
        }
    }

    public async Task<AuthBinding> GetOrCreateAuthBindingAsync(bool isTrusted, string? xauthorityFilePath, string xauthLocation, TimeSpan timeout, CancellationToken cancellationToken)
    {
        // Serialize so concurrent calls share a single binding instead of each generating authentication data.
        await _authBindingSemaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            lock (_gate)
            {
                // Connections for expired bindings are refused, so they no longer need to be kept.
                _authBindings.RemoveAll(authBinding => authBinding.IsExpired);

                foreach (var authBinding in _authBindings)
                {
                    if (authBinding.IsTrusted == isTrusted && !authBinding.IsExpired)
                    {
                        return authBinding;
                    }
                }
            }

            byte[]? cookie;
            long refuseTimestamp = 0;
            if (isTrusted)
            {
                xauthorityFilePath ??= GetDefaultXAuthorityFilePath();
                cookie = await FindCookieAsync(xauthorityFilePath, Display, cancellationToken).ConfigureAwait(false);
                if (cookie is null)
                {
                    // Like OpenSSH, use random data. The X server may accept the connection when it doesn't require authentication.
                    _logger.X11NoAuthenticationData(Display.Name, xauthorityFilePath);
                    cookie = RandomNumberGenerator.GetBytes(FakeCookieLength);
                }
            }
            else
            {
                try
                {
                    cookie = await GenerateUntrustedCookieAsync(xauthLocation, Display, timeout, cancellationToken).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    throw new SshOperationException($"Untrusted X11 forwarding setup failed: can not generate authentication data for display '{Display.Name}' using '{xauthLocation}'.", ex);
                }
                if (timeout > TimeSpan.Zero)
                {
                    refuseTimestamp = Stopwatch.GetTimestamp() + (long)Math.Min(timeout.TotalSeconds * Stopwatch.Frequency, long.MaxValue / 2);
                }
            }

            return AddAuthBinding(isTrusted, cookie, refuseTimestamp);
        }
        finally
        {
            _authBindingSemaphore.Release();
        }
    }

    internal AuthBinding AddAuthBinding(bool isTrusted, byte[] cookie, long refuseTimestamp = 0)
    {
        var authBinding = new AuthBinding()
        {
            IsTrusted = isTrusted,
            Cookie = cookie,
            FakeCookie = RandomNumberGenerator.GetBytes(cookie.Length),
            RefuseTimestamp = refuseTimestamp
        };
        lock (_gate)
        {
            _authBindings.Add(authBinding);
        }
        return authBinding;
    }

    public void HandleConnection(SshDataStream channelStream, string originatorAddress, uint originatorPort, CancellationToken connectionAborting)
        => _ = ForwardConnectionAsync(channelStream, $"{originatorAddress}:{originatorPort}", connectionAborting);

    private async Task ForwardConnectionAsync(SshDataStream channelStream, string sourceAddress, CancellationToken connectionAborting)
    {
        // Don't block the SshSession receive loop.
        await Task.Yield();

        Stream? displayStream = null;
        string? displayName = null;
        try
        {
            byte[] header = new byte[SetupHeaderLength];
            await channelStream.ReadExactlyAsync(header, connectionAborting).ConfigureAwait(false);
            if (!TryGetAuthenticationLengths(header, out int nameLength, out int dataLength))
            {
                _logger.X11ConnectionRejected(sourceAddress, "invalid connection setup message");
                return;
            }
            byte[] setupMessage = new byte[GetSetupMessageLength(nameLength, dataLength)];
            header.CopyTo(setupMessage, 0);
            await channelStream.ReadExactlyAsync(setupMessage.AsMemory(SetupHeaderLength), connectionAborting).ConfigureAwait(false);

            AuthBinding? authBinding = Authenticate(setupMessage);
            if (authBinding is null)
            {
                _logger.X11ConnectionRejected(sourceAddress, "authentication data does not match");
                return;
            }
            if (authBinding.IsExpired)
            {
                _logger.X11ConnectionRejected(sourceAddress, "ForwardX11Timeout expired");
                return;
            }

            displayName = Display.Name;
            _logger.X11ConnectionForward(sourceAddress, displayName);
            displayStream = await ConnectToDisplayAsync(Display, connectionAborting).ConfigureAwait(false);
            await displayStream.WriteAsync(setupMessage, connectionAborting).ConfigureAwait(false);

            await SshSession.ForwardStreamsAsync(channelStream, displayStream).ConfigureAwait(false);

            _logger.X11ConnectionClosed(sourceAddress, displayName);
        }
        catch (EndOfStreamException) when (displayName is null)
        {
            // The X11 client closed the connection before completing the connection setup.
            _logger.X11ConnectionRejected(sourceAddress, "connection closed during connection setup");
        }
        catch (Exception ex)
        {
            // Don't log when the connection is aborting.
            if (!connectionAborting.IsCancellationRequested)
            {
                _logger.X11ConnectionAborted(sourceAddress, displayName, ex);
            }
        }
        finally
        {
            channelStream.Dispose();
            displayStream?.Dispose();
        }
    }

    private static async Task<Stream> ConnectToDisplayAsync(X11Display display, CancellationToken cancellationToken)
    {
        if (display.SocketPath is not null)
        {
            return await Connect.ConnectUnixAsync(new UnixDomainSocketEndPoint(display.SocketPath), cancellationToken).ConfigureAwait(false);
        }

        // Windows X servers (like VcXsrv) don't listen on Unix sockets.
        if (display.Host is null && !Platform.IsWindows)
        {
            string path = $"{UnixSocketDirectory}/X{display.DisplayNumber}";
            if (OperatingSystem.IsLinux())
            {
                // Like OpenSSH, try the abstract socket first.
                try
                {
                    return await Connect.ConnectUnixAsync(new UnixDomainSocketEndPoint($"\0{path}"), cancellationToken).ConfigureAwait(false);
                }
                catch (SocketException)
                { }
            }
            return await Connect.ConnectUnixAsync(new UnixDomainSocketEndPoint(path), cancellationToken).ConfigureAwait(false);
        }

        return await Connect.ConnectTcpAsync(display.Host ?? "localhost", BaseTcpPort + display.DisplayNumber, cancellationToken).ConfigureAwait(false);
    }

    // Finds the binding for the fake authentication data of the setup message and replaces it with the real data.
    internal AuthBinding? Authenticate(Span<byte> setupMessage) // internal for testing
    {
        if (!TryGetAuthenticationLengths(setupMessage, out int nameLength, out int dataLength) ||
            setupMessage.Length != GetSetupMessageLength(nameLength, dataLength))
        {
            return null;
        }

        Span<byte> name = setupMessage.Slice(SetupHeaderLength, nameLength);
        Span<byte> data = setupMessage.Slice(SetupHeaderLength + Pad4(nameLength), dataLength);
        if (!name.SequenceEqual(AuthenticationProtocolBytes))
        {
            return null;
        }

        lock (_gate)
        {
            foreach (var authBinding in _authBindings)
            {
                if (CryptographicOperations.FixedTimeEquals(data, authBinding.FakeCookie))
                {
                    authBinding.Cookie.CopyTo(data);
                    return authBinding;
                }
            }
        }

        return null;
    }

    internal static bool TryGetAuthenticationLengths(ReadOnlySpan<byte> setupMessage, out int nameLength, out int dataLength) // internal for testing
    {
        /*
            X11 connection setup:
            CARD8     byte-order: 'B' (MSB first) or 'l' (LSB first)
            BYTE      unused
            CARD16    protocol-major-version
            CARD16    protocol-minor-version
            CARD16    n, length of authorization-protocol-name
            CARD16    d, length of authorization-protocol-data
            CARD16    unused
            STRING8   authorization-protocol-name
            p         unused, p=pad(n)
            STRING8   authorization-protocol-data
            q         unused, q=pad(d)
        */
        nameLength = 0;
        dataLength = 0;
        if (setupMessage.Length < SetupHeaderLength)
        {
            return false;
        }
        switch (setupMessage[0])
        {
            case (byte)'B':
                nameLength = BinaryPrimitives.ReadUInt16BigEndian(setupMessage.Slice(6));
                dataLength = BinaryPrimitives.ReadUInt16BigEndian(setupMessage.Slice(8));
                return true;
            case (byte)'l':
                nameLength = BinaryPrimitives.ReadUInt16LittleEndian(setupMessage.Slice(6));
                dataLength = BinaryPrimitives.ReadUInt16LittleEndian(setupMessage.Slice(8));
                return true;
            default:
                return false;
        }
    }

    internal static int GetSetupMessageLength(int nameLength, int dataLength) // internal for testing
        => SetupHeaderLength + Pad4(nameLength) + Pad4(dataLength);

    private static int Pad4(int length)
        => (length + 3) & ~3;

    private static string GetDefaultXAuthorityFilePath()
    {
        string? path = Environment.GetEnvironmentVariable("XAUTHORITY");
        return string.IsNullOrEmpty(path) ? Path.Combine(SshClientSettings.Home, ".Xauthority") : path;
    }

    // Returns the MIT-MAGIC-COOKIE-1 data for the display from the Xauthority file, or 'null' when there is none.
    internal static async Task<byte[]?> FindCookieAsync(string xauthorityFilePath, X11Display display, CancellationToken cancellationToken) // internal for testing
    {
        byte[] content;
        try
        {
            content = await File.ReadAllBytesAsync(xauthorityFilePath, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }

        List<(ushort Family, byte[] Address)> addresses = await GetAddressesAsync(display, cancellationToken).ConfigureAwait(false);
        return FindCookie(ParseXAuthorityEntries(content), display.DisplayNumber, addresses);
    }

    internal static byte[]? FindCookie(IEnumerable<XAuthorityEntry> entries, int displayNumber, List<(ushort Family, byte[] Address)> addresses) // internal for testing
    {
        foreach (var entry in entries)
        {
            if (entry.Name != AuthenticationProtocol ||
                !int.TryParse(entry.Number, NumberStyles.None, CultureInfo.InvariantCulture, out int entryDisplayNumber) ||
                entryDisplayNumber != displayNumber ||
                entry.Data.Length == 0)
            {
                continue;
            }
            if (entry.Family == FamilyWild)
            {
                return entry.Data;
            }
            foreach (var (family, address) in addresses)
            {
                if (entry.Family == family && entry.Address.AsSpan().SequenceEqual(address))
                {
                    return entry.Data;
                }
            }
        }
        return null;
    }

    internal static List<XAuthorityEntry> ParseXAuthorityEntries(ReadOnlySpan<byte> content) // internal for testing
    {
        /*
            Each entry is (integers are big-endian):
            uint16    family
            uint16    address length, followed by the address
            uint16    display number length, followed by the display number
            uint16    name length, followed by the name
            uint16    data length, followed by the data
        */
        List<XAuthorityEntry> entries = new();
        while (TryReadUInt16(ref content, out ushort family) &&
               TryReadBytes(ref content, out ReadOnlySpan<byte> address) &&
               TryReadBytes(ref content, out ReadOnlySpan<byte> number) &&
               TryReadBytes(ref content, out ReadOnlySpan<byte> name) &&
               TryReadBytes(ref content, out ReadOnlySpan<byte> data))
        {
            entries.Add(new XAuthorityEntry(family, address.ToArray(), Encoding.ASCII.GetString(number), Encoding.ASCII.GetString(name), data.ToArray()));
        }
        return entries;

        static bool TryReadUInt16(ref ReadOnlySpan<byte> content, out ushort value)
        {
            if (!BinaryPrimitives.TryReadUInt16BigEndian(content, out value))
            {
                return false;
            }
            content = content.Slice(2);
            return true;
        }

        static bool TryReadBytes(ref ReadOnlySpan<byte> content, out ReadOnlySpan<byte> value)
        {
            if (!TryReadUInt16(ref content, out ushort length) || content.Length < length)
            {
                value = default;
                return false;
            }
            value = content.Slice(0, length);
            content = content.Slice(length);
            return true;
        }
    }

    private static async Task<List<(ushort Family, byte[] Address)>> GetAddressesAsync(X11Display display, CancellationToken cancellationToken)
    {
        List<(ushort, byte[])> addresses = new();

        string localHostName = Dns.GetHostName();
        string? host = display.Host;
        IPAddress[] hostAddresses = [];
        if (host is not null)
        {
            if (IPAddress.TryParse(host, out IPAddress? ipAddress))
            {
                hostAddresses = [ipAddress];
            }
            else
            {
                try
                {
                    hostAddresses = await Dns.GetHostAddressesAsync(host, cancellationToken).ConfigureAwait(false);
                }
                catch (SocketException)
                { }
            }
        }

        // Like Xlib, connections to the local host are authorized using the local hostname.
        if (host is null ||
            hostAddresses.Any(IPAddress.IsLoopback) ||
            string.Equals(host, localHostName, StringComparison.OrdinalIgnoreCase))
        {
            addresses.Add((FamilyLocal, Encoding.ASCII.GetBytes(localHostName)));
        }
        foreach (var hostAddress in hostAddresses)
        {
            IPAddress address = hostAddress.IsIPv4MappedToIPv6 ? hostAddress.MapToIPv4() : hostAddress;
            ushort family = address.AddressFamily == AddressFamily.InterNetwork ? FamilyInternet : FamilyInternet6;
            addresses.Add((family, address.GetAddressBytes()));
        }

        return addresses;
    }

    private static async Task<byte[]> GenerateUntrustedCookieAsync(string xauthLocation, X11Display display, TimeSpan timeout, CancellationToken cancellationToken)
    {
        DirectoryInfo directory = Directory.CreateTempSubdirectory("tmds-ssh-xauth-");
        try
        {
            string filePath = Path.Combine(directory.FullName, "xauthfile");
            var psi = new ProcessStartInfo()
            {
                FileName = xauthLocation,
                ArgumentList = { "-q", "-f", filePath, "generate", display.XAuthDisplayName, AuthenticationProtocol, "untrusted" },
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false
            };
            if (timeout > TimeSpan.Zero)
            {
                double seconds = Math.Min(uint.MaxValue, Math.Ceiling(timeout.TotalSeconds) + UntrustedTimeoutSlackSeconds);
                psi.ArgumentList.Add("timeout");
                psi.ArgumentList.Add(((uint)seconds).ToString(CultureInfo.InvariantCulture));
            }

            using Process process = Process.Start(psi)!;
            process.StandardInput.Close();
            // xauth connects to the X server, don't wait indefinitely when it is unreachable.
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(XAuthTimeout);
            Task<string> readStdout = process.StandardOutput.ReadToEndAsync(timeoutCts.Token);
            Task<string> readStderr = process.StandardError.ReadToEndAsync(timeoutCts.Token);
            try
            {
                await process.WaitForExitAsync(timeoutCts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                try
                {
                    process.Kill();
                }
                catch
                { }

                cancellationToken.ThrowIfCancellationRequested();
                throw new TimeoutException($"'{xauthLocation}' did not complete within {XAuthTimeout.TotalSeconds} seconds.");
            }
            await readStdout.ConfigureAwait(false);
            string stderr = await readStderr.ConfigureAwait(false);

            if (process.ExitCode != 0)
            {
                throw new InvalidOperationException($"'{xauthLocation}' exited with code {process.ExitCode}: {stderr.Trim()}");
            }

            if (File.Exists(filePath))
            {
                foreach (var entry in ParseXAuthorityEntries(await File.ReadAllBytesAsync(filePath, cancellationToken).ConfigureAwait(false)))
                {
                    if (entry.Name == AuthenticationProtocol && entry.Data.Length > 0)
                    {
                        return entry.Data;
                    }
                }
            }

            throw new InvalidOperationException($"'{xauthLocation}' did not generate authentication data.");
        }
        finally
        {
            try
            {
                directory.Delete(recursive: true);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            { }
        }
    }
}

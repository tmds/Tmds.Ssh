// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Buffers;
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
    // internal for testing.
    internal const ushort FamilyInternet = 0;
    internal const ushort FamilyInternet6 = 6;
    internal const ushort FamilyLocal = 256;
    internal const ushort FamilyWild = 65535;

    private const int SetupHeaderLength = 12;
    private const int MaxSetupMessageLength = 1024;
    private const int FakeCookieLength = 16;
    private const int BaseTcpPort = 6000;
    private const string UnixSocketDirectory = "/tmp/.X11-unix";

    // Like OpenSSH, the xauth timeout is extended so the cookie outlives ForwardX11Timeout.
    private const int UntrustedTimeoutSlackSeconds = 60;


    private static ReadOnlySpan<byte> AuthenticationProtocolBytes => "MIT-MAGIC-COOKIE-1"u8;

    internal sealed class AuthBinding
    {
        public required bool IsTrusted { get; init; }
        public required byte[] Cookie { get; init; }
        public required byte[] FakeCookie { get; init; }
        public long RefuseTimestamp { get; init; } // 0: connections are never refused.

        public string FakeCookieHex => Convert.ToHexString(FakeCookie).ToLowerInvariant();

        public bool IsExpired => RefuseTimestamp != 0 && Stopwatch.GetTimestamp() >= RefuseTimestamp;
    }

    // internal for testing.
    internal readonly record struct XAuthorityEntry(ushort Family, byte[] Address, string Number, string Name, byte[] Data);

    private readonly ILogger<SshClient> _logger;
    private readonly X11Display? _display; // 'null' when DISPLAY is not set or can not be parsed.
    private readonly string _defaultXAuthorityFilePath;
    private readonly SemaphoreSlim _authBindingSemaphore = new(initialCount: 1); // Serializes GetOrCreateAuthBindingAsync.
    private AuthBinding? _trustedAuthBinding;
    private AuthBinding? _untrustedAuthBinding;

    // displayName: the display to forward to, or 'null' to use the DISPLAY environment variable.
    public X11Forwarding(string? displayName, ILogger<SshClient> logger)
    {
        if (string.IsNullOrEmpty(displayName))
        {
            displayName = Environment.GetEnvironmentVariable("DISPLAY");
        }
        if (!string.IsNullOrEmpty(displayName) && X11Display.TryParse(displayName, out X11Display? display))
        {
            _display = display;
        }
        _logger = logger;
        _defaultXAuthorityFilePath = GetDefaultXAuthorityFilePath();
    }

    public int ScreenNumber => Display.ScreenNumber;

    public bool HasAuthBindings => _trustedAuthBinding is not null || _untrustedAuthBinding is not null;

    private X11Display Display
    {
        get
        {
            Debug.Assert(_display is not null);
            return _display;
        }
    }

    public async Task<AuthBinding> GetOrCreateAuthBindingAsync(bool isTrusted, string? xauthorityFilePath, string xauthLocation, TimeSpan timeout, CancellationToken cancellationToken)
    {
        if (_display is null)
        {
            throw new InvalidOperationException("DISPLAY is not set or can not be parsed.");
        }

        // Serialize so concurrent calls share a single binding instead of each generating authentication data.
        await _authBindingSemaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if ((isTrusted ? _trustedAuthBinding : _untrustedAuthBinding) is { IsExpired: false } authBinding)
            {
                return authBinding;
            }

            byte[]? cookie;
            long refuseTimestamp = 0;
            if (isTrusted)
            {
                xauthorityFilePath ??= _defaultXAuthorityFilePath;
                cookie = await FindCookieAsync(xauthorityFilePath, Display, cancellationToken).ConfigureAwait(false);
                if (cookie is null)
                {
                    // Like OpenSSH, use random data. The X server may accept the connection when it doesn't require authentication.
                    _logger.X11ForwardNoAuthenticationData(Display.Name, xauthorityFilePath);
                    cookie = RandomNumberGenerator.GetBytes(FakeCookieLength);
                }
            }
            else
            {
                cookie = await GenerateUntrustedCookieAsync(xauthLocation, Display, timeout, cancellationToken).ConfigureAwait(false);
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

    // internal for testing.
    internal AuthBinding AddAuthBinding(bool isTrusted, byte[] cookie, long refuseTimestamp = 0)
    {
        var authBinding = new AuthBinding()
        {
            IsTrusted = isTrusted,
            Cookie = cookie,
            FakeCookie = RandomNumberGenerator.GetBytes(cookie.Length),
            RefuseTimestamp = refuseTimestamp
        };
        // This replaces an expired binding. Connections for it are refused, so it no longer needs to be kept.
        if (isTrusted)
        {
            _trustedAuthBinding = authBinding;
        }
        else
        {
            _untrustedAuthBinding = authBinding;
        }
        return authBinding;
    }

    public void HandleConnection(SshDataStream channelStream, string originatorAddress, uint originatorPort, CancellationToken cancellationToken)
        => _ = ForwardConnectionAsync(channelStream, $"{originatorAddress}:{originatorPort}", cancellationToken);

    private async Task ForwardConnectionAsync(SshDataStream channelStream, string sourceAddress, CancellationToken cancellationToken)
    {
        Stream? displayStream = null;
        byte[] buffer = ArrayPool<byte>.Shared.Rent(MaxSetupMessageLength);
        try
        {
            // Read the X11 connection setup message.
            await channelStream.ReadExactlyAsync(buffer.AsMemory(0, SetupHeaderLength), cancellationToken).ConfigureAwait(false);
            if (!TryGetAuthenticationLengths(buffer, out int nameLength, out int dataLength))
            {
                _logger.X11ForwardConnectionRejected(sourceAddress, "invalid connection setup message");
                return;
            }
            int setupLength = GetSetupMessageLength(nameLength, dataLength);
            if (setupLength > MaxSetupMessageLength)
            {
                _logger.X11ForwardConnectionRejected(sourceAddress, "connection setup message too large");
                return;
            }
            await channelStream.ReadExactlyAsync(buffer.AsMemory(SetupHeaderLength, setupLength - SetupHeaderLength), cancellationToken).ConfigureAwait(false);

            // Authenticate: verify the fake cookie and replace it with the real one.
            AuthBinding? authBinding = Authenticate(buffer.AsSpan(0, setupLength));
            if (authBinding is null)
            {
                _logger.X11ForwardConnectionRejected(sourceAddress, "authentication data does not match");
                return;
            }
            if (authBinding.IsExpired)
            {
                _logger.X11ForwardConnectionRejected(sourceAddress, "ForwardX11Timeout expired");
                return;
            }

            // Connect to the local display and forward the setup message.
            _logger.X11ForwardConnection(sourceAddress, Display.Name);
            displayStream = await ConnectToDisplayAsync(Display, cancellationToken).ConfigureAwait(false);
            await displayStream.WriteAsync(buffer.AsMemory(0, setupLength), cancellationToken).ConfigureAwait(false);

            ArrayPool<byte>.Shared.Return(buffer);
            buffer = null!;

            await SshSession.ForwardStreamsAsync(channelStream, displayStream).ConfigureAwait(false);

            _logger.X11ForwardConnectionClosed(sourceAddress, Display.Name);
        }
        catch (EndOfStreamException)
        {
            // The X11 client closed the connection before completing the connection setup.
            _logger.X11ForwardConnectionRejected(sourceAddress, "connection closed during connection setup");
        }
        catch (Exception ex) when (ex is not OperationCanceledException) // Don't log when the forwarding is stopped.
        {
            _logger.X11ForwardConnectionAborted(sourceAddress, Display.Name, ex);
        }
        finally
        {
            if (buffer is not null)
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
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
    // internal for testing.
    internal AuthBinding? Authenticate(Span<byte> setupMessage)
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

        foreach (AuthBinding? authBinding in (ReadOnlySpan<AuthBinding?>)[_trustedAuthBinding, _untrustedAuthBinding])
        {
            if (authBinding is not null && CryptographicOperations.FixedTimeEquals(data, authBinding.FakeCookie))
            {
                authBinding.Cookie.CopyTo(data);
                return authBinding;
            }
        }

        return null;
    }

    // internal for testing.
    internal static bool TryGetAuthenticationLengths(ReadOnlySpan<byte> setupMessage, out int nameLength, out int dataLength)
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

    // internal for testing.
    internal static int GetSetupMessageLength(int nameLength, int dataLength)
        => SetupHeaderLength + Pad4(nameLength) + Pad4(dataLength);

    private static int Pad4(int length)
        => (length + 3) & ~3;

    private static string GetDefaultXAuthorityFilePath()
    {
        string? path = Environment.GetEnvironmentVariable("XAUTHORITY");
        return string.IsNullOrEmpty(path) ? Path.Combine(SshClientSettings.Home, ".Xauthority") : path;
    }

    // Returns the MIT-MAGIC-COOKIE-1 data for the display from the Xauthority file, or 'null' when there is none.
    // internal for testing.
    internal static async Task<byte[]?> FindCookieAsync(string xauthorityFilePath, X11Display display, CancellationToken cancellationToken)
    {
        byte[] content;
        try
        {
            content = File.ReadAllBytes(xauthorityFilePath);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }

        List<(ushort Family, byte[] Address)> addresses = await GetAddressesAsync(display, cancellationToken).ConfigureAwait(false);
        return FindCookie(ParseXAuthorityEntries(content), display.DisplayNumber, addresses);
    }

    // internal for testing.
    internal static byte[]? FindCookie(IEnumerable<XAuthorityEntry> entries, int displayNumber, List<(ushort Family, byte[] Address)> addresses)
    {
        foreach (var entry in entries)
        {
            if (entry.Name != AuthenticationProtocol ||
                (entry.Number.Length > 0 && (!int.TryParse(entry.Number, NumberStyles.None, CultureInfo.InvariantCulture, out int entryDisplayNumber) || entryDisplayNumber != displayNumber)) ||
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

    // internal for testing.
    internal static List<XAuthorityEntry> ParseXAuthorityEntries(ReadOnlySpan<byte> content)
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

    private static async Task<byte[]> GenerateUntrustedCookieAsync(string xauthLocation, X11Display display, TimeSpan forwardTimeout, CancellationToken cancellationToken)
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
            if (forwardTimeout > TimeSpan.Zero)
            {
                double seconds = Math.Min(uint.MaxValue, Math.Ceiling(forwardTimeout.TotalSeconds) + UntrustedTimeoutSlackSeconds);
                psi.ArgumentList.Add("timeout");
                psi.ArgumentList.Add(((uint)seconds).ToString(CultureInfo.InvariantCulture));
            }

            using Process process = Process.Start(psi)!;
            process.StandardInput.Close();
            // Timeout for the xauth process. It connects to the X server and may hang when it is unreachable.
            const int XAuthTimeoutSeconds = 30;
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(TimeSpan.FromSeconds(XAuthTimeoutSeconds));
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
                throw new TimeoutException($"'{xauthLocation}' timed out.");
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

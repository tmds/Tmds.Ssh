// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Tmds.Ssh;

// Forwards Wayland connections using waypipe (https://gitlab.freedesktop.org/mstoeckl/waypipe), like 'waypipe ssh':
// - a local 'waypipe client' listens on a local Unix socket and connects to the local Wayland compositor,
// - a remote Unix socket is forwarded to that local socket using SshClient.StartRemoteForwardAsync,
// - the remote command is run by 'waypipe server' which connects to the remote socket and sets WAYLAND_DISPLAY for the command.
//
// This only uses the public Tmds.Ssh API, so you can copy this file into your own application.
//
// Requirements:
// - waypipe on the client and on the server,
// - a local Wayland compositor (WAYLAND_DISPLAY must be set),
// - a server that allows Unix socket ('streamlocal') remote forwarding (AllowStreamLocalForwarding, enabled by default in OpenSSH)
//   and that runs commands with a POSIX '/bin/sh'.
//
// Usage:
//   using var waypipe = await WaypipeForward.StartAsync(client);
//   using var process = await client.ExecuteAsync(waypipe.CreateRemoteCommand("weston-terminal"), executeOptions);
//   // Dispose the process before disposing the forward.
sealed class WaypipeForward : IDisposable
{
    private static readonly TimeSpan ClientStartTimeout = TimeSpan.FromSeconds(10);

    private readonly ILogger? _logger;
    private readonly string _remoteWaypipeLocation;
    private readonly IReadOnlyList<string> _waypipeArguments;
    private Process? _clientProcess;
    private RemoteForward? _remoteForward;
    private bool _disposed;

    // The local Unix socket that 'waypipe client' listens on.
    public string LocalSocketPath { get; }
    // The Unix socket on the server that is forwarded to LocalSocketPath.
    public string RemoteSocketPath { get; }
    // The WAYLAND_DISPLAY name that 'waypipe server' sets for the command.
    public string RemoteDisplay { get; }

    private WaypipeForward(ILogger? logger, string remoteWaypipeLocation, IReadOnlyList<string> waypipeArguments, string localDirectory, string id)
    {
        _logger = logger;
        _remoteWaypipeLocation = remoteWaypipeLocation;
        _waypipeArguments = AddDefaultArguments(waypipeArguments);
        LocalSocketPath = Path.Combine(localDirectory, $"ssh-waypipe-client-{id}.sock");
        RemoteSocketPath = $"/tmp/waypipe-server-{id}.sock";
        RemoteDisplay = $"wayland-{id}";
    }

    public static async Task<WaypipeForward> StartAsync(
        SshClient client,
        ILogger? logger = null,
        string waypipeLocation = "waypipe",
        string remoteWaypipeLocation = "waypipe",
        IReadOnlyList<string>? waypipeArguments = null,
        CancellationToken cancellationToken = default)
    {
        string id = Convert.ToHexString(RandomNumberGenerator.GetBytes(8)).ToLowerInvariant();

        // Like waypipe, prefer XDG_RUNTIME_DIR for the local socket.
        string? runtimeDirectory = Environment.GetEnvironmentVariable("XDG_RUNTIME_DIR");
        string localDirectory = !string.IsNullOrEmpty(runtimeDirectory) && Directory.Exists(runtimeDirectory) ? runtimeDirectory : Path.GetTempPath();

        var forward = new WaypipeForward(logger, remoteWaypipeLocation, waypipeArguments ?? [], localDirectory, id);
        try
        {
            await forward.StartClientAsync(waypipeLocation, cancellationToken).ConfigureAwait(false);

            forward._remoteForward = await client.StartRemoteForwardAsync(
                new RemoteUnixEndPoint(forward.RemoteSocketPath),
                new UnixDomainSocketEndPoint(forward.LocalSocketPath),
                cancellationToken).ConfigureAwait(false);

            logger?.LogInformation("Forwarding Wayland using waypipe from '{RemoteSocketPath}' to '{LocalSocketPath}'", forward.RemoteSocketPath, forward.LocalSocketPath);

            return forward;
        }
        catch
        {
            forward.Dispose();

            throw;
        }
    }

    private async Task StartClientAsync(string waypipeLocation, CancellationToken cancellationToken)
    {
        var psi = new ProcessStartInfo()
        {
            FileName = waypipeLocation,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };
        foreach (var argument in _waypipeArguments)
        {
            psi.ArgumentList.Add(argument);
        }
        psi.ArgumentList.Add("--socket");
        psi.ArgumentList.Add(LocalSocketPath);
        psi.ArgumentList.Add("client");

        Process process;
        try
        {
            process = Process.Start(psi)!;
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"Wayland forwarding setup failed: can not start '{waypipeLocation}'.", ex);
        }
        _clientProcess = process;

        // The output is collected while starting so it can be included in the exception when the client fails to start.
        // Once started, the output is only logged so it doesn't accumulate for long running clients.
        StringBuilder? startupOutput = new();
        object outputGate = new();
        DataReceivedEventHandler handler = (o, e) =>
        {
            if (e.Data is null)
            {
                return;
            }
            lock (outputGate)
            {
                startupOutput?.AppendLine(e.Data);
            }
            _logger?.LogDebug("waypipe: {Line}", e.Data);
        };
        process.OutputDataReceived += handler;
        process.ErrorDataReceived += handler;
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();
        process.StandardInput.Close();

        // Wait for the client to create its socket.
        long startTime = Stopwatch.GetTimestamp();
        while (!File.Exists(LocalSocketPath))
        {
            if (process.HasExited)
            {
                // Ensure all output is received.
                process.WaitForExit();
                string message;
                lock (outputGate)
                {
                    message = startupOutput!.ToString().Trim();
                }
                throw new InvalidOperationException($"Wayland forwarding setup failed: '{waypipeLocation}' exited with code {process.ExitCode}: {message}");
            }
            if (Stopwatch.GetElapsedTime(startTime) > ClientStartTimeout)
            {
                throw new TimeoutException($"Wayland forwarding setup failed: '{waypipeLocation}' did not create socket '{LocalSocketPath}'.");
            }
            await Task.Delay(20, cancellationToken).ConfigureAwait(false);
        }

        lock (outputGate)
        {
            startupOutput = null;
        }
    }

    // Returns the remote command that runs 'command' with Wayland forwarding. When command is null, a login shell is run.
    public string CreateRemoteCommand(string? command)
    {
        // The SSH server runs the command using the user's shell, which may not be a POSIX shell.
        // The waypipe invocation is run by '/bin/sh', and the user command is passed as an argument so it is quoted only once.
        // waypipe then runs the command using the user's shell, like the SSH server does.
        StringBuilder sb = new();
        sb.Append("exec ");
        sb.Append(QuoteArgument(_remoteWaypipeLocation));
        foreach (var argument in _waypipeArguments)
        {
            sb.Append(' ');
            sb.Append(QuoteArgument(argument));
        }
        sb.Append(" --socket ");
        sb.Append(QuoteArgument(RemoteSocketPath));
        // waypipe places a display name in XDG_RUNTIME_DIR. When the server doesn't set XDG_RUNTIME_DIR (e.g. no login session manager),
        // use an absolute path instead. RemoteDisplay only contains [a-z0-9-] so it doesn't need to be quoted.
        sb.Append(" --display \"$([ -n \"$XDG_RUNTIME_DIR\" ] && printf '%s' '");
        sb.Append(RemoteDisplay);
        sb.Append("' || printf '%s' '/tmp/");
        sb.Append(RemoteDisplay);
        sb.Append("')\"");
        // The socket is created by the SSH server for the forward, remove it when waypipe exits.
        sb.Append(" --unlink-socket");
        if (command is null)
        {
            // Like 'ssh' without a command, run a login shell.
            sb.Append(" --login-shell server");
        }
        else
        {
            sb.Append(" server -- \"${SHELL:-/bin/sh}\" -c \"$1\"");
        }

        string remoteCommand = $"/bin/sh -c {QuoteArgument(sb.ToString())}";
        if (command is not null)
        {
            // $0 and $1 of the /bin/sh script.
            remoteCommand += $" sh {QuoteArgument(command)}";
        }
        return remoteCommand;
    }

    // The client and the server must use the same compression. Their defaults differ between waypipe versions
    // (e.g. the 0.8 server defaults to 'none' while the 0.9 client defaults to 'lz4'), so like 'waypipe ssh' we set it explicitly.
    private static IReadOnlyList<string> AddDefaultArguments(IReadOnlyList<string> arguments)
    {
        foreach (var argument in arguments)
        {
            if (argument.StartsWith("--compress", StringComparison.Ordinal) ||
                (argument.StartsWith("-c", StringComparison.Ordinal) && !argument.StartsWith("--", StringComparison.Ordinal)))
            {
                return arguments;
            }
        }
        return ["--compress=lz4", ..arguments];
    }

    // Quotes an argument for a POSIX shell.
    private static string QuoteArgument(string argument)
        => $"'{argument.Replace("'", "'\\''")}'";

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;

        bool wasStarted = _remoteForward is not null;
        _remoteForward?.Dispose();

        Process? process = _clientProcess;
        if (process is not null)
        {
            try
            {
                if (!process.HasExited)
                {
                    process.Kill(entireProcessTree: true);
                    process.WaitForExit(TimeSpan.FromSeconds(5));
                }
            }
            catch (Exception ex) when (ex is InvalidOperationException or SystemException)
            { }
            process.Dispose();
        }

        try
        {
            File.Delete(LocalSocketPath);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        { }

        if (wasStarted)
        {
            _logger?.LogInformation("Stopped Wayland forwarding from '{RemoteSocketPath}'", RemoteSocketPath);
        }
    }
}

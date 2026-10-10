// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using Microsoft.Extensions.Logging;

namespace Tmds.Ssh;

/// <summary>
/// Context for a banner message sent by the server during authentication.
/// </summary>
public struct BannerMessageContext
{
    private ILogger<SshClient> _logger;

    internal BannerMessageContext(string message, SshConnectionInfo connectionInfo, ILogger<SshClient> logger)
    {
        Message = message;
        ConnectionInfo = connectionInfo;
        _logger = logger;
    }

    /// <summary>
    /// Gets the banner message.
    /// </summary>
    /// <remarks>
    /// The message may be empty and may span multiple lines. Control characters other than tab,
    /// carriage return, and newline are replaced by escape sequences, so the message is safe to
    /// write to a terminal.
    /// </remarks>
    public string Message { get; }

    /// <summary>
    /// Gets the SSH connection information.
    /// </summary>
    public SshConnectionInfo ConnectionInfo { get; }

    /// <summary>
    /// Logs the banner message at <c>Information</c> level.
    /// </summary>
    public void Log()
    {
        _logger?.Banner(Message);
    }
}

/// <summary>
/// Delegate for handling banner messages sent by the server.
/// </summary>
/// <param name="context">The banner message context.</param>
/// <remarks>
/// The server may send a banner at any time after the authentication protocol starts and before
/// authentication succeeds, and may send several. The next packet is not read until the delegate
/// returns.
/// </remarks>
public delegate void BannerHandler(BannerMessageContext context);

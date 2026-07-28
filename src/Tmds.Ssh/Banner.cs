// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

/// <summary>
/// Context for a banner message sent by the server during authentication.
/// </summary>
public struct BannerContext
{
    internal BannerContext(string message, string languageTag, SshConnectionInfo connectionInfo)
    {
        Message = message;
        LanguageTag = languageTag;
        ConnectionInfo = connectionInfo;
    }

    /// <summary>
    /// Gets the banner message.
    /// </summary>
    /// <remarks>
    /// The message is under the control of the server. It may be empty, span multiple lines, and
    /// contain control characters. Treat it as untrusted when displaying it to a user.
    /// </remarks>
    public string Message { get; }

    /// <summary>
    /// Gets the language tag of the message, as described in RFC 3066. Often empty.
    /// </summary>
    public string LanguageTag { get; }

    /// <summary>
    /// Gets the SSH connection information.
    /// </summary>
    public SshConnectionInfo ConnectionInfo { get; }

    /// <summary>
    /// Returns whether batch (non-interactive) mode is enabled.
    /// </summary>
    /// <remarks>
    /// In batch mode the <see cref="BannerHandler"/> delegate mustn't make interactive prompts.
    /// </remarks>
    public bool IsBatchMode => ConnectionInfo.IsBatchMode;
}

/// <summary>
/// Delegate for handling banner messages sent by the server.
/// </summary>
/// <param name="context">The banner context.</param>
/// <param name="cancellationToken">Token to cancel the operation.</param>
/// <remarks>
/// The server may send a banner at any time after the authentication protocol starts and before
/// authentication succeeds, and may send several. Authentication does not continue until the
/// delegate completes, so a delegate that waits for the user also delays the connection. Bear in
/// mind that <see cref="SshClientSettings.ConnectTimeout"/> bounds the entire authenticated
/// connect, including time spent in this delegate.
/// </remarks>
public delegate ValueTask BannerHandler(BannerContext context, CancellationToken cancellationToken);

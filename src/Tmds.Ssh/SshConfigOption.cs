// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

/// <summary>
/// OpenSSH sshd_config options.
/// </summary>
public enum SshConfigOption
{
    // SshConfigOption is meant for unconditionally setting options through code
    // so we don't provide option names that are meant for conditionals or including config files
    // Host,
    // Match,
    // Include,

    /// <summary>
    /// Hostname to connect to.
    /// </summary>
    Hostname,

    /// <summary>
    /// User to authenticate as.
    /// </summary>
    User,

    /// <summary>
    /// Port number to connect to.
    /// </summary>
    Port,

    /// <summary>
    /// Timeout (in seconds) for establishing the SSH connection.
    /// </summary>
    ConnectTimeout,

    /// <summary>
    /// Files to use for the global known hosts keys.
    /// </summary>
    GlobalKnownHostsFile,

    /// <summary>
    /// Files to use for the user known hosts keys.
    /// </summary>
    UserKnownHostsFile,

    /// <summary>
    /// Hash host names and addresses when they are added to known_hosts.
    /// </summary>
    HashKnownHosts,

    /// <summary>
    /// Controls addition of host keys to known_hosts file and behavior when host keys change.
    /// </summary>
    StrictHostKeyChecking,

    /// <summary>
    /// Authentication methods allowed and their order of preference.
    /// </summary>
    PreferredAuthentications,

    /// <summary>
    /// Whether to try public key authentication.
    /// </summary>
    PubkeyAuthentication,

    /// <summary>
    /// File from which the user's key is read.
    /// </summary>
    IdentityFile,

    /// <summary>
    /// Whether user authentication based on GSSAPI is allowed.
    /// </summary>
    GSSAPIAuthentication,

    /// <summary>
    /// Forward (delegate) GSSAPI credentials to the server.
    /// </summary>
    GSSAPIDelegateCredentials,

    /// <summary>
    /// GSSAPI server identity expected when connecting to the server.
    /// </summary>
    GSSAPIServerIdentity,

    /// <summary>
    /// Minimum RSA key size (in bits).
    /// </summary>
    RequiredRSASize,

    /// <summary>
    /// Environment variables to set when executing remote processes.
    /// </summary>
    SendEnv,

    /// <summary>
    /// Ciphers allowed and their order of preference.
    /// </summary>
    Ciphers,

    /// <summary>
    /// Host key signature algorithms allowed and their order of preference.
    /// </summary>
    HostKeyAlgorithms,

    /// <summary>
    /// KEX (Key Exchange) algorithms allowed and their order of preference.
    /// </summary>
    KexAlgorithms,

    /// <summary>
    /// MAC (message authentication code) algorithms allowed and their order of preference.
    /// </summary>
    MACs,

    /// <summary>
    /// Signature algorithms for public key authentication allowed and their order of preference.
    /// </summary>
    PubkeyAcceptedAlgorithms,

    /// <summary>
    /// Whether to send TCP keepalive messages.
    /// </summary>
    TCPKeepAlive,

    /// <summary>
    /// Number of server alive messages that may be sent without receiving a response.
    /// </summary>
    ServerAliveCountMax,

    /// <summary>
    /// Timeout interval (in seconds) after which a server alive message is sent.
    /// </summary>
    ServerAliveInterval,

    /// <summary>
    /// Only use configured authentication identity and certificate files. Do not use SSH agent credentials.
    /// </summary>
    IdentitiesOnly,

    /// <summary>
    /// Jump proxies to use.
    /// </summary>
    ProxyJump,

    /// <summary>
    /// Algorithms allowed for signing certificates by certificate authorities (CAs).
    /// </summary>
    CASignatureAlgorithms,

    /// <summary>
    /// File from which the user's certificate is read.
    /// </summary>
    CertificateFile,

    /// <summary>
    /// Whether to use password authentication.
    /// </summary>
    PasswordAuthentication,

    /// <summary>
    /// Disable user interaction such as password prompts and host key confirmation requests.
    /// </summary>
    BatchMode
}
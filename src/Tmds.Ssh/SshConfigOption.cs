// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

public enum SshConfigOption
{
    // SshConfigOption is meant for unconditionally setting options through code
    // so we don't provide option names that are meant for conditionals or including config files
    // Host,
    // Match,
    // Include,

    Hostname,
    User,
    Port,
    ConnectTimeout,
    GlobalKnownHostsFile,
    UserKnownHostsFile,
    HashKnownHosts,
    StrictHostKeyChecking,
    PreferredAuthentications,
    PubkeyAuthentication,
    IdentityFile,
    GSSAPIAuthentication,
    GSSAPIDelegateCredentials,
    GSSAPIServerIdentity,
    RequiredRSASize,
    SendEnv,
    Ciphers,
    HostKeyAlgorithms,
    KexAlgorithms,
    MACs,
    PubkeyAcceptedAlgorithms,
    TCPKeepAlive,
    ServerAliveCountMax,
    ServerAliveInterval,
    IdentitiesOnly,
    ProxyJump,
    CASignatureAlgorithms,
}
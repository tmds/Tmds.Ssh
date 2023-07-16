// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh
{
    enum SshOption : uint
    {
        Host,
        Port,
        _PORT_STR,
        _FD,
        User,
        _SSH_DIR,
        _IDENTITY,
        _ADD_IDENTITY,
        KnownHosts,
        _TIMEOUT,
        _TIMEOUT_USEC,
        _SSH1,
        _SSH2,
        LogVerbosity,
        _LOG_VERBOSITY_STR,
        _CIPHERS_C_S,
        _CIPHERS_S_C,
        _COMPRESSION_C_S,
        _COMPRESSION_S_C,
        _PROXYCOMMAND,
        _BINDADDR,
        _STRICTHOSTKEYCHECK,
        _COMPRESSION,
        _COMPRESSION_LEVEL,
        _KEY_EXCHANGE,
        _HOSTKEYS,
        _GSSAPI_SERVER_IDENTITY,
        _GSSAPI_CLIENT_IDENTITY,
        _GSSAPI_DELEGATE_CREDENTIALS,
        _HMAC_C_S,
        _HMAC_S_C,
        _PASSWORD_AUTH,
        _PUBKEY_AUTH,
        _KBDINT_AUTH,
        _GSSAPI_AUTH,
        GlobalKnownHosts,
        _NODELAY,
        _PUBLICKEY_ACCEPTED_TYPES,
        _PROCESS_CONFIG,
        _REKEY_DATA,
        _REKEY_TIME,
    }
}
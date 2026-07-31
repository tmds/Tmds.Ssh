// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using Microsoft.Extensions.Logging;
using System.Diagnostics;
using System.Text;

namespace Tmds.Ssh;

sealed class UserAuthContext
{
    private readonly SshConnection _connection;
    private readonly SshConnectionInfo _connectionInfo;
    private readonly BannerMessageHandler? _bannerMessageHandler;
    private readonly ILogger<SshClient> _logger;
    private readonly HashSet<SshKeyData> _publicKeysToSkip = new(); // track keys that were already attempted.
    private HashSet<Name>? _acceptedPublicKeyAlgorithms; // Allowed algorithms by config/server.
    private readonly HashSet<Name> _supportedAcceptedPublicKeyAlgorithms; // Algorithms the library supports.
    private readonly HashSet<Name>? _allowedSignatureAlgorithms; // Algorithms the server accepts.
    private int _bannerPacketCount = 0;
    private bool _msgInfoReceived = false;
    private Name[]? _allowedAuthentications;
    private AuthResult _authResult;
    private Name _currentMethod;

    public UserAuthContext(SshConnection connection, string userName,
        IReadOnlyList<Name>? acceptedPublicKeyAlgorithms, // what the client is allowed to accept
        IReadOnlyList<Name> supportedPublicKeyAlgorithms, // what the library supports
        IReadOnlyList<Name>? allowedSignatureAlgorithms,  // what the server accepts
        int minimumRSAKeySize,
        SshConnectionInfo connectionInfo,
        BannerMessageHandler? bannerMessageHandler,
        ILogger<SshClient> logger)
    {
        _connection = connection;
        _connectionInfo = connectionInfo;
        _bannerMessageHandler = bannerMessageHandler;
        _logger = logger;
        UserName = userName;
        _supportedAcceptedPublicKeyAlgorithms = new HashSet<Name>(supportedPublicKeyAlgorithms);
        MinimumRSAKeySize = minimumRSAKeySize;

        if (acceptedPublicKeyAlgorithms is not null)
        {
            FilterAcceptedPublicKeyAlgorithms(acceptedPublicKeyAlgorithms);
        }

        if (allowedSignatureAlgorithms is not null)
        {
            _allowedSignatureAlgorithms = new HashSet<Name>(allowedSignatureAlgorithms);
        }
    }

    public string UserName { get; }

    public SequencePool SequencePool => _connection.SequencePool;

    private void FilterAcceptedPublicKeyAlgorithms(IReadOnlyCollection<Name> names)
    {
        if (_acceptedPublicKeyAlgorithms is null)
        {
            _acceptedPublicKeyAlgorithms = new HashSet<Name>(names);
        }
        else
        {
            _acceptedPublicKeyAlgorithms.IntersectWith(names);
        }
        _supportedAcceptedPublicKeyAlgorithms.IntersectWith(names);
    }

    public IReadOnlyCollection<Name> SupportedAcceptedPublicKeyAlgorithms => _supportedAcceptedPublicKeyAlgorithms;

    public IReadOnlyCollection<Name>? AcceptedPublicKeyAlgorithms => _acceptedPublicKeyAlgorithms;

    public IReadOnlyCollection<Name>? AcceptedPublicKeySignatureAlgorithms => _allowedSignatureAlgorithms;

    public int MinimumRSAKeySize { get; }

    public async ValueTask<Packet> ReceivePacketAsync(CancellationToken ct, int maxLength = Constants.PreAuthMaxPacketLength)
    {
        if (_currentMethod.IsEmpty)
        {
            throw new InvalidOperationException();
        }

        while (true)
        {
            var packet = await _connection.ReceivePacketAsync(ct, maxLength);
            if (packet.IsEmpty)
            {
                ThrowHelper.ThrowProtocolUnexpectedPeerClose();
            }

            MessageId messageId = packet.MessageId!.Value;

            // https://datatracker.ietf.org/doc/html/rfc8308#section-2.4
            // The server may send SSH_MSG_EXT_INFO preceeding SSH_MSG_USERAUTH_SUCCESS.
            if (_msgInfoReceived && messageId != MessageId.SSH_MSG_USERAUTH_SUCCESS)
            {
                packet.Dispose();
                ThrowHelper.ThrowProtocolUnexpectedMessageId(messageId);
            }
            else if (messageId == MessageId.SSH_MSG_EXT_INFO)
            {
                packet.Dispose();
                _msgInfoReceived = true;
            }
            else if (messageId == MessageId.SSH_MSG_USERAUTH_BANNER)
            {
                /* The SSH server may send an SSH_MSG_USERAUTH_BANNER message at any
                   time after this authentication protocol starts and before
                   authentication is successful. */

                BannerMessageHandler? bannerMessageHandler = _bannerMessageHandler;
                BannerMessageContext bannerMessageContext = default;
                try
                {
                    // Check the limit before parsing or invoking user code. Preserve the existing
                    // counting semantics while ensuring an over-limit packet is not observed.
                    if (_bannerPacketCount++ > Constants.MaxBannerPackets)
                    {
                        ThrowHelper.ThrowBannerTooLong();
                    }

                    if (bannerMessageHandler is not null)
                    {
                        bannerMessageContext = ParseBanner(packet, _connectionInfo);
                    }
                }
                finally
                {
                    packet.Dispose();
                }

                if (bannerMessageHandler is not null)
                {
                    bannerMessageHandler(bannerMessageContext);
                }
            }
            else
            {
                if (messageId == MessageId.SSH_MSG_USERAUTH_FAILURE)
                {
                    ParseAuthFail(packet);

                    _currentMethod = default;
                }
                else if (messageId == MessageId.SSH_MSG_USERAUTH_SUCCESS)
                {
                    _authResult = AuthResult.Success;
                    _logger.Authenticated(_currentMethod);
                    _currentMethod = default;
                }

                return packet;
            }
        }
    }

    public ValueTask SendPacketAsync(Packet packet, CancellationToken ct)
    {
        if (_currentMethod.IsEmpty)
        {
            throw new InvalidOperationException();
        }

        return _connection.SendPacketAsync(packet, ct);
    }

    public async Task<AuthResult> ReceiveAuthResultAsync(CancellationToken ct)
    {
        using Packet response = await ReceivePacketAsync(ct).ConfigureAwait(false);
        return GetAuthResult(response);
    }

    public AuthResult AuthResult => _authResult;

    private AuthResult GetAuthResult(ReadOnlyPacket packet)
    {
        var reader = packet.GetReader();
        MessageId b = reader.ReadMessageId();
        switch (b)
        {
            case MessageId.SSH_MSG_USERAUTH_SUCCESS:
            case MessageId.SSH_MSG_USERAUTH_FAILURE:
                return _authResult;
            default:
                ThrowHelper.ThrowDataUnexpectedValue();
                return AuthResult.Failure;
        }
    }

    public bool IsSkipPublicAuthKey(SshKeyData publicKey)
    {
        Debug.Assert(!publicKey.IsDefault);
        return _publicKeysToSkip.Contains(publicKey);
    }

    public void AddPublicAuthKeyToSkip(SshKeyData publicKey)
    {
        Debug.Assert(!publicKey.IsDefault);
        _publicKeysToSkip.Add(publicKey);
    }

    public bool? IsMethodAccepted(Name method)
    {
        if (_allowedAuthentications == null)
        {
            return null;
        }
        // Servers don't return when 'none' is allowed.
        if (method == AlgorithmNames.None)
        {
            return null;
        }
        return Array.IndexOf(_allowedAuthentications, method) >= 0;
    }

    public void StartAuth(Name method)
    {
        Debug.Assert(_currentMethod.IsEmpty);
        Debug.Assert(IsMethodAccepted(method) != false);

        _currentMethod = method;
        _authResult = AuthResult.None;
    }

    public void SetFailed()
    {
        _currentMethod = default;
        _authResult = AuthResult.Failure;
    }

    internal static BannerMessageContext ParseBanner(ReadOnlyPacket packet, SshConnectionInfo connectionInfo)
    {
        var reader = packet.GetReader();
        /*
            byte         SSH_MSG_USERAUTH_BANNER
            string       message in ISO-10646 UTF-8 encoding [RFC3629]
            string       language tag [RFC3066]
        */
        reader.ReadMessageId(MessageId.SSH_MSG_USERAUTH_BANNER);
        string message = reader.ReadUtf8String();
        reader.SkipString(); // language tag
        reader.ReadEnd();

        return new BannerMessageContext(EscapeControlCharacters(message), connectionInfo);
    }

    // Match OpenSSH: keep tab, carriage return, and newline; replace other control
    // characters by an octal escape sequence per UTF-8 byte (RFC 4251 section 9.2).
    internal static string EscapeControlCharacters(string message)
    {
        StringBuilder? builder = null;
        int copiedUpTo = 0;
        int index = 0;
        Span<byte> utf8 = stackalloc byte[4];

        foreach (Rune rune in message.EnumerateRunes())
        {
            if (Rune.IsControl(rune) && rune.Value is not ('\t' or '\n' or '\r'))
            {
                builder ??= new StringBuilder(message.Length + 16);
                builder.Append(message, copiedUpTo, index - copiedUpTo);

                int byteCount = rune.EncodeToUtf8(utf8);
                for (int i = 0; i < byteCount; i++)
                {
                    byte b = utf8[i];
                    builder.Append('\\')
                           .Append((char)('0' + ((b >> 6) & 7)))
                           .Append((char)('0' + ((b >> 3) & 7)))
                           .Append((char)('0' + (b & 7)));
                }

                copiedUpTo = index + rune.Utf16SequenceLength;
            }
            index += rune.Utf16SequenceLength;
        }

        if (builder is null)
        {
            return message;
        }

        builder.Append(message, copiedUpTo, message.Length - copiedUpTo);
        return builder.ToString();
    }

    private void ParseAuthFail(ReadOnlyPacket packet)
    {
        var reader = packet.GetReader();
        /*
            byte         SSH_MSG_USERAUTH_FAILURE
            name-list    authentications that can continue
            boolean      partial success
        */
        reader.ReadMessageId(MessageId.SSH_MSG_USERAUTH_FAILURE);
        _allowedAuthentications = reader.ReadNameList();
        bool wasPartial = reader.ReadBoolean();

        if (wasPartial)
        {
            _authResult = AuthResult.Partial;
            _logger.PartialSuccessAuth(_currentMethod, _allowedAuthentications);
        }
        else
        {
            bool isAccepted = IsMethodAccepted(_currentMethod) != false;
            _authResult = isAccepted ? AuthResult.Failure : AuthResult.FailureMethodNotAllowed;
            _logger.AuthMethodFailed(_currentMethod, _allowedAuthentications);
        }
    }
}

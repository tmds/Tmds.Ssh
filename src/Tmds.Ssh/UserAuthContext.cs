// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using Microsoft.Extensions.Logging;
using System.Buffers;
using System.Diagnostics;
using System.Text;

namespace Tmds.Ssh;

sealed class UserAuthContext
{
    private readonly SshConnection _connection;
    private readonly SshConnectionInfo _connectionInfo;
    private readonly BannerHandler? _bannerHandler;
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
        BannerHandler? bannerHandler,
        ILogger<SshClient> logger)
    {
        _connection = connection;
        _connectionInfo = connectionInfo;
        _bannerHandler = bannerHandler;
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

                BannerHandler? bannerHandler = _bannerHandler;
                BannerMessageContext bannerMessageContext = default;
                try
                {
                    // Check the limit before parsing or invoking user code. Preserve the existing
                    // counting semantics while ensuring an over-limit packet is not observed.
                    if (_bannerPacketCount++ > Constants.MaxBannerPackets)
                    {
                        ThrowHelper.ThrowBannerTooLong();
                    }

                    if (bannerHandler is not null)
                    {
                        bannerMessageContext = ParseBanner(packet, _connectionInfo);
                    }
                }
                finally
                {
                    packet.Dispose();
                }

                if (bannerHandler is not null)
                {
                    bannerHandler(bannerMessageContext);
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

    // Built from ShouldEscape so the vectorized scan can never drift from the scalar predicate.
    private static readonly SearchValues<char> BannerCharsToEscape = CreateBannerCharsToEscape();

    private static SearchValues<char> CreateBannerCharsToEscape()
    {
        // ShouldEscape only returns true for characters in the C0/DEL/C1 range (<= U+009F),
        // so there is no need to scan the rest of the BMP when building the set.
        Span<char> chars = stackalloc char[0xA0];
        int count = 0;
        for (char c = '\0'; c <= '\u009F'; c++)
        {
            if (ShouldEscape(c))
            {
                chars[count++] = c;
            }
        }

        return SearchValues.Create(chars.Slice(0, count));
    }

    private static bool ShouldEscape(char c)
    {
        // Escape the control characters that can drive terminal escape sequences when the banner
        // is written to a console: the C0 range (U+0000-U+001F), DEL (U+007F) and the C1 range
        // (U+0080-U+009F). Tab, newline and carriage return are preserved.
        if (c is '\t' or '\n' or '\r')
        {
            return false;
        }

        return c <= '\u001F' || (c >= '\u007F' && c <= '\u009F');
    }

    // Escapes like Microsoft.Extensions.Logging.Console ConsoleControlCharacterSanitizer.
    internal static string EscapeControlCharacters(string message)
    {
        ReadOnlySpan<char> remaining = message;
        int firstEscapedCharacterIndex = remaining.IndexOfAny(BannerCharsToEscape);
        if (firstEscapedCharacterIndex < 0)
        {
            return message;
        }

        var escaped = new ValueStringBuilder(stackalloc char[256]);
        escaped.Append(remaining.Slice(0, firstEscapedCharacterIndex));
        remaining = remaining.Slice(firstEscapedCharacterIndex);

        while (true)
        {
            // remaining[0] is always a character that must be escaped.
            AppendEscaped(ref escaped, remaining[0]);
            remaining = remaining.Slice(1);

            int next = remaining.IndexOfAny(BannerCharsToEscape);
            if (next < 0)
            {
                escaped.Append(remaining);
                break;
            }

            escaped.Append(remaining.Slice(0, next));
            remaining = remaining.Slice(next);
        }

        return escaped.ToString();
    }

    private static void AppendEscaped(ref ValueStringBuilder builder, char c)
    {
        Span<char> escaped = builder.AppendSpan(6);
        escaped[0] = '\\';
        escaped[1] = 'u';
        escaped[2] = ToHexChar(c >> 12);
        escaped[3] = ToHexChar(c >> 8);
        escaped[4] = ToHexChar(c >> 4);
        escaped[5] = ToHexChar(c);
    }

    private static char ToHexChar(int nibble)
    {
        nibble &= 0xF;
        return (char)(nibble < 10 ? '0' + nibble : 'A' + nibble - 10);
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

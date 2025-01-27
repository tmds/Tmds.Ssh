// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using Microsoft.Extensions.Logging;
using System.Diagnostics;

namespace Tmds.Ssh;

sealed class UserAuthContext
{
    private readonly SshConnection _connection;
    private readonly ILogger<SshClient> _logger;
    private readonly HashSet<SshKeyData> _publicKeysToSkip = new(); // track keys that were already attempted.
    private HashSet<Name>? _acceptedPublicKeyAlgorithms; // Allowed algorithms by config/server.
    private readonly HashSet<Name> _supportedAcceptedPublicKeyAlgorithms; // Algorithms the library supports.
    private int _bannerPacketCount = 0;
    private Name[]? _allowedAuthentications;
    private AuthResult _authResult;
    private Name _currentMethod;

    public UserAuthContext(SshConnection connection, string userName, IReadOnlyList<Name>? acceptedPublicKeyAlgorithms, IReadOnlyList<Name> supportedPublicKeyAlgorithms, int minimumRSAKeySize, ILogger<SshClient> logger)
    {
        _connection = connection;
        _logger = logger;
        UserName = userName;
        _supportedAcceptedPublicKeyAlgorithms = new HashSet<Name>(supportedPublicKeyAlgorithms);
        MinimumRSAKeySize = minimumRSAKeySize;

        if (acceptedPublicKeyAlgorithms is not null)
        {
            FilterAcceptedPublicKeyAlgorithms(acceptedPublicKeyAlgorithms);
        }
    }

    public string UserName { get; }

    public SequencePool SequencePool => _connection.SequencePool;

    public void FilterAcceptedPublicKeyAlgorithms(IReadOnlyCollection<Name> names)
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

            if (messageId == MessageId.SSH_MSG_USERAUTH_BANNER)
            {
                /* The SSH server may send an SSH_MSG_USERAUTH_BANNER message at any
                   time after this authentication protocol starts and before
                   authentication is successful. */

                // TODO: provide the banner to the user.

                packet.Dispose();

                if (_bannerPacketCount++ > Constants.MaxBannerPackets)
                {
                    ThrowHelper.ThrowBannerTooLong();
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
                ThrowHelper.ThrowProtocolUnexpectedValue();
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
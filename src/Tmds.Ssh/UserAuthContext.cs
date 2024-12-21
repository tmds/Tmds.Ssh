// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using Microsoft.Extensions.Logging;
using System.Diagnostics;

namespace Tmds.Ssh;

sealed class UserAuthContext
{
    private readonly SshConnection _connection;
    private readonly ILogger<SshClient> _logger;
    private readonly HashSet<SshKey> _publicKeysToSkip = new(); // track keys that were already attempted.
    private int _bannerPacketCount = 0;
    private Name[]? _allowedAuthentications;
    private bool _wasPartial;
    private Name _currentMethod;

    public UserAuthContext(SshConnection connection, string userName, List<Name> publicKeyAcceptedAlgorithms, int minimumRSAKeySize, ILogger<SshClient> logger)
    {
        _connection = connection;
        _logger = logger;
        UserName = userName;
        PublicKeyAcceptedAlgorithms = publicKeyAcceptedAlgorithms;
        MinimumRSAKeySize = minimumRSAKeySize;
    }

    public string UserName { get; }

    public SequencePool SequencePool => _connection.SequencePool;

    public List<Name> PublicKeyAcceptedAlgorithms { get; }

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

    private AuthResult GetAuthResult(ReadOnlyPacket packet)
    {
        var reader = packet.GetReader();
        MessageId b = reader.ReadMessageId();
        switch (b)
        {
            case MessageId.SSH_MSG_USERAUTH_SUCCESS:
                return AuthResult.Success;
            case MessageId.SSH_MSG_USERAUTH_FAILURE:
                return _wasPartial ? AuthResult.Partial : AuthResult.Failure;
            default:
                ThrowHelper.ThrowProtocolUnexpectedValue();
                return AuthResult.Failure;
        }
    }

    public bool IsSkipPublicAuthKey(SshKey publicKey)
    {
        if (publicKey is null)
        {
            return false;
        }

        return _publicKeysToSkip.Contains(publicKey);
    }

    public void AddPublicAuthKeyToSkip(SshKey publicKey)
    {
        if (publicKey is null)
        {
            return;
        }
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
        if (!_currentMethod.IsEmpty)
        {
            throw new InvalidOperationException("Already authenticating using an other method.");
        }

        Debug.Assert(IsMethodAccepted(method) != false);

        _currentMethod = method;
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
        _wasPartial = reader.ReadBoolean();

        if (_wasPartial)
        {
            _logger.PartialSuccessAuth(_currentMethod, _allowedAuthentications);
        }
        else
        {
            _logger.AuthMethodFailed(_currentMethod, _allowedAuthentications);
        }
    }
}
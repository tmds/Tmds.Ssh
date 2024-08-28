// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Tmds.Ssh;

sealed class UserAuthContext
{
    private readonly SshConnection _connection;
    private readonly ILogger<SshClient> _logger;
    private int _bannerPacketCount = 0;
    private Name[]? _allowedAuthentications;
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

    public async Task<bool> ReceiveAuthIsSuccesfullAsync(CancellationToken ct)
    {
        using Packet response = await ReceivePacketAsync(ct).ConfigureAwait(false);
        bool isSuccess = IsAuthSuccesfull(response);
        return isSuccess;
    }

    private bool IsAuthSuccesfull(ReadOnlyPacket packet)
    {
        var reader = packet.GetReader();
        MessageId b = reader.ReadMessageId();
        switch (b)
        {
            case MessageId.SSH_MSG_USERAUTH_SUCCESS:
                return true;
            case MessageId.SSH_MSG_USERAUTH_FAILURE:
                return false;
            default:
                ThrowHelper.ThrowProtocolUnexpectedValue();
                return false;
        }
    }

    public bool TryStartAuth(Name method)
    {
        if (!_currentMethod.IsEmpty)
        {
            throw new InvalidOperationException("Already authenticating using an other method.");
        }

        bool shouldStart = !SkipMethod(method);

        if (shouldStart)
        {
            _currentMethod = method;
        }

        return shouldStart;
    }

    public bool SkipMethod(Name method)
    {
        bool isAllowed = _allowedAuthentications == null ? true : Array.IndexOf(_allowedAuthentications, method) >= 0;
        return !isAllowed;
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
        bool partial_success = reader.ReadBoolean();

        _logger.AuthMethodFailed(_currentMethod, _allowedAuthentications);

        if (partial_success)
        {
            throw new NotImplementedException("Partial success auth is not implemented.");
        }
    }
}
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
    private readonly ILogger _logger;
    private int _bannerPacketCount = 0;
    private Name[]? _allowedAuthentications;

    public UserAuthContext(SshConnection connection, string userName, List<Name> publicKeyAcceptedAlgorithms, int minimumRSAKeySize, ILogger logger)
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
        while (true)
        {
            var packet = await _connection.ReceivePacketAsync(ct, maxLength);
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
                return packet;
            }
        }
    }

    public ValueTask SendPacketAsync(Packet packet, CancellationToken ct)
        => _connection.SendPacketAsync(packet, ct);

    public async Task<bool> ReceiveAuthIsSuccesfullAsync(CancellationToken ct)
    {
        using Packet response = await ReceivePacketAsync(ct).ConfigureAwait(false);
        bool isSuccess = IsAuthSuccesfull(response);
        if (isSuccess)
        {
            _logger.AuthenticationSucceeded();
        }
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
                /*
                    byte         SSH_MSG_USERAUTH_FAILURE
                    name-list    authentications that can continue
                    boolean      partial success
                */
                _allowedAuthentications = reader.ReadNameList();
                bool partial_success = reader.ReadBoolean();
                if (partial_success)
                {
                    throw new NotImplementedException("Partial success auth is not implemented.");
                }
                return false;
            default:
                ThrowHelper.ThrowProtocolUnexpectedValue();
                return false;
        }
    }

    public bool IsAuthenticationAllowed(Name name)
    {
        return _allowedAuthentications == null ? true : Array.IndexOf(_allowedAuthentications, name) >= 0;
    }
}
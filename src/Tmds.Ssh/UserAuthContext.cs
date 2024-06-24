// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Tmds.Ssh;

sealed class UserAuthContext
{
    private readonly SshConnection _connection;
    private readonly ILogger _logger;
    private int _bannerPacketCount = 0;

    public UserAuthContext(SshConnection connection, string userName, ILogger logger)
    {
        _connection = connection;
        _logger = logger;
        UserName = userName;
    }

    public string UserName { get; }

    public SequencePool SequencePool => _connection.SequencePool;

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

    private static bool IsAuthSuccesfull(ReadOnlyPacket packet)
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
}
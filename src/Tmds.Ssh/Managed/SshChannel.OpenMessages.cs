// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Buffers;
using System.Diagnostics;
using System.Net;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace Tmds.Ssh.Managed;

sealed partial class SshChannel : ISshChannel
{
    public void TrySendChannelOpenDirectStreamLocalMessage(string socketPath)
        => TrySendPacket(_sequencePool.CreateChannelOpenDirectStreamLocalMessage(LocalChannel, (uint)_receiveWindow, (uint)ReceiveMaxPacket, socketPath));

    public void TrySendChannelOpenSessionMessage()
        => TrySendPacket(_sequencePool.CreateChannelOpenSessionMessage(LocalChannel, (uint)_receiveWindow, (uint)ReceiveMaxPacket));

    public void TrySendExecCommandMessage(string command)
        => TrySendPacket(_sequencePool.CreateExecCommandMessage(RemoteChannel, command));

    public void TrySendExecSubsystemMessage(string subsystem)
        => TrySendPacket(_sequencePool.CreateExecSubsystemMessage(RemoteChannel, subsystem));

    public void TrySendChannelOpenDirectTcpIpMessage(string host, uint port, IPAddress originatorIP, uint originatorPort)
        => TrySendPacket(_sequencePool.CreateChannelOpenDirectTcpIpMessage(LocalChannel, (uint)_receiveWindow, (uint)ReceiveMaxPacket, host, port, originatorIP, originatorPort));

    private void TrySendChannelWindowAdjustMessage(uint bytesToAdd)
        => TrySendPacket(_sequencePool.CreateChannelWindowAdjustMessage(RemoteChannel, bytesToAdd));

    public async ValueTask ReceiveChannelOpenConfirmationAsync(CancellationToken ct)
    {
        using var packet = await ReceivePacketAsync(ct).ConfigureAwait(false);

        switch (packet.MessageId)
        {
            case MessageId.SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
                return;
            case MessageId.SSH_MSG_CHANNEL_OPEN_FAILURE:
                (ChannelOpenFailureReason reason, string description) = ParseChannelOpenFailure(packet);
                string message = $"Failed to open channel - {reason}{(description.Length > 0 ? $" - {description}" : "")}.";
                throw new SshChannelException(message);
            default:
                ThrowHelper.ThrowProtocolUnexpectedMessageId(packet.MessageId!.Value);
                break;
        }

        static (ChannelOpenFailureReason reason, string description) ParseChannelOpenFailure(ReadOnlyPacket packet)
        {
            /*
                byte      SSH_MSG_CHANNEL_OPEN_FAILURE
                uint32    recipient channel
                uint32    reason code
                string    description in ISO-10646 UTF-8 encoding [RFC3629]
                string    language tag [RFC3066]
             */
            var reader = packet.GetReader();
            reader.ReadMessageId(MessageId.SSH_MSG_CHANNEL_OPEN_FAILURE);
            reader.SkipUInt32();
            ChannelOpenFailureReason reason = (ChannelOpenFailureReason)reader.ReadUInt32();
            string description = reader.ReadUtf8String();
            reader.SkipString();
            reader.ReadEnd();

            return (reason, description);
        }
    }

    public async ValueTask ReceiveChannelRequestSuccessAsync(string failureMessage, CancellationToken ct)
    {
        using var packet = await ReceivePacketAsync(ct).ConfigureAwait(false);

        ParseChannelOpenConfirmation(packet, failureMessage);

        static void ParseChannelOpenConfirmation(ReadOnlyPacket packet, string failureMessage)
        {
            var reader = packet.GetReader();
            var msgId = reader.ReadMessageId();
            switch (msgId)
            {
                case MessageId.SSH_MSG_CHANNEL_SUCCESS:
                    break;
                case MessageId.SSH_MSG_CHANNEL_FAILURE:
                    throw new SshChannelException(failureMessage);
                default:
                    ThrowHelper.ThrowProtocolUnexpectedMessageId(msgId);
                    break;
            }
        }
    }
}

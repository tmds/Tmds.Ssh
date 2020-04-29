// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using System;
namespace Tmds.Ssh
{
    static class ChannelContextReceiveMessageExtensions
    {
        public static async ValueTask ReceiveChannelOpenConfirmationAsync(this ChannelContext context, CancellationToken ct)
        {
            using var packet = await context.ReceivePacketAsync(ct).ConfigureAwait(false);

            switch (packet.MessageId)
            {
                case MessageId.SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
                    return;
                case MessageId.SSH_MSG_CHANNEL_OPEN_FAILURE:
                    (ChannelOpenFailureReason reason, string description) = ParseChannelOpenFailure(packet);
                    throw new ChannelOpenFailureException(reason, description);
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

        public static async ValueTask ReceiveChannelRequestSuccessAsync(this ChannelContext context, string failureMessage, CancellationToken ct)
        {
            using var packet = await context.ReceivePacketAsync(ct).ConfigureAwait(false);

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
                        throw new ChannelRequestFailed(failureMessage);
                    default:
                        ThrowHelper.ThrowProtocolUnexpectedMessageId(msgId);
                        break;
                }
            }
        }
    }
}
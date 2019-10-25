// This file is part of Tmds.Ssh which is released under LGPL-3.0.
// See file LICENSE for full license details.

using System;
using System.Net;
using System.Threading.Tasks;

namespace Tmds.Ssh
{
    static class ChannelContextExtensions
    {
        public static ValueTask SendChannelFailureMessageAsync(this ChannelContext context)
        {
            return context.SendPacketAsync(CreateChannelFailureMessage(context));

            static Packet CreateChannelFailureMessage(ChannelContext context)
            {
                /*
                    byte      SSH_MSG_CHANNEL_FAILURE
                    uint32    recipient channel
                */
                using var packet = context.RentPacket();
                var writer = packet.GetWriter();
                writer.WriteMessageId(MessageId.SSH_MSG_CHANNEL_FAILURE);
                writer.WriteUInt32(context.RemoteChannel);
                return packet.Move();
            }
        }

        public static async ValueTask ReceiveChannelOpenConfirmationAsync(this ChannelContext context)
        {
            using var packet = await context.ReceivePacketAsync();

            ParseChannelOpenConfirmation(packet);

            static void ParseChannelOpenConfirmation(Packet packet)
            {
                var reader = packet.GetReader();
                reader.ReadMessageId(MessageId.SSH_MSG_CHANNEL_OPEN_CONFIRMATION); // TODO SSH_MSG_CHANNEL_OPEN_FAILURE
            }
        }

        public static ValueTask SendChannelDataAsync(this ChannelContext context, ReadOnlyMemory<byte> memory)
        {
            // TODO: RemoteWindowSize, RemoteMaxPacketSize
            return context.SendPacketAsync(CreateChannelDataMessage(context, memory));

            static Packet CreateChannelDataMessage(ChannelContext context, ReadOnlyMemory<byte> memory)
            {
                /*
                    byte      SSH_MSG_CHANNEL_DATA
                    uint32    recipient channel
                    string    data
                 */

                using var packet = context.RentPacket();
                var writer = packet.GetWriter();
                writer.WriteMessageId(MessageId.SSH_MSG_CHANNEL_DATA);
                writer.WriteUInt32(context.RemoteChannel);
                writer.WriteString(memory.Span);
                return packet.Move();
            }
        }
    }
}
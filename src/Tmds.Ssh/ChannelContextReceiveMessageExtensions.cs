// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Threading;
using System.Threading.Tasks;

namespace Tmds.Ssh
{
    static class ChannelContextReceiveMessageExtensions
    {
        public static async ValueTask ReceiveChannelOpenConfirmationAsync(this ChannelContext context)
        {
            using var packet = await context.ReceivePacketAsync();

            ParseChannelOpenConfirmation(packet);

            static void ParseChannelOpenConfirmation(ReadOnlyPacket packet)
            {
                var reader = packet.GetReader();
                reader.ReadMessageId(MessageId.SSH_MSG_CHANNEL_OPEN_CONFIRMATION); // TODO SSH_MSG_CHANNEL_OPEN_FAILURE
            }
        }

        public static async ValueTask ReceiveChannelRequestSuccessAsync(this ChannelContext context)
        {
            using var packet = await context.ReceivePacketAsync();

            ParseChannelOpenConfirmation(packet);

            static void ParseChannelOpenConfirmation(ReadOnlyPacket packet)
            {
                var reader = packet.GetReader();
                reader.ReadMessageId(MessageId.SSH_MSG_CHANNEL_SUCCESS); // TODO SSH_MSG_CHANNEL_FAILURE
            }
        }
    }
}
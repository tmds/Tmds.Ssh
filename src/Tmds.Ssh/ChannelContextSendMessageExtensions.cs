// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Net;
using System.Threading.Tasks;

namespace Tmds.Ssh
{
    static class ChannelContextSendMessageExtensions
    {
        public static ValueTask SendChannelFailureMessageAsync(this ChannelContext context)
        {
            return context.SendPacketAsync(CreatePacket(context));

            static Packet CreatePacket(ChannelContext context)
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

        public static ValueTask SendChannelDataMessageAsync(this ChannelContext context,  ReadOnlyMemory<byte> memory)
        {
            return context.SendPacketAsync(CreatePacket(context, memory));

            static Packet CreatePacket(ChannelContext context, ReadOnlyMemory<byte> memory)
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

        public static ValueTask SendChannelOpenDirectStreamLocalMessageAsync(this ChannelContext context, string socketPath)
        {
            return context.SendPacketAsync(CreatePacket(context, socketPath));

            static Packet CreatePacket(ChannelContext context, string socketPath)
            {
                /*
                    byte		SSH_MSG_CHANNEL_OPEN
                    string		"direct-streamlocal@openssh.com"
                    uint32		sender channel
                    uint32		initial window size
                    uint32		maximum packet size
                    string		socket path
                    string		reserved
                    uint32		reserved
                 */

                using var packet = context.RentPacket();
                var writer = packet.GetWriter();
                writer.WriteMessageId(MessageId.SSH_MSG_CHANNEL_OPEN);
                writer.WriteString("direct-streamlocal@openssh.com");
                writer.WriteUInt32(context.LocalChannel);
                writer.WriteUInt32(context.LocalWindowSize);
                writer.WriteUInt32(context.LocalMaxPacketSize);
                writer.WriteString(socketPath);
                writer.WriteString("");
                writer.WriteUInt32(0);
                return packet.Move();
            }
        }

        public static ValueTask SendChannelOpenDirectTcpIpMessageAsync(this ChannelContext context, string host, uint port, IPAddress originatorIP, uint originatorPort)
        {
            return context.SendPacketAsync(CreatePacket(context, host, port, originatorIP, originatorPort));

            static Packet CreatePacket(ChannelContext context, string host, uint port, IPAddress originatorIP, uint originatorPort)
            {
                /*
                    byte      SSH_MSG_CHANNEL_OPEN
                    string    "direct-tcpip"
                    uint32    sender channel
                    uint32    initial window size
                    uint32    maximum packet size
                    string    host to connect
                    uint32    port to connect
                    string    originator IP address
                    uint32    originator port
                 */

                using var packet = context.RentPacket();
                var writer = packet.GetWriter();
                writer.WriteMessageId(MessageId.SSH_MSG_CHANNEL_OPEN);
                writer.WriteString("direct-tcpip");
                writer.WriteUInt32(context.LocalChannel);
                writer.WriteUInt32(context.LocalWindowSize);
                writer.WriteUInt32(context.LocalMaxPacketSize);
                writer.WriteString(host);
                writer.WriteUInt32(port);
                writer.WriteString(originatorIP.ToString());
                writer.WriteUInt32(originatorPort);
                return packet.Move();
            }
        }

        public static ValueTask SendChannelWindowAdjustMessageAsync(this ChannelContext context, uint bytesToAdd)
        {
            return context.SendPacketAsync(CreatePacket(context, bytesToAdd));

            static Packet CreatePacket(ChannelContext context, uint bytesToAdd)
            {
                /*
                    byte      SSH_MSG_CHANNEL_WINDOW_ADJUST
                    uint32    recipient channel
                    uint32    bytes to add
                */
                using var packet = context.RentPacket();
                var writer = packet.GetWriter();
                writer.WriteMessageId(MessageId.SSH_MSG_CHANNEL_WINDOW_ADJUST);
                writer.WriteUInt32(context.RemoteChannel);
                writer.WriteUInt32(bytesToAdd);
                return packet.Move();
            }
        }
    }
}
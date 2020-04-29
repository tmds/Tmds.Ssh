// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace Tmds.Ssh
{
    static class ChannelContextSendMessageExtensions
    {
        public static ValueTask SendChannelFailureMessageAsync(this ChannelContext context, CancellationToken ct)
        {
            return context.SendPacketAsync(CreatePacket(context), ct);

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

        public static ValueTask SendChannelDataMessageAsync(this ChannelContext context, ReadOnlyMemory<byte> memory, CancellationToken ct)
        {
            return context.SendPacketAsync(CreatePacket(context, memory), ct);

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

        public static ValueTask SendChannelOpenDirectStreamLocalMessageAsync(this ChannelContext context, string socketPath, CancellationToken ct)
        {
            return context.SendPacketAsync(CreatePacket(context, socketPath), ct);

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

        public static ValueTask SendChannelOpenSessionMessageAsync(this ChannelContext context, CancellationToken ct)
        {
            return context.SendPacketAsync(CreatePacket(context), ct);

            static Packet CreatePacket(ChannelContext context)
            {
                /*
                    byte      SSH_MSG_CHANNEL_OPEN
                    string    "session"
                    uint32    sender channel
                    uint32    initial window size
                    uint32    maximum packet size
                 */

                using var packet = context.RentPacket();
                var writer = packet.GetWriter();
                writer.WriteMessageId(MessageId.SSH_MSG_CHANNEL_OPEN);
                writer.WriteString("session");
                writer.WriteUInt32(context.LocalChannel);
                writer.WriteUInt32(context.LocalWindowSize);
                writer.WriteUInt32(context.LocalMaxPacketSize);
                return packet.Move();
            }
        }

        public static ValueTask SendExecCommandMessageAsync(this ChannelContext context, string command, CancellationToken ct)
        {
            return context.SendPacketAsync(CreatePacket(context, command), ct);

            static Packet CreatePacket(ChannelContext context, string command)
            {
                /*
                    byte      SSH_MSG_CHANNEL_REQUEST
                    uint32    recipient channel
                    string    "exec"
                    boolean   want reply
                    string    command
                 */

                using var packet = context.RentPacket();
                var writer = packet.GetWriter();
                writer.WriteMessageId(MessageId.SSH_MSG_CHANNEL_REQUEST);
                writer.WriteUInt32(context.RemoteChannel);
                writer.WriteString("exec");
                writer.WriteBoolean(true);
                writer.WriteString(command);
                return packet.Move();
            }
        }

        public static ValueTask SendChannelOpenDirectTcpIpMessageAsync(this ChannelContext context, string host, uint port, IPAddress originatorIP, uint originatorPort, CancellationToken ct)
        {
            return context.SendPacketAsync(CreatePacket(context, host, port, originatorIP, originatorPort), ct);

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

        public static ValueTask SendChannelWindowAdjustMessageAsync(this ChannelContext context, uint bytesToAdd, CancellationToken ct)
        {
            return context.SendPacketAsync(CreatePacket(context, bytesToAdd), ct);

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

        public static ValueTask SendChannelSubsystemMessageAsync(this ChannelContext context, string subsystem, CancellationToken ct)
        {
            return context.SendPacketAsync(CreatePacket(context, subsystem), ct);

            static Packet CreatePacket(ChannelContext context, string subsystem)
            {
                /*
                    byte      SSH_MSG_CHANNEL_REQUEST
                    uint32    recipient channel
                    string    "subsystem"
                    boolean   want reply
                    string    "name"
                 */

                using var packet = context.RentPacket();
                var writer = packet.GetWriter();
                writer.WriteMessageId(MessageId.SSH_MSG_CHANNEL_REQUEST);
                writer.WriteUInt32(context.RemoteChannel);
                writer.WriteString("subsystem");
                writer.WriteBoolean(true);
                writer.WriteString(subsystem);
                return packet.Move();
            }
        }

        public static ValueTask SftpInitMessageAsync(this ChannelContext context, uint version, CancellationToken ct)
        {
            return context.SendPacketAsync(CreatePacket(context, version), ct); // TODO later build sftp over SendChannelDataMessageAsync()

            static Packet CreatePacket(ChannelContext context, uint version)
            {
                /*
                    byte        SSH_MSG_CHANNEL_DATA
                    uint32      recipient channel
                    uint32      length
                    byte        SSH_FXP_INIT
                    uint32      version
                */
                using var packet = context.RentPacket();
                var writer = packet.GetWriter();
                writer.WriteMessageId(MessageId.SSH_MSG_CHANNEL_DATA);
                writer.WriteUInt32(context.RemoteChannel);
                writer.WriteUInt32(9); // length
                writer.WriteUInt32(5); // length
                writer.WriteByte((byte)SftpPacketType.SSH_FXP_INIT);
                writer.WriteUInt32(version); // version
                return packet.Move();
            }
        }
    }
}
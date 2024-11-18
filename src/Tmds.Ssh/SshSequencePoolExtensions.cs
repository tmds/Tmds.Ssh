// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Net;

namespace Tmds.Ssh;

static class SshSequencePoolExtensions
{
    public static Packet RentPacket(this SequencePool sequencePool)
    {
        Sequence sequence = sequencePool.RentSequence();
        return new Packet(sequence);
    }

    public static Packet CreateRequestFailureMessage(this SequencePool sequencePool)
    {
        var packet = sequencePool.RentPacket();
        var writer = packet.GetWriter();
        writer.WriteMessageId(MessageId.SSH_MSG_REQUEST_FAILURE);
        return packet;
    }

    public static Packet CreateChannelCloseMessage(this SequencePool sequencePool, uint remoteChannel)
    {
        /*
            byte      SSH_MSG_CHANNEL_CLOSE
            uint32    recipient channel
        */
        using var packet = sequencePool.RentPacket();
        var writer = packet.GetWriter();
        writer.WriteMessageId(MessageId.SSH_MSG_CHANNEL_CLOSE);
        writer.WriteUInt32(remoteChannel);
        return packet.Move();
    }

    public static Packet CreateChannelFailureMessage(this SequencePool sequencePool, uint remoteChannel)
    {
        /*
            byte      SSH_MSG_CHANNEL_FAILURE
            uint32    recipient channel
        */
        using var packet = sequencePool.RentPacket();
        var writer = packet.GetWriter();
        writer.WriteMessageId(MessageId.SSH_MSG_CHANNEL_FAILURE);
        writer.WriteUInt32(remoteChannel);
        return packet.Move();
    }

    public static Packet CreateChannelDataMessage(this SequencePool sequencePool, uint remoteChannel, ReadOnlyMemory<byte> memory)
    {
        /*
            byte      SSH_MSG_CHANNEL_DATA
            uint32    recipient channel
            string    data
        */

        using var packet = sequencePool.RentPacket();
        var writer = packet.GetWriter();
        writer.WriteMessageId(MessageId.SSH_MSG_CHANNEL_DATA);
        writer.WriteUInt32(remoteChannel);
        writer.WriteString(memory.Span);
        return packet.Move();
    }

    public static Packet CreateChannelOpenDirectStreamLocalMessage(this SequencePool sequencePool, uint localChannel, uint localWindowSize, uint maxPacketSize, string socketPath)
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
        using var packet = sequencePool.RentPacket();
        var writer = packet.GetWriter();
        writer.WriteMessageId(MessageId.SSH_MSG_CHANNEL_OPEN);
        writer.WriteString("direct-streamlocal@openssh.com");
        writer.WriteUInt32(localChannel);
        writer.WriteUInt32(localWindowSize);
        writer.WriteUInt32(maxPacketSize);
        writer.WriteString(socketPath);
        writer.WriteString("");
        writer.WriteUInt32(0);
        return packet.Move();
    }

    public static Packet CreateChannelOpenSessionMessage(this SequencePool sequencePool, uint localChannel, uint localWindowSize, uint maxPacketSize)
    {
        /*
            byte      SSH_MSG_CHANNEL_OPEN
            string    "session"
            uint32    sender channel
            uint32    initial window size
            uint32    maximum packet size
            */

        using var packet = sequencePool.RentPacket();
        var writer = packet.GetWriter();
        writer.WriteMessageId(MessageId.SSH_MSG_CHANNEL_OPEN);
        writer.WriteString("session");
        writer.WriteUInt32(localChannel);
        writer.WriteUInt32(localWindowSize);
        writer.WriteUInt32(maxPacketSize);
        return packet.Move();
    }

    public static Packet CreateExecCommandMessage(this SequencePool sequencePool, uint remoteChannel, string command)
    {
        /*
            byte      SSH_MSG_CHANNEL_REQUEST
            uint32    recipient channel
            string    "exec"
            boolean   want reply
            string    command
            */

        using var packet = sequencePool.RentPacket();
        var writer = packet.GetWriter();
        writer.WriteMessageId(MessageId.SSH_MSG_CHANNEL_REQUEST);
        writer.WriteUInt32(remoteChannel);
        writer.WriteString("exec");
        writer.WriteBoolean(true);
        writer.WriteString(command);
        return packet.Move();
    }

    public static Packet CreateExecSubsystemMessage(this SequencePool sequencePool, uint remoteChannel, string subsystem)
    {
        /*
            byte      SSH_MSG_CHANNEL_REQUEST
            uint32    recipient channel
            string    "subsystem"
            boolean   want reply
            string    subsystem name
            */

        using var packet = sequencePool.RentPacket();
        var writer = packet.GetWriter();
        writer.WriteMessageId(MessageId.SSH_MSG_CHANNEL_REQUEST);
        writer.WriteUInt32(remoteChannel);
        writer.WriteString("subsystem");
        writer.WriteBoolean(true);
        writer.WriteString(subsystem);
        return packet.Move();
    }

    public static Packet CreateSetEnvMessage(this SequencePool sequencePool, uint remoteChannel, string variableName, string variableValue)
    {
        /*
            byte      SSH_MSG_CHANNEL_REQUEST
            uint32    recipient channel
            string    "env"
            boolean   want reply
            string    variable name
            string    variable value
            */

        using var packet = sequencePool.RentPacket();
        var writer = packet.GetWriter();
        writer.WriteMessageId(MessageId.SSH_MSG_CHANNEL_REQUEST);
        writer.WriteUInt32(remoteChannel);
        writer.WriteString("env");
        writer.WriteBoolean(false);
        writer.WriteString(variableName);
        writer.WriteString(variableValue);
        return packet.Move();
    }

    public static Packet CreateChannelOpenDirectTcpIpMessage(this SequencePool sequencePool, uint localChannel, uint localWindowSize, uint maxPacketSize, string host, uint port, IPAddress originatorIP, uint originatorPort)
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

        using var packet = sequencePool.RentPacket();
        var writer = packet.GetWriter();
        writer.WriteMessageId(MessageId.SSH_MSG_CHANNEL_OPEN);
        writer.WriteString("direct-tcpip");
        writer.WriteUInt32(localChannel);
        writer.WriteUInt32(localWindowSize);
        writer.WriteUInt32(maxPacketSize);
        writer.WriteString(host);
        writer.WriteUInt32(port);
        writer.WriteString(originatorIP.ToString());
        writer.WriteUInt32(originatorPort);
        return packet.Move();
    }

    public static Packet CreateChannelWindowAdjustMessage(this SequencePool sequencePool, uint remoteChannel, uint bytesToAdd)
    {
        /*
            byte      SSH_MSG_CHANNEL_WINDOW_ADJUST
            uint32    recipient channel
            uint32    bytes to add
        */
        using var packet = sequencePool.RentPacket();
        var writer = packet.GetWriter();
        writer.WriteMessageId(MessageId.SSH_MSG_CHANNEL_WINDOW_ADJUST);
        writer.WriteUInt32(remoteChannel);
        writer.WriteUInt32(bytesToAdd);
        return packet.Move();
    }

    public static Packet CreateKeepAliveMessage(this SequencePool sequencePool)
    {
        using var packet = sequencePool.RentPacket();
        var writer = packet.GetWriter();
        writer.WriteMessageId(MessageId.SSH_MSG_GLOBAL_REQUEST);
        // The request name can be any unknown name (to trigger an SSH_MSG_REQUEST_FAILURE response).
        // We use the same name as the OpenSSH client.
        writer.WriteString("keepalive@openssh.com");
        writer.WriteBoolean(true); // want reply
        return packet.Move();
    }
}

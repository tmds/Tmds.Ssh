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

    public static Packet CreateChannelOpenFailureMessage(this SequencePool sequencePool, uint remoteChannel)
    {
        const uint SSH_OPEN_ADMINISTRATIVELY_PROHIBITED = 1;
        /*
            byte      SSH_MSG_CHANNEL_OPEN_FAILURE
            uint32    recipient channel
            uint32    reason code
            string    description in ISO-10646 UTF-8 encoding [RFC3629]
            string    language tag [RFC3066]
        */
        var packet = sequencePool.RentPacket();
        var writer = packet.GetWriter();
        writer.WriteMessageId(MessageId.SSH_MSG_CHANNEL_OPEN_FAILURE);
        writer.WriteUInt32(remoteChannel);
        writer.WriteUInt32(SSH_OPEN_ADMINISTRATIVELY_PROHIBITED);
        writer.WriteString("open failed");
        writer.WriteString("");
        return packet;
    }

    public static Packet CreateChannelOpenConfirmationMessage(this SequencePool sequencePool, uint remoteChannel, uint localChannel, uint localWindowSize, uint maxPacketSize)
    {
        /*
            byte      SSH_MSG_CHANNEL_OPEN_CONFIRMATION
            uint32    recipient channel
            uint32    sender channel
            uint32    initial window size
            uint32    maximum packet size
            ....      channel type specific data follows
        */
        var packet = sequencePool.RentPacket();
        var writer = packet.GetWriter();
        writer.WriteMessageId(MessageId.SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
        writer.WriteUInt32(remoteChannel);
        writer.WriteUInt32(localChannel);
        writer.WriteUInt32(localWindowSize);
        writer.WriteUInt32(maxPacketSize);
        return packet;
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

    public static Packet CreateChannelEofMessage(this SequencePool sequencePool, uint remoteChannel)
    {
        /*
            byte      SSH_MSG_CHANNEL_EOF
            uint32    recipient channel
        */
        using var packet = sequencePool.RentPacket();
        var writer = packet.GetWriter();
        writer.WriteMessageId(MessageId.SSH_MSG_CHANNEL_EOF);
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

    public static Packet CreateCancelTcpIpForwardMessage(this SequencePool sequencePool, string address, ushort port)
    {
        /*
            byte      SSH_MSG_GLOBAL_REQUEST
            string    "cancel-tcpip-forward"
            boolean   want reply
            string    address_to_bind (e.g., "127.0.0.1")
            uint32    port number to bind
        */
        using var packet = sequencePool.RentPacket();
        var writer = packet.GetWriter();
        writer.WriteMessageId(MessageId.SSH_MSG_GLOBAL_REQUEST);
        writer.WriteString("cancel-tcpip-forward");
        writer.WriteBoolean(false); // want reply
        writer.WriteString(address);
        writer.WriteUInt32(port);
        return packet.Move();
    }

    public static Packet CreateCancelLocalStreamForwardMessage(this SequencePool sequencePool, string path)
    {
        /*
            byte            SSH2_MSG_GLOBAL_REQUEST
            string          "cancel-streamlocal-forward@openssh.com"
            boolean         FALSE
            string          socket path
        */
        using var packet = sequencePool.RentPacket();
        var writer = packet.GetWriter();
        writer.WriteMessageId(MessageId.SSH_MSG_GLOBAL_REQUEST);
        writer.WriteString("cancel-streamlocal-forward@openssh.com");
        writer.WriteBoolean(false); // want reply
        writer.WriteString(path);
        return packet.Move();
    }

    public static Packet CreateTcpIpForwardMessage(this SequencePool sequencePool, string address, ushort port)
    {
        /*
            byte      SSH_MSG_GLOBAL_REQUEST
            string    "tcpip-forward"
            boolean   want reply
            string    address to bind (e.g., "0.0.0.0")
            uint32    port number to bind
        */
        using var packet = sequencePool.RentPacket();
        var writer = packet.GetWriter();
        writer.WriteMessageId(MessageId.SSH_MSG_GLOBAL_REQUEST);
        writer.WriteString("tcpip-forward");
        writer.WriteBoolean(true); // want reply
        writer.WriteString(address);
        writer.WriteUInt32(port);
        return packet.Move();
    }

    public static Packet CreateStreamLocalForwardMessage(this SequencePool sequencePool, string path)
    {
        /*
            byte            SSH2_MSG_GLOBAL_REQUEST
            string          "streamlocal-forward@openssh.com"
            boolean         TRUE
            string          socket path
        */
        using var packet = sequencePool.RentPacket();
        var writer = packet.GetWriter();
        writer.WriteMessageId(MessageId.SSH_MSG_GLOBAL_REQUEST);
        writer.WriteString("streamlocal-forward@openssh.com");
        writer.WriteBoolean(true); // want reply
        writer.WriteString(path);
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

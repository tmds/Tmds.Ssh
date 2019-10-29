// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.IO;
using System.Net;
using System.Threading.Tasks;

namespace Tmds.Ssh
{
    public static partial class TcpForwardSshClientExtensions
    {
        public static Task<Stream> CreateTcpConnectionAsStreamAsync(this SshClient client, string host, int port)
            => CreateTcpConnectionAsStreamAsync(client, host, port, IPAddress.Any, 0);

        public static async Task<Stream> CreateTcpConnectionAsStreamAsync(this SshClient client, string host, int port, IPAddress originatorIP, int originatorPort)
        {
            ChannelContext context = client.CreateChannel();
            ChannelDataStream? stream = null;
            try
            {
                await context.SendChannelOpenMessageAsync(host, (uint)port, originatorIP, (uint)originatorPort);
                await context.ReceiveChannelOpenConfirmationAsync();
                stream = new ChannelDataStream(context);;
                return stream;
            }
            catch
            {
                if (stream != null)
                {
                    await stream.DisposeAsync();
                }
                else
                {
                    await context.DisposeAsync();
                }
                throw;
            }
        }

        private static ValueTask SendChannelOpenMessageAsync(this ChannelContext context, string host, uint port, IPAddress originatorIP, uint originatorPort)
        {
            return context.SendPacketAsync(CreateChannelOpenMessage(context, host, port, originatorIP, originatorPort));

            static Packet CreateChannelOpenMessage(ChannelContext context, string host, uint port, IPAddress originatorIP, uint originatorPort)
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
    }
}

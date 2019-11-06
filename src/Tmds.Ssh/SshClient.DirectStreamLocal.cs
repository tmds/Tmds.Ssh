// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Tmds.Ssh
{
    public partial class SshClient
    {
        // MAYDO: maybe add arg to control window size?
        public async Task<Stream> CreateUnixConnectionAsStreamAsync(string socketPath, CancellationToken cancellationToken = default)
        {
            ChannelContext context = CreateChannel();

            using var abortOnCancel = cancellationToken.Register(ctx => ((ChannelContext)ctx!).Abort(), context);

            ChannelDataStream? stream = null;
            try
            {
                await SendChannelOpenMessageAsync(context, socketPath);
                await context.ReceiveChannelOpenConfirmationAsync();
                stream = new ChannelDataStream(context);
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

        private static ValueTask SendChannelOpenMessageAsync(ChannelContext context, string socketPath)
        {
            return context.SendPacketAsync(CreateChannelOpenMessage(context, socketPath));

            static Packet CreateChannelOpenMessage(ChannelContext context, string socketPath)
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
    }
}

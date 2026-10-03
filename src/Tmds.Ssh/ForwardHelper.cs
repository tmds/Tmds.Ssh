// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Net.Sockets;

namespace Tmds.Ssh;

static class ForwardHelper
{
    internal static async Task ForwardStreamsAsync(Stream sourceStream, Stream targetStream)
    {
        Task first, second;
        try
        {
            Task copy1 = CopyTillEofAsync(sourceStream, targetStream);
            Task copy2 = CopyTillEofAsync(targetStream, sourceStream);

            first = await Task.WhenAny(copy1, copy2).ConfigureAwait(false);
            second = first == copy1 ? copy2 : copy1;
        }
        finally
        {
            // When the copy stops in one direction, stop it in the other direction too.
            sourceStream.Dispose();
            targetStream.Dispose();
        }
        // The dispose will cause the second copy to stop.
        await second.ConfigureAwait(ConfigureAwaitOptions.SuppressThrowing);

        await first.ConfigureAwait(false); // Throws if faulted.
    }

    private static async Task CopyTillEofAsync(Stream from, Stream to)
    {
        int bufferSize;
        if (to is SshDataStream toDataStream)
        {
            bufferSize = toDataStream.WriteMaxPacketDataLength;
        }
        else
        {
            bufferSize = ((SshDataStream)from).ReadMaxPacketDataLength;
        }
        await from.CopyToAsync(to, bufferSize).ConfigureAwait(false);
        if (to is NetworkStream ns)
        {
            ns.Socket.Shutdown(SocketShutdown.Send);
        }
        else if (to is SshDataStream ds)
        {
            ds.WriteEof();
        }
    }
}

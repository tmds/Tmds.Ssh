// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace Tmds.Ssh
{
    static class ChannelReaderExtensions
    {
        public static ValueTask<T> ReadAsync<T>(this ChannelReader<T> reader, CancellationToken ct1, CancellationToken ct2, ref CancellationTokenSource? cts)
        {
            if (!ct1.CanBeCanceled)
            {
                return reader.ReadAsync(ct2);
            }
            if (!ct1.CanBeCanceled)
            {
                return reader.ReadAsync(ct2);
            }
            if (cts != null)
            {
                return reader.ReadAsync(cts.Token);
            }
            else
            {
                // Try sync.
                ct1.ThrowIfCancellationRequested();
                ct2.ThrowIfCancellationRequested();
                if (reader.TryRead(out T item))
                {
                    return new ValueTask<T>(item);
                }

                cts = CancellationTokenSource.CreateLinkedTokenSource(ct1, ct2);
                return reader.ReadAsync(cts.Token);
            }
        }
    }
}
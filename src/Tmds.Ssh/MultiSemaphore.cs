// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Threading;
using System.Threading.Tasks;

namespace Tmds.Ssh
{
    sealed class MultiSemaphore : IDisposable
    {
        private readonly SemaphoreSlim _semaphore = new SemaphoreSlim(0);
        private int _available;
        private int _waiters;

        public int Available => Volatile.Read(ref _available);

        private bool TryAquire(int aquireCount, bool exactCount, out int aquired)
        {
            while (true)
            {
                int available = Volatile.Read(ref _available);
                int tryAquire = exactCount ? aquireCount : Math.Max(Math.Min(available, aquireCount), 1);
                if (available >= tryAquire)
                {
                    if (Interlocked.CompareExchange(ref _available, available - tryAquire, available) == available)
                    {
                        aquired = tryAquire;
                        return true;
                    }
                    else
                    {
                        continue;
                    }
                }
                aquired = 0;
                return false;
            }
        }

        public async ValueTask<int> AquireAsync(int aquireCount, bool exactCount, CancellationToken ct1, CancellationToken ct2 = default)
        {
            do
            {
                if (TryAquire(aquireCount, exactCount, out int aquired))
                {
                    return aquired;
                }

                // Synchronize with Release by first incrementing waiters
                // and then checking again before waiting.
                Interlocked.Increment(ref _waiters);
                if (TryAquire(aquireCount, exactCount, out aquired))
                {
                    return aquired;
                }
                else
                {
                    if (ct1.CanBeCanceled && ct2.CanBeCanceled)
                    {
                        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct1, ct2);
                        await _semaphore.WaitAsync(cts.Token).ConfigureAwait(false);
                    }
                    else if (!ct2.CanBeCanceled)
                    {
                        await _semaphore.WaitAsync(ct1).ConfigureAwait(false);
                    }
                }
            } while (true);
        }

        public void Release(int releaseCount)
        {
            Interlocked.Add(ref _available, releaseCount);

            int waiters = Interlocked.Exchange(ref _waiters, 0);
            if (waiters > 0)
            {
                _semaphore.Release(waiters);
            }
        }

        public void Dispose()
        {
            _semaphore.Dispose();
        }
    }
}
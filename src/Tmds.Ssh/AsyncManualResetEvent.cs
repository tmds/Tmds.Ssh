// This file is part of Tmds.Ssh which is released under LGPL-3.0.
// See file LICENSE for full license details.

using System;
using System.Threading;
using System.Threading.Tasks;

namespace Tmds.Ssh
{
    sealed class AsyncManualResetEvent : IDisposable
    {
        private readonly SemaphoreSlim _semaphore = new SemaphoreSlim(0);
        private int _waiters;
        private const int SET = -1;

        public async ValueTask WaitAsync(CancellationToken ct)
        {
            do
            {
                int waiters = Volatile.Read(ref _waiters);
                if (waiters == SET)
                {
                    return;
                }

                if (Interlocked.CompareExchange(ref _waiters, waiters + 1, waiters) == waiters)
                {
                    await _semaphore.WaitAsync(ct);
                }
            } while (true);
        }

        public void Set()
        {
            int waiters = Interlocked.Exchange(ref _waiters, SET);
            if (waiters > 0)
            {
                _semaphore.Release(waiters);
            }
        }

        public void Reset()
        {
            Interlocked.CompareExchange(ref _waiters, 0, SET);
        }

        public void Dispose()
        {
            _semaphore.Dispose();
        }
    }
}
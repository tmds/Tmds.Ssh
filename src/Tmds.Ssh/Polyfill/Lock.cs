// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

#if !NET9_0_OR_GREATER

namespace Tmds.Ssh;

// Polyfill for System.Threading.Lock for use with the `lock` keyword.
sealed class Lock
{
    public bool IsHeldByCurrentThread => Monitor.IsEntered(this);
}

#endif

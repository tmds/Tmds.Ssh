// This file is part of Tmds.Ssh which is released under LGPL-3.0.
// See file LICENSE for full license details.

using System;
using System.Buffers;

namespace Tmds.Ssh
{
    class Sequence : IDisposable
    {
        public void Dispose()
        {
            // TODO: return Sequence and it parts to SequencePool.
        }

        public ReadOnlySequence<byte> AsReadOnlySequence()
        {
            // TODO...
            return ReadOnlySequence<byte>.Empty;
        }
    }
}
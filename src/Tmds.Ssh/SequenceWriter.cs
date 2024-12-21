// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

ref partial struct SequenceWriter
{
    private readonly Sequence? _sequence;
    private Span<byte> _unused;

    public SequencePool SequencePool
        => Sequence.SequencePool;

    public Sequence Sequence
    {
        get
        {
            if (_sequence == null)
            {
                ThrowHelper.ThrowArgumentNull(nameof(_sequence));
            }

            return _sequence;
        }
    }

    public SequenceWriter(Sequence sequence)
    {
        if (sequence == null)
        {
            ThrowHelper.ThrowArgumentNull(nameof(sequence));
        }

        _sequence = sequence;
        _unused = default;
    }

    private Span<byte> AllocGetSpan(int minimumLength)
    {
        if (_unused.Length <= minimumLength)
        {
            EnlargeUnused(minimumLength);
        }

        return _unused;
    }

    private void EnlargeUnused(int minimumLength)
    {
        _unused = Sequence.AllocGetSpan(minimumLength);
    }

    private void AppendAlloced(int length)
    {
        _unused = _unused.Slice(length);
        Sequence.AppendAlloced(length);
    }
}

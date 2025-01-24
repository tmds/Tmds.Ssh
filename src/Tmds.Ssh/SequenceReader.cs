// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Buffers;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace Tmds.Ssh;

ref struct SequenceReader
{
    private static readonly UTF8Encoding s_utf8Encoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    private SequenceReader<byte> _reader;

    public long Length => _reader.Length;
    public bool AtEnd => _reader.End;
    public long Consumed => _reader.Consumed;

    public SequenceReader(Sequence sequence)
    {
        if (sequence == null)
        {
            ThrowHelper.ThrowArgumentNull(nameof(sequence));
        }

        _reader = new SequenceReader<byte>(sequence.AsReadOnlySequence());
    }

    public SequenceReader(byte[] array)
    {
        if (array == null)
        {
            ThrowHelper.ThrowArgumentNull(nameof(array));
        }

        _reader = new SequenceReader<byte>(new ReadOnlySequence<byte>(array));
    }

    public SequenceReader(ReadOnlyMemory<byte> memory)
    {
        _reader = new SequenceReader<byte>(new ReadOnlySequence<byte>(memory));
    }

    public SequenceReader(ReadOnlySequence<byte> data)
    {
        _reader = new SequenceReader<byte>(data);
    }

    public byte ReadByte()
    {
        if (_reader.TryRead(out byte b))
        {
            return b;
        }
        ThrowHelper.ThrowProtocolUnexpectedEndOfPacket();
        return 0;
    }

    public void ReadByte(byte expectedValue)
    {
        byte value = ReadByte();
        if (value != expectedValue)
        {
            ThrowHelper.ThrowProtocolUnexpectedValue();
        }
    }

    public MessageId ReadMessageId()
    {
        return (MessageId)ReadByte();
    }

    public void ReadMessageId(MessageId expectedValue)
    {
        MessageId value = ReadMessageId();
        if (value != expectedValue)
        {
            ThrowHelper.ThrowProtocolUnexpectedValue();
        }
    }

    public uint ReadUInt32()
    {
        if (_reader.TryReadBigEndian(out int i))
        {
            return unchecked((uint)i);
        }
        ThrowHelper.ThrowProtocolUnexpectedEndOfPacket();
        return 0;
    }

    public void SkipUInt32()
    {
        Skip(4);
    }

    public uint ReadUInt32(uint expectedValue)
    {
        uint value = ReadUInt32();
        if (value != expectedValue)
        {
            ThrowHelper.ThrowProtocolUnexpectedValue();
        }
        return value;
    }

    public bool ReadBoolean()
    {
        return ReadByte() != 0;
    }

    public void SkipBoolean()
    {
        Skip(1);
    }

    public ulong ReadUInt64()
    {
        if (_reader.TryReadBigEndian(out long i))
        {
            return unchecked((ulong)i);
        }
        ThrowHelper.ThrowProtocolUnexpectedEndOfPacket();
        return 0;
    }

    public ReadOnlySequence<byte> ReadStringAsBytes()
    {
        long length = ReadUInt32();
        if (TryRead(length, out ReadOnlySequence<byte> value))
        {
            return value;
        }
        ThrowHelper.ThrowProtocolUnexpectedEndOfPacket();
        return default;
    }

    public ReadOnlySequence<byte> ReadStringAsBytes(int maxLength)
    {
        ReadOnlySequence<byte> data = ReadStringAsBytes();
        if (data.Length > maxLength)
        {
            ThrowHelper.ThrowProtocolStringTooLong();
        }
        return data;
    }

    public byte[] ReadStringAsByteArray()
    {
        long length = ReadUInt32();
        ReadOnlySpan<byte> span = _reader.UnreadSpan;
        byte[] byteArray;
        if (span.Length >= length)
        {
            byteArray = new byte[length];
            span.Slice(0, (int)length).CopyTo(byteArray);
        }
        else
        {
            byteArray = _reader.Sequence.Slice(_reader.Position, length).ToArray();
        }
        _reader.Advance(length);

        return byteArray;
    }

    public SshKey ReadSshKey()
    {
        ReadOnlySequence<byte> key = ReadStringAsBytes(Constants.MaxKeyLength);
        SequenceReader keyReader = new SequenceReader(key);
        Name type = keyReader.ReadName();
        return new SshKey(type, key.ToArray());
    }

    public void SkipString()
    {
        long length = ReadUInt32();
        Skip(length);
    }

    public string ReadUtf8String()
    {
        long length = ReadUInt32();
        try
        {
            ReadOnlySpan<byte> span = _reader.UnreadSpan.Length >= length ?
                _reader.UnreadSpan.Slice(0, (int)length) :
                _reader.Sequence.Slice(_reader.Position, length).ToArray(); // MAYDO: maybe stackalloc if length is small
            _reader.Advance(length);
            try
            {
                return s_utf8Encoding.GetString(span);
            }
            catch (DecoderFallbackException)
            {
                ThrowHelper.ThrowProtocolInvalidUtf8();
                throw;
            }
        }
        catch (ArgumentOutOfRangeException)
        {
            ThrowHelper.ThrowProtocolUnexpectedEndOfPacket();
            throw;
        }
    }

    public Name ReadName()
    {
        long length = ReadUInt32();
        return ReadName(length);
    }

    public void ReadName(Name expected)
    {
        // MAYDO: implement without allocating.
        if (ReadName() != expected)
        {
            ThrowHelper.ThrowProtocolUnexpectedValue();
        }
    }

    public void ReadName(Name expected, IReadOnlyList<Name> allowedNames)
    {
        var name = ReadName();
        if (name != expected || !allowedNames.Contains(name))
        {
            ThrowHelper.ThrowProtocolUnexpectedValue();
        }
    }

    public Name ReadName(IReadOnlyList<Name> allowedNames)
    {
        var name = ReadName();
        if (!allowedNames.Contains(name))
        {
            ThrowHelper.ThrowProtocolUnexpectedValue();
            return default;
        }

        return name;
    }

    private Name ReadName(long length)
    {
        try
        {
            Name name;
            if (_reader.UnreadSpan.Length >= length)
            {
                name = Name.Parse(_reader.UnreadSpan.Slice(0, (int)length));
            }
            else
            {
                if (length > Constants.MaxParseNameLength)
                {
                    ThrowHelper.ThrowProtocolNameTooLong();
                }
                name = Name.Parse(_reader.Sequence.Slice(_reader.Position, length).ToArray());
            }

            _reader.Advance(length);

            return name;
        }
        catch (ArgumentOutOfRangeException)
        {
            ThrowHelper.ThrowProtocolUnexpectedEndOfPacket();
            throw;
        }
    }

    public Name[] ReadNameList()
    {
        long length = ReadUInt32();
        if (length == 0)
        {
            return Array.Empty<Name>();
        }

        List<Name> names = new List<Name>();

        if (TryRead(length, out ReadOnlySequence<byte> namesSequence))
        {
            SequenceReader<byte> namesReader = new SequenceReader<byte>(namesSequence);

            while (namesReader.TryReadTo(out ReadOnlySequence<byte> nameSequence, (byte)','))
            {
                Name name = ReadName(nameSequence);
                names.Add(name);
            }

            names.Add(ReadName(namesReader.Sequence.Slice(namesReader.Position)));
        }
        else
        {
            ThrowHelper.ThrowProtocolUnexpectedEndOfPacket();
        }

        return names.ToArray();

        static Name ReadName(ReadOnlySequence<byte> nameSequence)
        {
            if (nameSequence.FirstSpan.Length == nameSequence.Length)
            {
                return Name.Parse(nameSequence.FirstSpan);
            }
            else
            {
                if (nameSequence.Length > Constants.MaxParseNameLength)
                {
                    ThrowHelper.ThrowProtocolNameTooLong();
                }
                return Name.Parse(nameSequence.ToArray());
            }
        }
    }

    public BigInteger ReadMPInt()
    {
        long length = ReadUInt32();

        if (length > Constants.MaxMPIntLength)
        {
            ThrowHelper.ThrowProtocolMPIntTooLong();
        }

        if (length == 0)
        {
            return BigInteger.Zero;
        }
        try
        {
            ReadOnlySpan<byte> span = _reader.UnreadSpan.Length >= length ?
                    _reader.UnreadSpan.Slice(0, (int)length) :
                    _reader.Sequence.Slice(_reader.Position, length).ToArray(); // MAYDO: maybe stackalloc if length is small

            _reader.Advance(length);

            return new BigInteger(span, isUnsigned: false, isBigEndian: true);
        }
        catch (ArgumentOutOfRangeException)
        {
            ThrowHelper.ThrowProtocolUnexpectedEndOfPacket();
            throw;
        }
    }

    public byte[] ReadMPIntAsByteArray(bool isUnsigned, int minLength = -1)
    {
        minLength = Math.Max(1, minLength);

        uint l = ReadUInt32();

        if (Math.Max(l, minLength) > Constants.MaxMPIntLength)
        {
            ThrowHelper.ThrowProtocolMPIntTooLong();
        }

        int length = (int)l;

        if (length == 0)
        {
            return new byte[minLength];
        }

        byte firstByte = ReadByte();

        bool isNegative = firstByte >= 128;
        if (isUnsigned && isNegative)
        {
            ThrowHelper.ThrowProtocolValueOutOfRange();
        }

        bool skipFirstByte = isUnsigned && firstByte == 0;

        int arrayLength = Math.Max(minLength, length + (skipFirstByte ? -1 : 0));
        byte[] array = new byte[arrayLength];

        length--;

        array.AsSpan(0, arrayLength - length).Fill(isNegative ? (byte)0xff : (byte)0x00);

        if (!skipFirstByte)
        {
            array[arrayLength - length - 1] = firstByte;
        }

        if (!_reader.TryCopyTo(array.AsSpan(arrayLength - length)))
        {
            ThrowHelper.ThrowProtocolUnexpectedEndOfPacket();
        }

        _reader.Advance(length);

        return array;
    }

    public ECPoint ReadStringAsECPoint()
    {
        long length = ReadUInt32();
        if (length == 0)
        {
            ThrowHelper.ThrowProtocolECPointInvalidLength();
        }
        if (length > Constants.MaxECPointLength)
        {
            ThrowHelper.ThrowProtocolECPointTooLong();
        }

        byte firstByte = ReadByte();
        if (firstByte != 0x04) // Check uncompressed.
        {
            ThrowHelper.ThrowNotSupportedException("Reading compressed ECPoints is not supported.");
        }
        length--;

        if (length % 2 != 0)
        {
            ThrowHelper.ThrowProtocolECPointInvalidLength();
        }

        return new ECPoint
        {
            X = ReadBytes(length / 2),
            Y = ReadBytes(length / 2)
        };
    }

    public void Skip(long count)
    {
        try
        {
            _reader.Advance(count);
        }
        catch (ArgumentOutOfRangeException)
        {
            ThrowHelper.ThrowProtocolUnexpectedEndOfPacket();
        }
    }

    public void ReadEnd()
    {
        if (!AtEnd)
        {
            ThrowHelper.ThrowProtocolPacketLongerThanExpected();
        }
    }

    // This will be added in https://github.com/dotnet/corefx/issues/40962.
    public bool TryRead(long length, out ReadOnlySequence<byte> value)
    {
        SequencePosition start = _reader.Position;
        try
        {
            _reader.Advance(length);
        }
        catch (ArgumentOutOfRangeException)
        {
            value = default;
            return false;
        }
        SequencePosition end = _reader.Position;
        value = _reader.Sequence.Slice(start, end);
        return true;
    }

    private byte[] ReadBytes(long length)
    {
        try
        {
            byte[] bytes = _reader.UnreadSpan.Length >= length ?
                    _reader.UnreadSpan.Slice(0, (int)length).ToArray() :
                    _reader.Sequence.Slice(_reader.Position, length).ToArray();

            _reader.Advance(length);

            return bytes;
        }
        catch (ArgumentOutOfRangeException)
        {
            ThrowHelper.ThrowProtocolUnexpectedEndOfPacket();
            throw;
        }
    }
}

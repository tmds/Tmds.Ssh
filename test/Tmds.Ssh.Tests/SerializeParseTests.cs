using System.Buffers;
using System.Text;
using Xunit;

namespace Tmds.Ssh.Managed.Tests;

public class SerializeParseTests
{
    [Fact]
    public void Byte()
    {
        SequenceWriter writer = CreateSequenceWriter();
        writer.WriteByte(100);
        writer.WriteByte(200);

        SequenceReader reader = new SequenceReader(writer.Sequence);
        Assert.Equal(100, reader.ReadByte());
        Assert.Equal(200, reader.ReadByte());
    }

    [Fact]
    public void UInt32()
    {
        SequenceWriter writer = CreateSequenceWriter();
        writer.WriteUInt32(100);
        writer.WriteUInt32(100U);
        writer.WriteUInt32(uint.MaxValue);

        SequenceReader reader = new SequenceReader(writer.Sequence);
        Assert.Equal(100U, reader.ReadUInt32());
        Assert.Equal(100U, reader.ReadUInt32());
        Assert.Equal(uint.MaxValue, reader.ReadUInt32());
    }

    [Fact]
    public void UInt64()
    {
        SequenceWriter writer = CreateSequenceWriter();
        writer.WriteUInt64(100);
        writer.WriteUInt64(100U);
        writer.WriteUInt64(ulong.MaxValue);

        SequenceReader reader = new SequenceReader(writer.Sequence);
        Assert.Equal(100U, reader.ReadUInt64());
        Assert.Equal(100U, reader.ReadUInt64());
        Assert.Equal(ulong.MaxValue, reader.ReadUInt64());
    }

    [Fact]
    public void Boolean()
    {
        SequenceWriter writer = CreateSequenceWriter();
        writer.WriteBoolean(true);
        writer.WriteBoolean(false);

        SequenceReader reader = new SequenceReader(writer.Sequence);
        Assert.True(reader.ReadBoolean());
        Assert.False(reader.ReadBoolean());
    }

    [Fact]
    public void StringBytes()
    {
        var hello = Encoding.UTF8.GetBytes("hello");
        var empty = Array.Empty<byte>();
        var world = Encoding.UTF8.GetBytes("world");
        var longData = new byte[1_000_000];
        new Random().NextBytes(longData);

        SequenceWriter writer = CreateSequenceWriter();
        writer.WriteString(hello);
        writer.WriteString(empty);
        writer.WriteString(world);
        writer.WriteString(longData);

        SequenceReader reader = new SequenceReader(writer.Sequence);
        Assert.Equal(hello, reader.ReadStringAsBytes().ToArray());
        Assert.Equal(empty, reader.ReadStringAsBytes().ToArray());
        Assert.Equal(world, reader.ReadStringAsBytes().ToArray());
        Assert.Equal(longData, reader.ReadStringAsBytes().ToArray());
    }

    [Fact]
    public void StringUtf8()
    {
        SequenceWriter writer = CreateSequenceWriter();
        writer.WriteString("hello");
        writer.WriteString("");
        writer.WriteString("world");
        var longString = GenerateRandomString(1_000_000);
        writer.WriteString(longString);

        SequenceReader reader = new SequenceReader(writer.Sequence);
        Assert.Equal("hello", reader.ReadUtf8String());
        Assert.Equal("", reader.ReadUtf8String());
        Assert.Equal("world", reader.ReadUtf8String());
        Assert.Equal(longString, reader.ReadUtf8String());
    }

    [Fact]
    public void StringName()
    {
        SequenceWriter writer = CreateSequenceWriter();
        writer.WriteString(new Name("hello"));
        writer.WriteString(new Name(""));
        writer.WriteString(new Name("world"));

        SequenceReader reader = new SequenceReader(writer.Sequence);
        Assert.Equal(new Name("hello"), reader.ReadName());
        Assert.Equal(new Name(""), reader.ReadName());
        Assert.Equal(new Name("world"), reader.ReadName());
    }

    [Fact]
    public void NameList()
    {
        var single = new List<Name> { new Name("foo") };
        var empty = new List<Name> { };
        var double_ = new List<Name> { new Name("bar"), new Name("baz") };

        SequenceWriter writer = CreateSequenceWriter();
        writer.WriteNameList(single);
        writer.WriteNameList(empty);
        writer.WriteNameList(double_);

        SequenceReader reader = new SequenceReader(writer.Sequence);
        Assert.Equal(single, reader.ReadNameList());
        Assert.Equal(empty, reader.ReadNameList());
        Assert.Equal(double_, reader.ReadNameList());
    }

    [Fact]
    public void MPInt()
    {
        SequenceWriter writer = CreateSequenceWriter();
        writer.WriteMPInt(1);
        writer.WriteMPInt(0);
        writer.WriteMPInt(-1);
        writer.WriteMPInt(ulong.MaxValue);
        writer.WriteMPInt(long.MinValue);

        SequenceReader reader = new SequenceReader(writer.Sequence);
        Assert.Equal(1, reader.ReadMPInt());
        Assert.Equal(0, reader.ReadMPInt());
        Assert.Equal(-1, reader.ReadMPInt());
        Assert.Equal(ulong.MaxValue, reader.ReadMPInt());
        Assert.Equal(long.MinValue, reader.ReadMPInt());
    }

    private static string GenerateRandomString(int length)
    {
        Random random = new Random();
        StringBuilder sb = new StringBuilder();
        while (length > 0)
        {
            sb.Append((char)random.Next('a', 'z'));
            length--;
        }
        return sb.ToString();
    }

    private static SequenceWriter CreateSequenceWriter()
        => new SequenceWriter(new SequencePool().RentSequence());
}

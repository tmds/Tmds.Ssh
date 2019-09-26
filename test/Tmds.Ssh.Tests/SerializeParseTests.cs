using System;
using System.Buffers;
using System.Collections.Generic;
using System.Text;
using Xunit;

namespace Tmds.Ssh.Tests
{
    public class SerializeParseTests
    {
        [Fact]
        public void Byte()
        {
            Sequence sequence = new SequencePool().RentSequence();
            sequence.WriteByte(100);
            sequence.WriteByte(200);

            var reader = sequence.CreateReader();
            Assert.Equal(100, reader.ReadByte());
            Assert.Equal(200, reader.ReadByte());
        }

        [Fact]
        public void UInt32()
        {
            Sequence sequence = new SequencePool().RentSequence();
            sequence.WriteUInt32(100);
            sequence.WriteUInt32(100U);
            sequence.WriteUInt32(uint.MaxValue);

            var reader = sequence.CreateReader();
            Assert.Equal(100U, reader.ReadUInt32());
            Assert.Equal(100U, reader.ReadUInt32());
            Assert.Equal(uint.MaxValue, reader.ReadUInt32());
        }

        [Fact]
        public void UInt64()
        {
            Sequence sequence = new SequencePool().RentSequence();
            sequence.WriteUInt64(100);
            sequence.WriteUInt64(100U);
            sequence.WriteUInt64(ulong.MaxValue);

            var reader = sequence.CreateReader();
            Assert.Equal(100U, reader.ReadUInt64());
            Assert.Equal(100U, reader.ReadUInt64());
            Assert.Equal(ulong.MaxValue, reader.ReadUInt64());
        }

        [Fact]
        public void Boolean()
        {
            Sequence sequence = new SequencePool().RentSequence();
            sequence.WriteBoolean(true);
            sequence.WriteBoolean(false);

            var reader = sequence.CreateReader();
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

            Sequence sequence = new SequencePool().RentSequence();
            sequence.WriteString(hello);
            sequence.WriteString(empty);
            sequence.WriteString(world);
            sequence.WriteString(longData);

            var reader = sequence.CreateReader();
            Assert.Equal(hello, reader.ReadStringAsBytes().ToArray());
            Assert.Equal(empty, reader.ReadStringAsBytes().ToArray());
            Assert.Equal(world, reader.ReadStringAsBytes().ToArray());
            Assert.Equal(longData, reader.ReadStringAsBytes().ToArray());
        }

        [Fact]
        public void StringUtf8()
        {
            Sequence sequence = new SequencePool().RentSequence();
            sequence.WriteString("hello");
            sequence.WriteString("");
            sequence.WriteString("world");
            var longString = GenerateRandomString(1_000_000);
            sequence.WriteString(longString);

            var reader = sequence.CreateReader();
            Assert.Equal("hello", reader.ReadUtf8String());
            Assert.Equal("", reader.ReadUtf8String());
            Assert.Equal("world", reader.ReadUtf8String());
            Assert.Equal(longString, reader.ReadUtf8String());
        }

        [Fact]
        public void StringAscii()
        {
            Sequence sequence = new SequencePool().RentSequence();
            sequence.WriteString("hello");
            sequence.WriteString("");
            sequence.WriteString("world");
            var longString = GenerateRandomString(1_000_000);
            sequence.WriteString(longString);

            var reader = sequence.CreateReader();
            Assert.Equal("hello", reader.ReadAsciiString());
            Assert.Equal("", reader.ReadAsciiString());
            Assert.Equal("world", reader.ReadAsciiString());
            Assert.Equal(longString, reader.ReadAsciiString());
        }

        [Fact]
        public void NameList()
        {
            var single = new List<string> { "foo"};
            var empty = new List<string> { };
            var double_ = new List<string> { "bar", "baz" };

            Sequence sequence = new SequencePool().RentSequence();
            sequence.WriteNameList(single);
            sequence.WriteNameList(empty);
            sequence.WriteNameList(double_);

            var reader = sequence.CreateReader();
            Assert.Equal(single, reader.ReadNameList());
            Assert.Equal(empty, reader.ReadNameList());
            Assert.Equal(double_, reader.ReadNameList());
        }

        [Fact]
        public void MPInt()
        {
            Sequence sequence = new SequencePool().RentSequence();
            sequence.WriteMPInt(1);
            sequence.WriteMPInt(0);
            sequence.WriteMPInt(-1);
            sequence.WriteMPInt(ulong.MaxValue);
            sequence.WriteMPInt(long.MinValue);

            var reader = sequence.CreateReader();
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
    }
}

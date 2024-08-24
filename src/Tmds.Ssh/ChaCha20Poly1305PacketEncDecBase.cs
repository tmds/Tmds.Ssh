// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Buffers.Binary;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

namespace Tmds.Ssh;

class ChaCha20Poly1305PacketEncDecBase
{
    public const int TagSize = 16;      // Poly1305 hash length.
    protected const int PaddTo = 8;     // We're not a block cipher. Padd to 8 octets per rfc4253.
    protected const int LengthSize = 4; // SSH packet length field is 4 bytes.

    protected readonly ChaCha7539Engine LengthCipher;
    protected readonly ChaCha7539Engine PayloadCipher;
    protected readonly Poly1305 Mac;
    private readonly byte[] _K1;
    private readonly byte[] _K2;

    protected ChaCha20Poly1305PacketEncDecBase(byte[] key)
    {
        _K1 = key.AsSpan(32, 32).ToArray();
        _K2 = key.AsSpan(0, 32).ToArray();
        LengthCipher = new();
        PayloadCipher = new();
        Mac = new();
    }

    protected void ConfigureCiphers(uint sequenceNumber)
    {
        Span<byte> iv = stackalloc byte[12];
        Span<byte> polyKey = stackalloc byte[64];
        BinaryPrimitives.WriteUInt64BigEndian(iv[4..], sequenceNumber);
        LengthCipher.Init(forEncryption: true, new ParametersWithIV(new KeyParameter(_K1), iv));
        PayloadCipher.Init(forEncryption: true, new ParametersWithIV(new KeyParameter(_K2), iv));
        // note: encrypting 64 bytes increments the ChaCha20 block counter.
        PayloadCipher.ProcessBytes(input: polyKey, output: polyKey);
        Mac.Init(new KeyParameter(polyKey[..32]));
    }
}

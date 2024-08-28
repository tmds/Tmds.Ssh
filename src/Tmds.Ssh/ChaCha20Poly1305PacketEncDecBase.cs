// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

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

    protected readonly MyChaCha20 LengthCipher;
    protected readonly MyChaCha20 PayloadCipher;
    protected readonly Poly1305 Mac;
    private readonly byte[] _iv;

    protected ChaCha20Poly1305PacketEncDecBase(byte[] key)
    {
        _iv = new byte[12];
        byte[] K_1 = key.AsSpan(32, 32).ToArray();
        byte[] K_2 = key.AsSpan(0, 32).ToArray();
        LengthCipher = new(K_1, _iv);
        PayloadCipher = new(K_2, _iv);
        Mac = new();
    }

    protected void ConfigureCiphers(uint sequenceNumber)
    {
        BinaryPrimitives.WriteUInt64BigEndian(_iv.AsSpan(4), sequenceNumber);
        LengthCipher.SetIv(_iv);
        PayloadCipher.SetIv(_iv);

        // note: encrypting 64 bytes increments the ChaCha20 block counter.
        Span<byte> polyKey = stackalloc byte[64];
        PayloadCipher.ProcessBytes(input: polyKey, output: polyKey);
        Mac.Init(new KeyParameter(polyKey[..32]));
    }

    // This class eliminates per packet ParametersWithIV/KeyParameter allocations.
    sealed protected class MyChaCha20 : ChaCha7539Engine
    {
        public MyChaCha20(byte[] key, byte[] dummyIv)
        {
            Init(forEncryption: true, new ParametersWithIV(new KeyParameter(key), dummyIv));
        }

        public void SetIv(byte[] iv)
        {
            SetKey(null, iv);

            Reset();
        }
    }
}

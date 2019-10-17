using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Numerics;
using System.Reflection;
using System.Security.Cryptography;
using Xunit;

namespace Tmds.Ssh.Tests
{
    public class ECDHSharedSecretTests
    {
        [Theory]
        [MemberData(nameof(Data))]
        public void SharedSecret(ECCurve curve, byte[] localPrivateKey, ECPoint localPublicKey, ECPoint remotePublicKey, byte[] expectedSharedSecret)
        {
            BigInteger expectedSharedSecretBigInt = ToBigInteger(expectedSharedSecret);
            byte[] expectedSharedSecretMPInt = FormatMPInt(expectedSharedSecretBigInt);

            ECParameters localParameters = new ECParameters
            {
                Curve = curve,
                D = localPrivateKey,
                Q = localPublicKey
            };
            using ECDiffieHellman localEcdh = ECDiffieHellman.Create(localParameters);

            ECParameters remoteParameters = new ECParameters
            {
                Curve = curve,
                Q = remotePublicKey
            };
            using ECDiffieHellman remoteEcdh = ECDiffieHellman.Create(remoteParameters);
            using ECDiffieHellmanPublicKey remoteKey = remoteEcdh.PublicKey;

            byte[] derivedSecret = DeriveSharedSecret(localEcdh, remoteKey);

            Assert.Equal(expectedSharedSecret, derivedSecret);
        }

        public static IEnumerable<object[]> Data =>
            new List<object[]>
            {
                // secret highest bit is '1'.
                new object[] { ECCurve.NamedCurves.nistP256,
                    HexToByteArray("a3154294bf468057f1903af6395788e6394988c4a1c3e9097c1425e94c898631"),
                    new ECPoint
                    {
                        X = HexToByteArray("fa719e6b556b83d413969196afdf2b07ce1ad14829f48b4c290fe276925148c7"),
                        Y = HexToByteArray("984a4a8d4686f162feefee023bc77184ea705e32bc304f0dbd166a2fe2ed204f")
                    },
                    new ECPoint
                    {
                        X = HexToByteArray("7f1da1f7f189a6f92aa4b83a0d3e9fd697d985b4bc3d13cfe05100d93e59c790"),
                        Y = HexToByteArray("01aa6b799ab30f02ca9195f17adf486d5c2482441506a42993d95f3c7c68bffd")
                    },
                    HexToByteArray("db55a875c76189ec1268adb15b98015d6e7d9b4d55736379be838af932ad387f") },
                // secret highest bit is '0'.
                new object[] { ECCurve.NamedCurves.nistP256,
                    HexToByteArray("17d2705e867e07a6e0186ee2aed5de27fc96cb28563c1a263848357d057145bc"),
                    new ECPoint
                    {
                        X = HexToByteArray("c6cc64f1b34f58ea2bd078b594ff5dc8abc4dc7e715ce6b4d091c707fc79e8a8"),
                        Y = HexToByteArray("da7ceb2cce46e97fe8205798a147bb877f762ead4b24b98aa3248cff064f3270")
                    },
                    new ECPoint
                    {
                        X = HexToByteArray("cead27708efde963fb24816063db4688145f1ab0aa990948da451fb4fcd2a08c"),
                        Y = HexToByteArray("62aa61ddfd26e833b73c816077eb3df972716f606dfd1211c57931e2230195fd")
                    },
                    HexToByteArray("33e9ee86460fc4e418261db36348d5fd5d28bff511a2e6b31f25bf90f7513a9f") },
                // secret highest byte is '00'.
                new object[] { ECCurve.NamedCurves.nistP256,
                    HexToByteArray("d84594f505a65785fcd2a5b0b1ebfa98ca0cc9076150c49ee05bb78b2ef17554"),
                    new ECPoint
                    {
                        X = HexToByteArray("8e9833e7fdd35872bc93261f6e6ceca4fa95deaea08234c584cafbc23fe95def"),
                        Y = HexToByteArray("5ad7246e7cd23eb6631927c023b9e829e119f17cdfa6039a9eee9f7347b6e5a7")
                    },
                    new ECPoint
                    {
                        X = HexToByteArray("292045ec970cc19a321199d686ca6296979a75072e060a4949d3185ba245fbfc"),
                        Y = HexToByteArray("dc981c8cbafa7c4bb4fff40fd40f2e4c7e7bd29bbaa0ff71ff8642fd1ec17cac")
                    },
                    HexToByteArray("00d7baadd6b7809d435347bc9ddd8505f0dace0067a9f7b5fa15f13231489b88") },
            };

        internal static byte[] HexToByteArray(string hexString)
        {
            byte[] bytes = new byte[hexString.Length / 2];

            for (int i = 0; i < hexString.Length; i += 2)
            {
                string s = hexString.Substring(i, 2);
                bytes[i / 2] = byte.Parse(s, NumberStyles.HexNumber, null);
            }

            return bytes;
        }

        private static byte[] DeriveSharedSecret(ECDiffieHellman ecdh, ECDiffieHellmanPublicKey peerPublicKey)
        {
            // TODO: this uses Reflection on the OpenSSL implementation to figure out the shared key.
            // Can we use 'ECDiffieHellman.DeriveKeyFromHash' instead?

            var method = ecdh.GetType().GetMethod("DeriveSecretAgreement", BindingFlags.NonPublic | BindingFlags.Instance, null, new Type[] { typeof(ECDiffieHellmanPublicKey), typeof(IncrementalHash) }, null);
            if (method != null)
            {
                object? rv = method.Invoke(ecdh, new[] { peerPublicKey, null });
                if (rv is byte[] sharedSecretArray)
                {
                    return sharedSecretArray;
                }
            }

            throw new NotSupportedException("Cannot determine private key.");
        }

        private static BigInteger ToBigInteger(ReadOnlySpan<byte> span)
        {
            return new BigInteger(span, isUnsigned: true, isBigEndian: true);
        }

        private static byte[] FormatMPInt(BigInteger bi)
        {
            int byteCount = bi.GetByteCount(isUnsigned: false);
            byte[] rv = new byte[4 + byteCount];
            BinaryPrimitives.WriteUInt32BigEndian(rv, (uint)byteCount);
            bi.TryWriteBytes(rv.AsSpan().Slice(4, byteCount), out int bytesWritten, isUnsigned: false, isBigEndian: true);
            Debug.Assert(bytesWritten == byteCount);
            return rv;
        }
    }
}

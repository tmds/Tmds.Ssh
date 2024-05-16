// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Buffers;
using System.Security.Cryptography;

namespace Tmds.Ssh.Managed
{
    sealed class RsaPrivateKey : PrivateKey
    {
        private readonly RSA _rsa;

        public RsaPrivateKey(RSA rsa) :
            base(AlgorithmNames.SshSha2_256)
        {
            _rsa = rsa ?? throw new ArgumentNullException(nameof(rsa));
        }

        public override void Dispose()
        {
            _rsa.Dispose();
        }

        public override void AppendPublicKey(ref SequenceWriter writer)
        {
            RSAParameters parameters = _rsa.ExportParameters(includePrivateParameters: false);
            using var innerData = writer.SequencePool.RentSequence();
            var innerWriter = new SequenceWriter(innerData);
            innerWriter.WriteString(AlgorithmNames.SshRsa);
            innerWriter.WriteMPInt(parameters.Exponent);
            innerWriter.WriteMPInt(parameters.Modulus);

            writer.WriteString(innerData.AsReadOnlySequence());
        }

        public override void AppendSignature(ref SequenceWriter writer, ReadOnlySequence<byte> data)
        {
            using var innerData = writer.SequencePool.RentSequence();
            var innerWriter = new SequenceWriter(innerData);
            innerWriter.WriteString(AlgorithmNames.SshSha2_256);
            int signatureLength = _rsa.KeySize / 8;
            byte[] signature = new byte[signatureLength];
            if (!_rsa.TrySignData(data.ToArray(), signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1, out int bytesWritten) ||
                bytesWritten != signatureLength)
            {
                throw new InvalidOperationException("Unable to sign data.");
            }
            innerWriter.WriteString(signature);

            writer.WriteString(innerData.AsReadOnlySequence());
        }
    }
}
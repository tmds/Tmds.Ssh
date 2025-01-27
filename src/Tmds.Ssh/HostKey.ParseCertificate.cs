// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Buffers;
using System.Security.Cryptography;
using Org.BouncyCastle.Math.EC.Rfc8032;

namespace Tmds.Ssh;

// https://cvsweb.openbsd.org/cgi-bin/cvsweb/~checkout~/src/usr.bin/ssh/PROTOCOL.certkeys
partial class HostKey
{
    const int SSH_CERT_TYPE_HOST = 2;

    private static (PublicKeyAlgorithm, HostCertificateInfo) ParseCertificate(SshKeyData key)
    {
        Name type = key.Type;
        if (key.Type == AlgorithmNames.SshEd25519Cert)
        {
            return ParseEd25519Cert(key);
        }
        else if (type == AlgorithmNames.SshRsaCert)
        {
            return ParseRsaCert(key);
        }
        else if (type == AlgorithmNames.EcdsaSha2Nistp256Cert ||
                 type == AlgorithmNames.EcdsaSha2Nistp384Cert ||
                 type == AlgorithmNames.EcdsaSha2Nistp521Cert)
        {
            return ParseEcdsaCert(type, key);
        }
        else
        {
            ThrowHelper.ThrowProtocolUnexpectedValue();
            return (null!, null!);
        }
    }

    private static (PublicKeyAlgorithm, HostCertificateInfo) ParseRsaCert(SshKeyData key)
    {
        /*
            string    "ssh-rsa-cert-v01@openssh.com"
            string    nonce
            mpint     e
            mpint     n
            ...
        */
        var ros = new ReadOnlySequence<byte>(key.RawData);
        var reader = new SequenceReader(ros);
        reader.ReadName(AlgorithmNames.SshRsaCert);
        reader.SkipString(); // nonce
        byte[] e = reader.ReadMPIntAsByteArray(isUnsigned: true);
        byte[] n = reader.ReadMPIntAsByteArray(isUnsigned: true);
        PublicKeyAlgorithm publicKey = new RsaPublicKey(e, n);

        SshKeyData signedKey = RsaPublicKey.DeterminePublicSshKey(e, n);

        HostCertificateInfo certificateInfo = ParseCommonHostCertificateFields(key.RawData, reader, key, signedKey);

        return (publicKey, certificateInfo);
    }

    private static (PublicKeyAlgorithm, HostCertificateInfo) ParseEcdsaCert(Name name, SshKeyData key)
    {
        /*
            string  "ecdsa-sha2-nistp256-cert-v01@openssh.com" |
                    "ecdsa-sha2-nistp384-cert-v01@openssh.com" |
                    "ecdsa-sha2-nistp521-cert-v01@openssh.com"
            string    nonce
            string    curve
            string    public_key
            ...
        */
        var ros = new ReadOnlySequence<byte>(key.RawData);
        var reader = new SequenceReader(ros);
        reader.ReadName(name);
        reader.SkipString(); // nonce
        PublicKeyAlgorithm publicKey;
        SshKeyData signedKey;
        if (name == AlgorithmNames.EcdsaSha2Nistp256Cert)
        {
            reader.ReadName(AlgorithmNames.Nistp256);
            ECPoint q = reader.ReadStringAsECPoint();
            publicKey = new ECDsaPublicKey(AlgorithmNames.EcdsaSha2Nistp256, ECCurve.NamedCurves.nistP256, q, HashAlgorithmName.SHA256);
            signedKey = ECDsaPublicKey.DeterminePublicSshKey(AlgorithmNames.EcdsaSha2Nistp256, AlgorithmNames.Nistp256, q);
        }
        else if (name == AlgorithmNames.EcdsaSha2Nistp384Cert)
        {
            reader.ReadName(AlgorithmNames.Nistp384);
            ECPoint q = reader.ReadStringAsECPoint();
            publicKey = new ECDsaPublicKey(AlgorithmNames.EcdsaSha2Nistp384, ECCurve.NamedCurves.nistP384, q, HashAlgorithmName.SHA384);
            signedKey = ECDsaPublicKey.DeterminePublicSshKey(AlgorithmNames.EcdsaSha2Nistp384, AlgorithmNames.Nistp384, q);
        }
        else if (name == AlgorithmNames.EcdsaSha2Nistp521Cert)
        {
            reader.ReadName(AlgorithmNames.Nistp521);
            ECPoint q = reader.ReadStringAsECPoint();
            publicKey = new ECDsaPublicKey(AlgorithmNames.EcdsaSha2Nistp521, ECCurve.NamedCurves.nistP521, q, HashAlgorithmName.SHA512);
            signedKey = ECDsaPublicKey.DeterminePublicSshKey(AlgorithmNames.EcdsaSha2Nistp521, AlgorithmNames.Nistp521, q);
        }
        else
        {
            ThrowHelper.ThrowProtocolUnexpectedValue();
            publicKey = null!;
            signedKey = default;
        }

        HostCertificateInfo certificateInfo = ParseCommonHostCertificateFields(key.RawData, reader, key, signedKey);

        return (publicKey, certificateInfo);
    }

    private static (PublicKeyAlgorithm, HostCertificateInfo) ParseEd25519Cert(SshKeyData key)
    {
        /*
            string    "ssh-ed25519-cert-v01@openssh.com"
            string    nonce
            string    pk
            ...
        */
        var ros = new ReadOnlySequence<byte>(key.RawData);
        var reader = new SequenceReader(ros);
        reader.ReadName(AlgorithmNames.SshEd25519Cert);
        reader.SkipString(); // nonce
        ReadOnlySequence<byte> pk = reader.ReadStringAsBytes();
        if (pk.Length != Ed25519.PublicKeySize)
        {
            ThrowHelper.ThrowProtocolUnexpectedValue();
        }
        byte[] pkArray = pk.ToArray();
        PublicKeyAlgorithm publicKey = new Ed25519PublicKey(pkArray);

        SshKeyData signedKey = Ed25519PublicKey.DeterminePublicSshKey(pkArray);

        HostCertificateInfo certificateInfo = ParseCommonHostCertificateFields(key.RawData, reader, key, signedKey);

        return (publicKey, certificateInfo);
    }

    private static HostCertificateInfo ParseCommonHostCertificateFields(ReadOnlyMemory<byte> keyData, SequenceReader reader, SshKeyData certificateKey, SshKeyData signedKey)
    {
        /*
            uint64    serial
            uint32    type
            string    key id
            string    valid principals
            uint64    valid after
            uint64    valid before
            string    critical options
            string    extensions
            string    reserved
            string    signature key
            string    signature
        */
        reader.ReadUInt64();
        reader.ReadUInt32(SSH_CERT_TYPE_HOST);
        reader.SkipString();

        var ros = reader.ReadStringAsBytes(); // principals
        var innerReader = new SequenceReader(ros);
        List<string> principals = new();
        while (!innerReader.AtEnd)
        {
            principals.Add(innerReader.ReadUtf8String());
        }

        ulong validAfter = reader.ReadUInt64();
        ulong validBefore = reader.ReadUInt64();

        ros = reader.ReadStringAsBytes(); // critical options
        // No critical options are defined for host certificates at present.
        // All such options are "critical" in the sense that an implementation
        // must refuse to authorise a key that has an unrecognised option.
        bool hasCriticalOptions = !ros.IsEmpty;

        // No extensions are defined for host certificates in the OpenSSH spec at present.
        // Custom extensions may be included.
        ros = reader.ReadStringAsBytes(); // extensions
        innerReader = new SequenceReader(ros);
        string? previousExtensionName = null;
        while (!innerReader.AtEnd)
        {
            string extensionName = innerReader.ReadUtf8String(); // name
            if (extensionName.Length == 0)
            {
                ThrowHelper.ThrowProtocolUnexpectedValue();
            }
            innerReader.SkipString(); // data

            if (previousExtensionName is not null)
            {
                if (string.CompareOrdinal(extensionName, previousExtensionName) <= 0)
                {
                    ThrowHelper.ThrowProtocolUnexpectedValue();
                }
            }
            previousExtensionName = extensionName;
        }

        reader.SkipString(); // reserved

        SshKeyData caKey = reader.ReadSshKey();

        int signedDataLength = (int)reader.Consumed;
        ReadOnlyMemory<byte> signedData = keyData.Slice(0, signedDataLength);

        var signature = reader.ReadStringAsBytes(); // signature

        reader.ReadEnd();

        PublicKeyAlgorithm caPublicKey = Ssh.PublicKeyAlgorithm.CreateFromSshKey(caKey);

        ulong dateTimeOffsetMax = (ulong)DateTimeOffset.MaxValue.ToUnixTimeSeconds();
        return new HostCertificateInfo
        (
            issuerKey: new PublicKey(caKey),
            certificateKey: certificateKey,
            signedKey: signedKey,
            hasCriticalOptions: hasCriticalOptions,
            validBefore: DateTimeOffset.FromUnixTimeSeconds((long)Math.Min(validBefore, dateTimeOffsetMax)),
            validAfter: DateTimeOffset.FromUnixTimeSeconds((long)Math.Min(validAfter, dateTimeOffsetMax)),
            principals: principals,
            signedData: signedData,
            signature: signature,
            caPublicKey: caPublicKey
        );
    }
}

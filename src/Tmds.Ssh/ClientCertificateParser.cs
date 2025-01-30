// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Buffers;
using System.Security.Cryptography;

namespace Tmds.Ssh;

sealed class ClientCertificateParser
{
    private static ReadOnlySpan<char> WhitespaceSeparators => [ ' ', '\t' ];
    private static ReadOnlySpan<char> NewlineCharacters => [ '\r', '\n' ];

    public static (SshKeyData certificate, SshKeyData publicKey) ParseClientCertificateFile(string path)
    {
        // Avoid throw when the credential file does not exist/is not accessible.
        if (!File.Exists(path))
        {
            return (default, default); // not found.
        }

        string content;
        try
        {
            content = File.ReadAllText(path);
        }
        catch (Exception e) when (e is FileNotFoundException || e is DirectoryNotFoundException)
        {
            return (default, default); // not found.
        }

        return ParseClientCertificateKey(content.AsSpan());
    }

    private static (SshKeyData certificate, SshKeyData publicKey) ParseClientCertificateKey(ReadOnlySpan<char> data)
    {
        int endOfLine = data.IndexOfAny(NewlineCharacters);
        if (endOfLine != -1)
        {
            data = data.Slice(0, endOfLine);
        }
        data.Trim(WhitespaceSeparators);
        int endOfType = data.IndexOfAny(WhitespaceSeparators);
        if (endOfType == -1)
        {
            throw new InvalidDataException($"No key type.");
        }
        ReadOnlySpan<char> keyType = data.Slice(0, endOfType);
        data = data.Slice(endOfType + 1).Trim(WhitespaceSeparators);
        ReadOnlySpan<char> base64Key = data;
        int endOfKey = base64Key.IndexOfAny(WhitespaceSeparators);
        if (endOfKey != -1)
        {
            base64Key = base64Key.Slice(0, endOfKey);
        }
        if (base64Key.IsEmpty)
        {
            throw new InvalidDataException($"No key data.");
        }
        byte[] keyData;
        try
        {
            keyData = Convert.FromBase64String(base64Key.ToString());
        }
        catch (FormatException)
        {
            throw new InvalidDataException($"Invalid base64 key data.");
        }
        SshKeyData certificate = new SshKeyData(new Name(keyType), keyData);
        SshKeyData publicKey = ParsePublicKey(certificate);
        return (certificate, publicKey);
    }

    private static SshKeyData ParsePublicKey(SshKeyData key)
    {
        Name type = key.Type;
        if (type == AlgorithmNames.SshEd25519Cert)
        {
            return ParsePublicKeyFromEd25519Cert(key);
        }
        else if (type == AlgorithmNames.SshRsaCert)
        {
            return ParsePublicKeyFromRsaCert(key);
        }
        else if (type == AlgorithmNames.EcdsaSha2Nistp256Cert ||
                 type == AlgorithmNames.EcdsaSha2Nistp384Cert ||
                 type == AlgorithmNames.EcdsaSha2Nistp521Cert)
        {
            return ParsePublicKeyFromEcdsaCert(type, key);
        }
        else
        {
            ThrowUnknownCertificateType(type);
            return default;
        }
    }

    private static SshKeyData ParsePublicKeyFromRsaCert(SshKeyData key)
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

        return RsaPublicKey.DeterminePublicSshKey(e, n);
    }

    private static SshKeyData ParsePublicKeyFromEcdsaCert(Name name, SshKeyData key)
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
        if (name == AlgorithmNames.EcdsaSha2Nistp256Cert)
        {
            reader.ReadName(AlgorithmNames.Nistp256);
            ECPoint q = reader.ReadStringAsECPoint();
            return ECDsaPublicKey.DeterminePublicSshKey(AlgorithmNames.EcdsaSha2Nistp256, AlgorithmNames.Nistp256, q);
        }
        else if (name == AlgorithmNames.EcdsaSha2Nistp384Cert)
        {
            reader.ReadName(AlgorithmNames.Nistp384);
            ECPoint q = reader.ReadStringAsECPoint();
            return ECDsaPublicKey.DeterminePublicSshKey(AlgorithmNames.EcdsaSha2Nistp384, AlgorithmNames.Nistp384, q);
        }
        else if (name == AlgorithmNames.EcdsaSha2Nistp521Cert)
        {
            reader.ReadName(AlgorithmNames.Nistp521);
            ECPoint q = reader.ReadStringAsECPoint();
            return ECDsaPublicKey.DeterminePublicSshKey(AlgorithmNames.EcdsaSha2Nistp521, AlgorithmNames.Nistp521, q);
        }
        else
        {
            ThrowUnknownCertificateType(name);
            return default;
        }
    }

    private static SshKeyData ParsePublicKeyFromEd25519Cert(SshKeyData key)
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
        byte[] pkArray = pk.ToArray();
        return Ed25519PublicKey.DeterminePublicSshKey(pkArray);
    }

    private static void ThrowUnknownCertificateType(Name name)
    {
        throw new NotSupportedException($"Unknown certificate type: {name}");
    }
}

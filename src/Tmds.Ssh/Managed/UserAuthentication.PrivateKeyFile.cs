// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Numerics;
using System.Security.Cryptography;

namespace Tmds.Ssh.Managed;

sealed partial class UserAuthentication
{
    internal static bool TryParsePrivateKeyFile(string filename, [NotNullWhen(true)] out PrivateKey? privateKey, [NotNullWhen(false)] out Exception? error)
    {
        privateKey = null;

        ReadOnlySpan<char> keyFormat;
        ReadOnlySpan<char> keyDataBase64;
        // MAYDO verify file doesn't have permissions for group/other.
        if (!File.Exists(filename))
        {
            error = new FileNotFoundException(filename);
            return false;
        }

        string fileContent;
        try
        {
            fileContent = File.ReadAllText(filename);
        }
        catch (IOException ex)
        {
            error = ex;
            return false;
        }

        int formatStart = fileContent.IndexOf("-----BEGIN");
        if (formatStart == -1)
        {
            error = new FormatException($"No start marker.");
            return false;
        }
        int keyStart = fileContent.IndexOf('\n', formatStart);
        if (keyStart == -1)
        {
            error = new FormatException($"No start marker.");
            return false;
        }
        keyStart++;
        int keyEnd = fileContent.IndexOf("-----END");
        if (formatStart == -1)
        {
            error = new FormatException($"No end marker.");
            return false;
        }
        keyFormat = fileContent.AsSpan(formatStart, keyStart - formatStart - 1).Trim();
        keyDataBase64 = fileContent.AsSpan(keyStart, keyEnd - keyStart - 1);

        byte[] keyData;
        try
        {
            keyData = Convert.FromBase64String(keyDataBase64.ToString());
        }
        catch (FormatException)
        {
            error = new FormatException($"Invalid base64 data.");
            return false;
        }

        switch (keyFormat)
        {
            case "-----BEGIN RSA PRIVATE KEY-----":
                return TryParseRsaPemKey(keyData, out privateKey, out error);
            case "-----BEGIN OPENSSH PRIVATE KEY-----":
                return TryParseOpenSshKey(keyData, out privateKey, out error);
            default:
                error = new NotSupportedException($"Unsupported format: '{keyFormat}'.");
                return false;
        }
    }

    private static bool TryParseRsaPemKey(byte[] keyData, out PrivateKey? privateKey, out Exception? error)
    {
        privateKey = null;
        RSA? rsa = RSA.Create();
        try
        {
            rsa.ImportRSAPrivateKey(keyData, out int bytesRead);
            if (bytesRead != keyData.Length)
            {
                rsa.Dispose();
                error = new FormatException($"There is additional data after the RSA key.");
                return false;
            }
            privateKey = new RsaPrivateKey(rsa);
            error = null;
            return true;
        }
        catch (Exception ex)
        {
            rsa?.Dispose();
            error = new FormatException($"The data can not be parsed into an RSA key.", ex);
            return false;
        }
    }

    private static bool TryParseOpenSshKey(byte[] keyData, out PrivateKey? privateKey, out Exception? error)
    {
        privateKey = null;

        // https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key
        /*
            byte[]	AUTH_MAGIC
            string	ciphername
            string	kdfname
            string	kdfoptions
            uint32	number of keys N
            string	publickey1
            string	publickey2
            ...
            string	publickeyN
            string	encrypted, padded list of private keys
        */
        ReadOnlySpan<byte> AUTH_MAGIC = "openssh-key-v1\0"u8;
        if (!keyData.AsSpan().StartsWith(AUTH_MAGIC))
        {
            error = new FormatException($"Unknown OpenSSH key format.");
            return false;
        }
        ReadOnlySequence<byte> ros = new ReadOnlySequence<byte>(keyData);
        ros = ros.Slice(AUTH_MAGIC.Length);
        var reader = new SequenceReader(ros);
        Name cipherName = reader.ReadName();
        if (cipherName != AlgorithmNames.None)
        {
            error = new NotSupportedException($"Unsupported cipher: '{cipherName}'.");
            return false; // cipherName not supported.
        }
        reader.SkipString(); // kfdname
        reader.SkipString(); // kdfoptions
        uint nrOfKeys = reader.ReadUInt32();
        if (nrOfKeys != 1)
        {
            error = new FormatException($"The data contains multiple keys.");
            return false; // Multiple keys are not supported.
        }
        reader.SkipString(); // skip the public key
        ReadOnlySequence<byte> privateKeyList = reader.ReadStringAsBytes();
        reader = new SequenceReader(privateKeyList);
        /*
            uint32	checkint
            uint32	checkint
            byte[]	privatekey1
            string	comment1
            byte[]	privatekey2
            string	comment2
            ...
            byte[]	privatekeyN
            string	commentN
            byte	1
            byte	2
            byte	3
            ...
            byte	padlen % 255
        */
        uint checkInt1 = reader.ReadUInt32();
        uint checkint2 = reader.ReadUInt32();
        if (checkInt1 != checkint2)
        {
            error = new FormatException($"The checkints mismatch. The key is invalid or the passphrase is wrong.");
            return false;
        }

        Name keyType = reader.ReadName();
        if (keyType == AlgorithmNames.SshRsa)
        {
            BigInteger modulus = reader.ReadMPInt();
            BigInteger exponent = reader.ReadMPInt();
            BigInteger d = reader.ReadMPInt();
            BigInteger inverseQ = reader.ReadMPInt();
            BigInteger p = reader.ReadMPInt();
            BigInteger q = reader.ReadMPInt();

            BigInteger dp = d % (p - BigInteger.One);
            BigInteger dq = d % (q - BigInteger.One);

            RSAParameters parameters = new()
            {
                Modulus = modulus.ToByteArray(isUnsigned: true, isBigEndian: true),
                Exponent = exponent.ToByteArray(isUnsigned: true, isBigEndian: true),
                D = d.ToByteArray(isUnsigned: true, isBigEndian: true),
                InverseQ = inverseQ.ToByteArray(isUnsigned: true, isBigEndian: true),
                P = p.ToByteArray(isUnsigned: true, isBigEndian: true),
                Q = q.ToByteArray(isUnsigned: true, isBigEndian: true),
                DP = dp.ToByteArray(isUnsigned: true, isBigEndian: true),
                DQ = dq.ToByteArray(isUnsigned: true, isBigEndian: true)
            };
            RSA? rsa = RSA.Create();
            try
            {
                rsa.ImportParameters(parameters);
                privateKey = new RsaPrivateKey(rsa);
                error = null;
                return true;
            }
            catch (Exception ex)
            {
                error = new FormatException($"The data can not be parsed into an RSA key.", ex);
                rsa?.Dispose();
                return false;
            }
        }
        else
        {
            error = new NotSupportedException($"The key type is unsupported: '{keyType}'.");
            return false;
        }
    }
}

// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Security.Cryptography;

namespace Tmds.Ssh;

public class PrivateKeyCredential : Credential
{
    internal string Identifier { get; }

    private Func<CancellationToken, ValueTask<Key>> LoadKey { get; }

    public PrivateKeyCredential(string path, string? password = null, string? identifier = null) :
        this(path, () => password, identifier)
    { }

    public PrivateKeyCredential(string path, Func<string?> passwordPrompt, string? identifier = null) :
        this(LoadKeyFromFile(path ?? throw new ArgumentNullException(nameof(path)), passwordPrompt), identifier ?? path)
    { }

    // Allows the user to implement derived classes that represent a private key.
    protected PrivateKeyCredential(Func<CancellationToken, ValueTask<Key>> loadKey, string identifier)
    {
        LoadKey = loadKey;
        Identifier = identifier;
    }

    private static Func<CancellationToken, ValueTask<Key>> LoadKeyFromFile(string path, Func<string?> passwordPrompt)
        => (CancellationToken cancellationToken) =>
        {
            if (PrivateKeyParser.TryParsePrivateKeyFile(path, passwordPrompt, out PrivateKey? privateKey, out Exception? error))
            {
                return ValueTask.FromResult(new Key(privateKey));
            }

            if (error is FileNotFoundException or DirectoryNotFoundException)
            {
                return ValueTask.FromResult(default(Key));
            }

            throw error;
        };

    // This is a type we expose to our derive types to avoid having to expose PrivateKey and a bunch of other internals.
    protected readonly struct Key
    {
        internal PrivateKey? PrivateKey { get; }

        public Key(RSA rsa)
        {
            PrivateKey = new RsaPrivateKey(rsa);
        }

        public Key(ECDsa ecdsa)
        {
            ECParameters parameters = ecdsa.ExportParameters(includePrivateParameters: false);
            Oid oid = parameters.Curve.Oid;

            Name algorithm;
            Name curveName;
            HashAlgorithmName hashAlgorithm;
            if (oid.Equals(ECCurve.NamedCurves.nistP256.Oid))
            {
                (algorithm, curveName, hashAlgorithm) = (AlgorithmNames.EcdsaSha2Nistp256, AlgorithmNames.Nistp256, HashAlgorithmName.SHA256);
            }
            else if (oid.Equals(ECCurve.NamedCurves.nistP384.Oid))
            {
                (algorithm, curveName, hashAlgorithm) = (AlgorithmNames.EcdsaSha2Nistp384, AlgorithmNames.Nistp384, HashAlgorithmName.SHA384);
            }
            else if (oid.Equals(ECCurve.NamedCurves.nistP521.Oid))
            {
                (algorithm, curveName, hashAlgorithm) = (AlgorithmNames.EcdsaSha2Nistp521, AlgorithmNames.Nistp521, HashAlgorithmName.SHA512);
            }
            else
            {
                throw new NotSupportedException($"Curve {oid} is not known.");
            }

            PrivateKey = new ECDsaPrivateKey(ecdsa, algorithm, curveName, hashAlgorithm);
        }

        internal Key(PrivateKey key)
        {
            PrivateKey = key;
        }
    }

    internal async ValueTask<PrivateKey?> LoadKeyAsync(CancellationToken cancellationToken)
    {
        Key key = await LoadKey(cancellationToken);
        return key.PrivateKey;
    }
}

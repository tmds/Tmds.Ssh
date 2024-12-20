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

    public PrivateKeyCredential(char[] rawKey, string? password = null, string identifier = "[raw key]") :
        this(rawKey, () => password, identifier)
    { }

    public PrivateKeyCredential(char[] rawKey, Func<string?> passwordPrompt, string identifier = "[raw key]") :
        this(LoadRawKey(ValidateRawKeyArgument(rawKey), passwordPrompt), identifier)
    { }

    // Allows the user to implement derived classes that represent a private key.
    protected PrivateKeyCredential(Func<CancellationToken, ValueTask<Key>> loadKey, string identifier)
    {
        ArgumentNullException.ThrowIfNull(identifier);
        ArgumentNullException.ThrowIfNull(loadKey);

        LoadKey = loadKey;
        Identifier = identifier;
    }

    private static char[] ValidateRawKeyArgument(char[] rawKey)
    {
        ArgumentNullException.ThrowIfNull(rawKey);
        return rawKey;
    }

    private static Func<CancellationToken, ValueTask<Key>> LoadRawKey(char[] rawKey, Func<string?>? passwordPrompt)
        => (CancellationToken cancellationToken) =>
        {
            Key key = new Key(rawKey.AsMemory(), passwordPrompt);

            return ValueTask.FromResult(key);
        };

    private static Func<CancellationToken, ValueTask<Key>> LoadKeyFromFile(string path, Func<string?> passwordPrompt)
        => (CancellationToken cancellationToken) =>
        {
            string rawKey;
            try
            {
                // We read the file so we get UnauthorizedAccessException in case it is not accessible
                rawKey = File.ReadAllText(path);
            }
            catch (Exception e) when (e is FileNotFoundException || e is DirectoryNotFoundException)
            {
                return ValueTask.FromResult(default(Key)); // not found.
            }

            Key key = new Key(rawKey.AsMemory(), passwordPrompt);

            return ValueTask.FromResult(key);
        };

    // This is a type we expose to our derive types to avoid having to expose PrivateKey and a bunch of other internals.
    protected readonly struct Key
    {
        internal PrivateKey? PrivateKey { get; }

        public Key(RSA rsa)
        {
            PrivateKey = new RsaPrivateKey(rsa, sshPublicKey: null);
        }

        public Key(ReadOnlyMemory<char> rawKey, Func<string?>? passwordPrompt = null)
        {
            passwordPrompt ??= delegate { return null; };

            PrivateKey = PrivateKeyParser.ParsePrivateKey(rawKey, passwordPrompt);
        }

        public Key(ECDsa ecdsa)
        {
            ECParameters parameters = ecdsa.ExportParameters(includePrivateParameters: false);
            Oid oid = parameters.Curve.Oid;

            Name algorithm;
            Name curveName;
            HashAlgorithmName hashAlgorithm;
            if (OidEquals(oid, ECCurve.NamedCurves.nistP256.Oid))
            {
                (algorithm, curveName, hashAlgorithm) = (AlgorithmNames.EcdsaSha2Nistp256, AlgorithmNames.Nistp256, HashAlgorithmName.SHA256);
            }
            else if (OidEquals(oid, ECCurve.NamedCurves.nistP384.Oid))
            {
                (algorithm, curveName, hashAlgorithm) = (AlgorithmNames.EcdsaSha2Nistp384, AlgorithmNames.Nistp384, HashAlgorithmName.SHA384);
            }
            else if (OidEquals(oid, ECCurve.NamedCurves.nistP521.Oid))
            {
                (algorithm, curveName, hashAlgorithm) = (AlgorithmNames.EcdsaSha2Nistp521, AlgorithmNames.Nistp521, HashAlgorithmName.SHA512);
            }
            else
            {
                throw new NotSupportedException($"Curve '{oid.FriendlyName ?? oid.Value}' is not known.");
            }

            PrivateKey = new ECDsaPrivateKey(ecdsa, algorithm, curveName, hashAlgorithm, sshPublicKey: null);
        }

        internal Key(PrivateKey key)
        {
            PrivateKey = key;
        }

        private static bool OidEquals(Oid oidA, Oid oidB)
            => oidA.Value is not null && oidB.Value is not null && oidA.Value == oidB.Value;
    }

    internal async ValueTask<PrivateKey?> LoadKeyAsync(CancellationToken cancellationToken)
    {
        Key key = await LoadKey(cancellationToken);
        return key.PrivateKey;
    }
}

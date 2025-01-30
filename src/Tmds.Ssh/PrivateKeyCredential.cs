// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Security.Cryptography;

namespace Tmds.Ssh;

public class PrivateKeyCredential : Credential
{
    internal string Identifier { get; }

    private Func<CancellationToken, ValueTask<Key>> LoadKey { get; }

    public PrivateKeyCredential(string path, string? password = null, string? identifier = null) :
        this(path, () => password, queryKey: false, identifier)
    { }

    public PrivateKeyCredential(string path, Func<string?> passwordPrompt, bool queryKey = true, string? identifier = null) :
        this(LoadKeyFromFile(path ?? throw new ArgumentNullException(nameof(path)), passwordPrompt, queryKey), identifier ?? path)
    { }

    public PrivateKeyCredential(char[] rawKey, string? password = null, string identifier = "[raw key]") :
        this(rawKey, () => password, queryKey: false, identifier)
    { }

    public PrivateKeyCredential(char[] rawKey, Func<string?> passwordPrompt, bool queryKey = true, string identifier = "[raw key]") :
        this(LoadRawKey(ValidateRawKeyArgument(rawKey), passwordPrompt, queryKey), identifier)
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

    private static Func<CancellationToken, ValueTask<Key>> LoadRawKey(char[] rawKey, Func<string?> passwordPrompt, bool queryKey)
        => (CancellationToken cancellationToken) =>
        {
            Key key = new Key(rawKey.AsMemory(), passwordPrompt, queryKey);

            return ValueTask.FromResult(key);
        };

    private static Func<CancellationToken, ValueTask<Key>> LoadKeyFromFile(string path, Func<string?> passwordPrompt, bool queryKey)
        => (CancellationToken cancellationToken) =>
        {
            // Avoid throw when the private key file does not exist/is not accessible.
            if (!File.Exists(path))
            {
                return ValueTask.FromResult(default(Key)); // not found.
            }

            string rawKey;
            try
            {
                rawKey = File.ReadAllText(path);
            }
            catch (Exception e) when (e is FileNotFoundException || e is DirectoryNotFoundException)
            {
                return ValueTask.FromResult(default(Key)); // not found.
            }

            Key key = new Key(rawKey.AsMemory(), passwordPrompt, queryKey);

            return ValueTask.FromResult(key);
        };

    // This is a type we expose to our derive types to avoid having to expose PrivateKey and a bunch of other internals.
    internal protected readonly struct Key : IDisposable
    {
        internal PrivateKey? PrivateKey { get; }

        internal bool QueryKey { get; }

        public Key(RSA rsa)
        {
            PrivateKey = new RsaPrivateKey(rsa, RsaPrivateKey.DeterminePublicSshKey(rsa));
        }

        public Key(ReadOnlyMemory<char> rawKey, string? password = null)
        {
            QueryKey = false;

            PrivateKey = PrivateKeyParser.ParsePrivateKey(rawKey, passwordPrompt: delegate { return password; });
        }

        public Key(ReadOnlyMemory<char> rawKey, Func<string?> passwordPrompt, bool queryKey = true)
        {
            ArgumentNullException.ThrowIfNull(passwordPrompt);

            QueryKey = queryKey;

            PrivateKey = queryKey ? ParsedPrivateKey.Create(rawKey, passwordPrompt) : PrivateKeyParser.ParsePrivateKey(rawKey, passwordPrompt);
        }

        public Key(ECDsa ecdsa)
        {
            ECParameters parameters = ecdsa.ExportParameters(includePrivateParameters: false);
            Oid oid = parameters.Curve.Oid;

            Name keyAlgorithm;
            Name curveName;
            HashAlgorithmName hashAlgorithm;
            if (OidEquals(oid, ECCurve.NamedCurves.nistP256.Oid))
            {
                (keyAlgorithm, curveName, hashAlgorithm) = (AlgorithmNames.EcdsaSha2Nistp256, AlgorithmNames.Nistp256, HashAlgorithmName.SHA256);
            }
            else if (OidEquals(oid, ECCurve.NamedCurves.nistP384.Oid))
            {
                (keyAlgorithm, curveName, hashAlgorithm) = (AlgorithmNames.EcdsaSha2Nistp384, AlgorithmNames.Nistp384, HashAlgorithmName.SHA384);
            }
            else if (OidEquals(oid, ECCurve.NamedCurves.nistP521.Oid))
            {
                (keyAlgorithm, curveName, hashAlgorithm) = (AlgorithmNames.EcdsaSha2Nistp521, AlgorithmNames.Nistp521, HashAlgorithmName.SHA512);
            }
            else
            {
                throw new NotSupportedException($"Curve '{oid.FriendlyName ?? oid.Value}' is not known.");
            }

            PrivateKey = new ECDsaPrivateKey(ecdsa, keyAlgorithm, curveName, hashAlgorithm, ECDsaPrivateKey.DeterminePublicSshKey(ecdsa, keyAlgorithm, curveName));
        }

        internal Key(PrivateKey key)
        {
            PrivateKey = key;
        }

        private static bool OidEquals(Oid oidA, Oid oidB)
            => oidA.Value is not null && oidB.Value is not null && oidA.Value == oidB.Value;

        public void Dispose()
        {
            PrivateKey?.Dispose();
        }
    }

    internal async ValueTask<Key> LoadKeyAsync(CancellationToken cancellationToken)
    {
        return await LoadKey(cancellationToken);
    }

    sealed class ParsedPrivateKey : PrivateKey
    {
        private ReadOnlyMemory<char> _rawKey;
        private Func<string?> _passwordPrompt;

        public static PrivateKey Create(ReadOnlyMemory<char> rawKey, Func<string?> passwordPrompt)
        {
            SshKeyData sshKey = PrivateKeyParser.ParsePublicKey(rawKey);
            Name[] algorithms = AlgorithmNames.GetSignatureAlgorithmsForKeyType(sshKey.Type);
            return new ParsedPrivateKey(algorithms, sshKey, rawKey, passwordPrompt);
        }

        private ParsedPrivateKey(Name[] algorithms, SshKeyData publicKey, ReadOnlyMemory<char> rawKey, Func<string?> passwordPrompt)
            : base(algorithms, publicKey)
        {
            _rawKey = rawKey;
            _passwordPrompt = passwordPrompt;
        }

        public override void Dispose()
        { }

        public override ValueTask<byte[]> SignAsync(Name algorithm, byte[] data, CancellationToken cancellationToken)
        {
            using PrivateKey pk = PrivateKeyParser.ParsePrivateKey(_rawKey, _passwordPrompt);
            return pk.SignAsync(algorithm, data, cancellationToken);
        }
    }
}

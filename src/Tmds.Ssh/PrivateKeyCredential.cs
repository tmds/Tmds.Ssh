// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Security.Cryptography;

namespace Tmds.Ssh;

/// <summary>
/// Credential for private key authentication.
/// </summary>
public class PrivateKeyCredential : Credential
{
    internal string Identifier { get; }

    private Func<CancellationToken, ValueTask<Key>> LoadKey { get; }

    /// <summary>
    /// Creates a private key credential from a file.
    /// </summary>
    /// <param name="path">Path to the private key file.</param>
    /// <param name="password">Password for decrypting the key.</param>
    /// <param name="identifier">Log identifier for the key.</param>
    public PrivateKeyCredential(string path, string? password = null, string? identifier = null) :
        this(path, () => password, queryKey: false, identifier)
    { }

    /// <summary>
    /// Creates a private key credential from a file with password prompt.
    /// </summary>
    /// <param name="path">Path to the private key file.</param>
    /// <param name="passwordPrompt">Callback to prompt for password for decrypting the key.</param>
    /// <param name="queryKey">Whether to check if the server knows the key before prompting for a decryption password.</param>
    /// <param name="identifier">Log identifier for the key.</param>
    public PrivateKeyCredential(string path, Func<string?> passwordPrompt, bool queryKey = true, string? identifier = null) :
        this(LoadKeyFromFile(path ?? throw new ArgumentNullException(nameof(path)), passwordPrompt, queryKey), identifier ?? path)
    { }

    /// <summary>
    /// Creates a private key credential from raw key data.
    /// </summary>
    /// <param name="rawKey">Raw private key data.</param>
    /// <param name="password">Password for decrypting the key.</param>
    /// <param name="identifier">Log identifier for the key.</param>
    public PrivateKeyCredential(char[] rawKey, string? password = null, string identifier = "[raw key]") :
        this(rawKey, () => password, queryKey: false, identifier)
    { }

    /// <summary>
    /// Creates a private key credential from raw key data with password prompt.
    /// </summary>
    /// <param name="rawKey">Raw private key data.</param>
    /// <param name="passwordPrompt">Callback to prompt for password for decrypting the key.</param>
    /// <param name="queryKey">Whether to check if the server knows the key before prompting for a decryption password.</param>
    /// <param name="identifier">Log identifier for the key.</param>
    public PrivateKeyCredential(char[] rawKey, Func<string?> passwordPrompt, bool queryKey = true, string identifier = "[raw key]") :
        this(LoadRawKey(ValidateRawKeyArgument(rawKey), passwordPrompt, queryKey), identifier)
    { }

    /// <summary>
    /// Creates a private key credential with custom key loading logic.
    /// </summary>
    /// <param name="loadKey">Function to load the private key.</param>
    /// <param name="identifier">Log identifier for the key.</param>
    /// <remarks>
    /// This constructor can be used to implement custom key loading, for example to use a private key stored in an Azure Key Vault without exporting the key.
    /// See the <see href="https://github.com/tmds/Tmds.Ssh/tree/main/examples/azure_key">azure_key example</see> for a demonstration.
    /// </remarks>
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

    /// <summary>
    /// Represents a private key.
    /// </summary>
    protected internal readonly struct Key : IDisposable
    {
        internal PrivateKey? PrivateKey { get; }

        internal bool QueryKey { get; }

        /// <summary>
        /// Creates a key from an RSA instance.
        /// </summary>
        /// <param name="rsa">The <see cref="RSA"/> private key.</param>
        public Key(RSA rsa)
        {
            PrivateKey = new RsaPrivateKey(rsa, RsaPrivateKey.DeterminePublicSshKey(rsa));
        }

        /// <summary>
        /// Creates a key from raw key data with password.
        /// </summary>
        /// <param name="rawKey">Raw private key data.</param>
        /// <param name="password">Password for decrypting the key.</param>
        public Key(ReadOnlyMemory<char> rawKey, string? password = null)
        {
            QueryKey = false;

            PrivateKey = PrivateKeyParser.ParsePrivateKey(rawKey, passwordPrompt: delegate { return password; });
        }

        /// <summary>
        /// Creates a key from raw key data with password prompt.
        /// </summary>
        /// <param name="rawKey">Raw private key data.</param>
        /// <param name="passwordPrompt">Callback to prompt for password.</param>
        /// <param name="queryKey">Whether to check if the server knows the key before prompting for a decryption password.</param>
        public Key(ReadOnlyMemory<char> rawKey, Func<string?> passwordPrompt, bool queryKey = true)
        {
            ArgumentNullException.ThrowIfNull(passwordPrompt);

            QueryKey = queryKey;

            PrivateKey = queryKey ? ParsedPrivateKey.Create(rawKey, passwordPrompt) : PrivateKeyParser.ParsePrivateKey(rawKey, passwordPrompt);
        }

        /// <summary>
        /// Creates a key from an ECDSA instance.
        /// </summary>
        /// <param name="ecdsa">The <see cref="ECDsa"/> private key.</param>
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

        /// <summary>
        /// Disposes the private key.
        /// </summary>
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
            (SshKeyData sshKey, _) = PrivateKeyParser.ParsePublicKey(rawKey);
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

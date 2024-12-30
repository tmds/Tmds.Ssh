// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Security.Cryptography;

namespace Tmds.Ssh;

sealed class KeyExchangeAlgorithmFactory
{
    private readonly Dictionary<Name, Func<Name, IKeyExchangeAlgorithm>> _algorithms;

    public static KeyExchangeAlgorithmFactory Default = new KeyExchangeAlgorithmFactory();

    public KeyExchangeAlgorithmFactory()
    {
        _algorithms = new Dictionary<Name, Func<Name, IKeyExchangeAlgorithm>>();
        _algorithms.Add(AlgorithmNames.EcdhSha2Nistp256, name => new ECDHKeyExchange(ECCurve.NamedCurves.nistP256, HashAlgorithmName.SHA256));
        _algorithms.Add(AlgorithmNames.EcdhSha2Nistp384, name => new ECDHKeyExchange(ECCurve.NamedCurves.nistP384, HashAlgorithmName.SHA384));
        _algorithms.Add(AlgorithmNames.EcdhSha2Nistp521, name => new ECDHKeyExchange(ECCurve.NamedCurves.nistP521, HashAlgorithmName.SHA512));
        _algorithms.Add(AlgorithmNames.Curve25519Sha256, name => new Curve25519KeyExchange());
        _algorithms.Add(AlgorithmNames.Curve25519Sha256LibSsh, name => new Curve25519KeyExchange());
        _algorithms.Add(AlgorithmNames.SNtruP761X25519Sha512, name => new SNtruPrime761X25519Sha512KeyExchange());
        _algorithms.Add(AlgorithmNames.SNtruP761X25519Sha512OpenSsh, name => new SNtruPrime761X25519Sha512KeyExchange());
    }

    public IKeyExchangeAlgorithm Create(Name name)
    {
        return _algorithms[name](name);
    }
}

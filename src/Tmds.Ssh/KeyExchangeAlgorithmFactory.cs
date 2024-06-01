// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

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
    }

    public IKeyExchangeAlgorithm Create(Name name)
    {
        return _algorithms[name](name);
    }
}

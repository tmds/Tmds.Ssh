// This file is part of Tmds.Ssh which is released under LGPL-3.0.
// See file LICENSE for full license details.

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Tmds.Ssh
{
    sealed class KeyExchangeAlgorithmFactory
    {
        private readonly Dictionary<Name, Func<Name, IKeyExchangeAlgorithm>> _algorithms;

        public static KeyExchangeAlgorithmFactory Default = new KeyExchangeAlgorithmFactory();

        public KeyExchangeAlgorithmFactory()
        {
            _algorithms = new Dictionary<Name, Func<Name, IKeyExchangeAlgorithm>>();
            _algorithms.Add(AlgorithmNames.EcdhSha2Nistp256, name => new ECDHKeyExchange(name));
        }

        public IKeyExchangeAlgorithm Create(Name name)
        {
            return _algorithms[name](name);
        }
    }
}
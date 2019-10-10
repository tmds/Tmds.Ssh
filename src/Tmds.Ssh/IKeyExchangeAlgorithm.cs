// This file is part of Tmds.Ssh which is released under LGPL-3.0.
// See file LICENSE for full license details.

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Tmds.Ssh
{
    interface IKeyExchangeAlgorithm : IDisposable
    {
        Task<KeyExchangeOutput> TryExchangeAsync(SshConnection connection, KeyExchangeInput input, ILogger logger, CancellationToken ct);
    }
}
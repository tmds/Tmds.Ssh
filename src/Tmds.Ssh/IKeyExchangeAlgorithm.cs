// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using Microsoft.Extensions.Logging;

namespace Tmds.Ssh;

interface IKeyExchangeAlgorithm : IDisposable
{
    Task<KeyExchangeOutput> TryExchangeAsync(KeyExchangeContext context, IHostKeyVerification hostKeyVerification, Packet firstPacket, KeyExchangeInput input, ILogger logger, CancellationToken ct);
}

// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Collections.Generic;

namespace Tmds.Ssh;

sealed class KeyExchangeContext
{
    public required List<Name> KeyExchangeAlgorithms { get; init; }
    public required List<Name> ServerHostKeyAlgorithms { get; init; }
    public required List<Name> EncryptionAlgorithmsClientToServer { get; init; }
    public required List<Name> EncryptionAlgorithmsServerToClient { get; init; }
    public required List<Name> MacAlgorithmsClientToServer { get; init; }
    public required List<Name> MacAlgorithmsServerToClient { get; init; }
    public required List<Name> CompressionAlgorithmsClientToServer { get; init; }
    public required List<Name> CompressionAlgorithmsServerToClient { get; init; }
    public required List<Name> LanguagesClientToServer { get; init; }
    public required List<Name> LanguagesServerToClient { get; init; }
    public required IHostKeyVerification HostKeyVerification { get; init; }
}
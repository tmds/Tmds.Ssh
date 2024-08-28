// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

// POCO input for IKeyExchangeAlgorithm.TryExchangeAsync
sealed class KeyExchangeInput
{
    public KeyExchangeInput(IReadOnlyList<Name> hostKeyAlgorithms,
        ReadOnlyPacket clientKexInitMsg,
        ReadOnlyPacket serverKexInitMsg,
        SshConnectionInfo connectionInfo,
        int initialIVC2SLength,
        int initialIVS2CLength,
        int encryptionKeyC2SLength,
        int encryptionKeyS2CLength,
        int integrityKeyC2SLength,
        int integrityKeyS2CLength,
        int minimumRSAKeySize)
    {
        HostKeyAlgorithms = hostKeyAlgorithms;
        ClientKexInitMsg = clientKexInitMsg;
        ServerKexInitMsg = serverKexInitMsg;
        ConnectionInfo = connectionInfo;
        InitialIVC2SLength = initialIVC2SLength;
        InitialIVS2CLength = initialIVS2CLength;
        EncryptionKeyC2SLength = encryptionKeyC2SLength;
        EncryptionKeyS2CLength = encryptionKeyS2CLength;
        IntegrityKeyC2SLength = integrityKeyC2SLength;
        IntegrityKeyS2CLength = integrityKeyS2CLength;
        MinimumRSAKeySize = minimumRSAKeySize;
    }

    public IReadOnlyList<Name> HostKeyAlgorithms { get; set; }
    public ReadOnlyPacket ClientKexInitMsg { get; set; }
    public ReadOnlyPacket ServerKexInitMsg { get; set; }
    public SshConnectionInfo ConnectionInfo { get; set; }
    public int InitialIVC2SLength { get; set; }
    public int InitialIVS2CLength { get; set; }
    public int EncryptionKeyC2SLength { get; set; }
    public int EncryptionKeyS2CLength { get; set; }
    public int IntegrityKeyC2SLength { get; set; }
    public int IntegrityKeyS2CLength { get; set; }
    public int MinimumRSAKeySize { get; set; }
}

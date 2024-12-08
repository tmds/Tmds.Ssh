// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

sealed class KeyExchangeContext
{
    private readonly SshConnection _connection;
    private readonly SshSession _session;
    private readonly bool _isInitialKex;

    public KeyExchangeContext(SshConnection connection, SshSession session, bool isInitialKex = true)
    {
        _connection = connection;
        _session = session;
        _isInitialKex = isInitialKex;
    }

    public SequencePool SequencePool => _connection.SequencePool;

    public async ValueTask<Packet> ReceivePacketAsync(CancellationToken ct)
    {
        var packet = await _connection.ReceivePacketAsync(ct).ConfigureAwait(false);
        if (packet.IsEmpty)
        {
            ThrowHelper.ThrowProtocolUnexpectedPeerClose();
        }
        return packet;
    }

    public async ValueTask<Packet> ReceivePacketAsync(MessageId expected, CancellationToken ct)
    {
        do
        {
            var packet = await ReceivePacketAsync(ct).ConfigureAwait(false);
            if (CheckPacketForReturn(expected, packet))
            {
                return packet;
            }
        } while (true);
    }

    public ValueTask<Packet> ReceivePacketAsync(MessageId expected, Packet packet, CancellationToken ct)
    {
        if (!packet.IsEmpty)
        {
            if (CheckPacketForReturn(expected, packet))
            {
                return ValueTask.FromResult(packet);
            }
        }

        return ReceivePacketAsync(expected, ct);
    }

    private bool CheckPacketForReturn(MessageId expected, Packet packet)
    {
        MessageId messageId = packet.MessageId!.Value;
        if (messageId == expected)
        {
            return true;
        }
        else if (_isInitialKex)
        {
            // During the initial kex, only permit the strictly required kex packets.
            packet.Dispose();
            ThrowHelper.ThrowProtocolUnexpectedMessageId(messageId);
        }
        else
        {
            // For later kexes, let the session handle the non-kex packets.
            _session.HandleNonKexPacket(messageId, packet);
        }
        return false;
    }

    public ValueTask SendPacketAsync(Packet packet, CancellationToken ct)
        => _connection.SendPacketAsync(packet, ct);

    public void SetEncryptorDecryptor(IPacketEncryptor encryptor, IPacketDecryptor decryptor, bool resetSequenceNumbers)
        => _connection.SetEncryptorDecryptor(encryptor, decryptor, resetSequenceNumbers);

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
    public required int MinimumRSAKeySize { get; init; }

    // Unconditionally enable strict key exchange as described in https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.
    // This mitigates the Terrapin attack (CVE-2023-48795, https://terrapin-attack.com/).
    public bool EnableStrictKex => true;
}
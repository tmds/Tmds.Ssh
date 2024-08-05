// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Linq;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Tmds.Ssh;

internal delegate Task ExchangeKeysAsyncDelegate(SshConnection connection, KeyExchangeContext context, ReadOnlyPacket serverKexInitMsg, ReadOnlyPacket clientKexInitMsg, SshConnectionInfo connectionInfo, ILogger logger, CancellationToken ct);
sealed class KeyExchange
{
    public static readonly ExchangeKeysAsyncDelegate Default = PerformDefaultExchange;

    private async static Task PerformDefaultExchange(SshConnection connection, KeyExchangeContext context, ReadOnlyPacket serverKexInitMsg, ReadOnlyPacket clientKexInitMsg, SshConnectionInfo connectionInfo, ILogger logger, CancellationToken ct)
    {
        // Key Exchange: https://tools.ietf.org/html/rfc4253#section-7.
        SequencePool sequencePool = connection.SequencePool;

        var remoteInit = ParseKeyExchangeInitMessage(serverKexInitMsg);

        // The chosen algorithm MUST be the first algorithm on the client's name-list
        // that is also on the server's name-list.
        Name encC2S = ChooseAlgorithm(context.EncryptionAlgorithmsClientToServer, remoteInit.encryption_algorithms_client_to_server);
        Name encS2C = ChooseAlgorithm(context.EncryptionAlgorithmsServerToClient, remoteInit.encryption_algorithms_server_to_client);
        Name macC2S = ChooseAlgorithm(context.MacAlgorithmsClientToServer, remoteInit.mac_algorithms_client_to_server);
        Name macS2C = ChooseAlgorithm(context.MacAlgorithmsServerToClient, remoteInit.mac_algorithms_server_to_client);
        Name comC2S = ChooseAlgorithm(context.CompressionAlgorithmsClientToServer, remoteInit.compression_algorithms_client_to_server);
        Name comS2C = ChooseAlgorithm(context.CompressionAlgorithmsServerToClient, remoteInit.compression_algorithms_server_to_client);

        if (encC2S.IsEmpty || encS2C.IsEmpty)
        {
            throw new ConnectFailedException(ConnectFailedReason.KeyExchangeFailed, "No common encryption algorithm.", connectionInfo);
        }

        if (comC2S.IsEmpty || comS2C.IsEmpty)
        {
            throw new ConnectFailedException(ConnectFailedReason.KeyExchangeFailed, "No common compression algorithm.", connectionInfo);
        }

        PackingAlgorithms encC2SAlg = PackingAlgorithms.Find(encC2S);
        PackingAlgorithms encS2CAlg = PackingAlgorithms.Find(encS2C);

        if ((!encC2SAlg.IsAuthenticated && macC2S.IsEmpty) ||
            (!encS2CAlg.IsAuthenticated && macS2C.IsEmpty))
        {
            throw new ConnectFailedException(ConnectFailedReason.KeyExchangeFailed, "No common integrity algorithm.", connectionInfo);
        }

        HMacAlgorithm? hmacC2SAlg = encC2SAlg.IsAuthenticated ? null : HMacAlgorithm.Find(macC2S);
        HMacAlgorithm? hmacS2CAlg = encS2CAlg.IsAuthenticated ? null : HMacAlgorithm.Find(macS2C);

        // Remove host key algorithms not supported by the server.
        List<Name> hostKeyAlgorithms = new List<Name>(capacity: context.ServerHostKeyAlgorithms.Count);
        foreach (var hostKeyAlgorithm in context.ServerHostKeyAlgorithms)
        {
            if (remoteInit.server_host_key_algorithms.Contains(hostKeyAlgorithm))
            {
                hostKeyAlgorithms.Add(hostKeyAlgorithm);
            }
        }

        // The first algorithm MUST be the preferred (and guessed) algorithm.  If
        // both sides make the same guess, that algorithm MUST be used.
        Name matchingKex = context.KeyExchangeAlgorithms.Count == 0 ||
                remoteInit.kex_algorithms.Length == 0 ||
                context.KeyExchangeAlgorithms[0] != remoteInit.kex_algorithms[0] ? default(Name) : context.KeyExchangeAlgorithms[0];

        KeyExchangeOutput? keyExchangeOutput = null;
        Packet exchangeInitMsg = default;
        try
        {
            if (remoteInit.first_kex_packet_follows)
            {
                exchangeInitMsg = await connection.ReceivePacketAsync(ct).ConfigureAwait(false);

                if (matchingKex.IsEmpty ||
                    context.ServerHostKeyAlgorithms.Count == 0 ||
                    remoteInit.server_host_key_algorithms.Length == 0 ||
                    context.ServerHostKeyAlgorithms[0] != remoteInit.server_host_key_algorithms[0])
                {
                    // Silently ignore if guessed wrong.
                    exchangeInitMsg.Dispose();
                    exchangeInitMsg = default;
                }
                else
                {
                    // Only accept the first hostKeyAlgorithm.
                    if (hostKeyAlgorithms.Count > 1)
                    {
                        hostKeyAlgorithms.RemoveRange(1, hostKeyAlgorithms.Count - 1);
                    }
                }
            }

            encC2SAlg = PackingAlgorithms.Find(encC2S);
            hmacC2SAlg = encC2SAlg.IsAuthenticated ? null : HMacAlgorithm.Find(macC2S);
            encS2CAlg = PackingAlgorithms.Find(encS2C);
            hmacS2CAlg = encS2CAlg.IsAuthenticated ? null : HMacAlgorithm.Find(macS2C);

            var keyExchangeInput = new KeyExchangeInput(hostKeyAlgorithms, exchangeInitMsg, clientKexInitMsg, serverKexInitMsg, connectionInfo,
                encC2SAlg.IVLength, encS2CAlg.IVLength, encC2SAlg.KeyLength, encS2CAlg.KeyLength, hmacC2SAlg?.KeyLength ?? 0, hmacS2CAlg?.KeyLength ?? 0,
                context.MinimumRSAKeySize);

            foreach (var keyAlgorithm in context.KeyExchangeAlgorithms)
            {
                if (remoteInit.kex_algorithms.Contains(keyAlgorithm))
                {
                    logger.KeyExchangeAlgorithm(keyAlgorithm);

                    using (var algorithm = KeyExchangeAlgorithmFactory.Default.Create(keyAlgorithm))
                    {
                        keyExchangeOutput = await algorithm.TryExchangeAsync(connection, context.HostKeyVerification, keyExchangeInput, logger, ct).ConfigureAwait(false);
                    }
                    if (keyExchangeOutput != null)
                    {
                        connectionInfo.SessionId ??= keyExchangeOutput.ExchangeHash;
                        break;
                    }

                    // Preferred algorithm must be used.
                    if (!matchingKex.IsEmpty)
                    {
                        throw new ConnectFailedException(ConnectFailedReason.KeyExchangeFailed, "Preferred key exchange algorithm failed.", connectionInfo);
                    }
                }
            }

            // If no algorithm satisfying all these conditions can be found, the
            // connection fails, and both sides MUST disconnect.
            if (keyExchangeOutput == null)
            {
                throw new ConnectFailedException(ConnectFailedReason.KeyExchangeFailed, "Key exchange failed.", connectionInfo);
            }
        }
        finally
        {
            exchangeInitMsg.Dispose();
        }

        logger.AlgorithmsServerToClient(encS2C, macS2C, comS2C);
        logger.AlgorithmsClientToServer(encC2S, macC2S, comC2S);

        // Send SSH_MSG_NEWKEYS.
        await connection.SendPacketAsync(CreateNewKeysMessage(sequencePool), ct).ConfigureAwait(false);

        // Receive SSH_MSG_NEWKEYS.
        using Packet newKeysReceivedMsg = await connection.ReceivePacketAsync(ct).ConfigureAwait(false);
        ParseNewKeysMessage(newKeysReceivedMsg);

        IPacketEncoder packetEncoder = encC2SAlg.CreatePacketEncoder(keyExchangeOutput.EncryptionKeyC2S, keyExchangeOutput.InitialIVC2S, hmacC2SAlg, keyExchangeOutput.IntegrityKeyC2S);
        IPacketDecoder packetDecoder = encS2CAlg.CreatePacketDecoder(sequencePool, keyExchangeOutput.EncryptionKeyS2C, keyExchangeOutput.InitialIVS2C, hmacS2CAlg, keyExchangeOutput.IntegrityKeyS2C);

        connection.SetEncoderDecoder(packetEncoder, packetDecoder);

        static Name ChooseAlgorithm(List<Name> localList, Name[] remoteList)
        {
            for (int i = 0; i < localList.Count; i++)
            {
                if (remoteList.Contains(localList[i]))
                {
                    return localList[i];
                }
            }
            return default;
        }
    }

    /*
        byte         SSH_MSG_KEXINIT
        byte[16]     cookie (random bytes)
        name-list    kex_algorithms
        name-list    server_host_key_algorithms
        name-list    encryption_algorithms_client_to_server
        name-list    encryption_algorithms_server_to_client
        name-list    mac_algorithms_client_to_server
        name-list    mac_algorithms_server_to_client
        name-list    compression_algorithms_client_to_server
        name-list    compression_algorithms_server_to_client
        name-list    languages_client_to_server
        name-list    languages_server_to_client
        boolean      first_kex_packet_follows
        uint32       0 (reserved for future extension)
    */

    private static (
        Name[] kex_algorithms,
        Name[] server_host_key_algorithms,
        Name[] encryption_algorithms_client_to_server,
        Name[] encryption_algorithms_server_to_client,
        Name[] mac_algorithms_client_to_server,
        Name[] mac_algorithms_server_to_client,
        Name[] compression_algorithms_client_to_server,
        Name[] compression_algorithms_server_to_client,
        Name[] languages_client_to_server,
        Name[] languages_server_to_client,
        bool first_kex_packet_follows)
        ParseKeyExchangeInitMessage(ReadOnlyPacket packet)
    {
        var reader = packet.GetReader();
        reader.ReadMessageId(MessageId.SSH_MSG_KEXINIT);
        reader.Skip(16);
        Name[] kex_algorithms = reader.ReadNameList();
        Name[] server_host_key_algorithms = reader.ReadNameList();
        Name[] encryption_algorithms_client_to_server = reader.ReadNameList();
        Name[] encryption_algorithms_server_to_client = reader.ReadNameList();
        Name[] mac_algorithms_client_to_server = reader.ReadNameList();
        Name[] mac_algorithms_server_to_client = reader.ReadNameList();
        Name[] compression_algorithms_client_to_server = reader.ReadNameList();
        Name[] compression_algorithms_server_to_client = reader.ReadNameList();
        Name[] languages_client_to_server = reader.ReadNameList();
        Name[] languages_server_to_client = reader.ReadNameList();
        bool first_kex_packet_follows = reader.ReadBoolean();
        reader.ReadUInt32(0);
        reader.ReadEnd();
        return (
            kex_algorithms,
            server_host_key_algorithms,
            encryption_algorithms_client_to_server,
            encryption_algorithms_server_to_client,
            mac_algorithms_client_to_server,
            mac_algorithms_server_to_client,
            compression_algorithms_client_to_server,
            compression_algorithms_server_to_client,
            languages_client_to_server,
            languages_server_to_client,
            first_kex_packet_follows);
    }

    private static Packet CreateNewKeysMessage(SequencePool sequencePool)
    {
        using var packet = sequencePool.RentPacket();
        var writer = packet.GetWriter();
        writer.WriteMessageId(MessageId.SSH_MSG_NEWKEYS);
        return packet.Move();
    }

    private static void ParseNewKeysMessage(ReadOnlyPacket packet)
    {
        var reader = packet.GetReader();
        reader.ReadMessageId(MessageId.SSH_MSG_NEWKEYS);
        reader.ReadEnd();
    }
}

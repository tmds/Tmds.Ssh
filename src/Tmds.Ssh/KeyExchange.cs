// This file is part of Tmds.Ssh which is released under LGPL-3.0.
// See file LICENSE for full license details.

using System;
using System.Linq;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Tmds.Ssh
{
    internal delegate Task ExchangeKeysAsyncDelegate(SshConnection connection, Packet clientKexInitMsg, Packet serverKexInitMsg, ILogger logger, SshClientSettings settings, SshConnectionInfo connectionInfo, CancellationToken ct);
    sealed class KeyExchange
    {
        public static readonly ExchangeKeysAsyncDelegate Default = PerformDefaultExchange;

        private async static Task PerformDefaultExchange(SshConnection connection, Packet clientKexInitMsg, Packet serverKexInitMsg, ILogger logger, SshClientSettings settings, SshConnectionInfo connectionInfo, CancellationToken ct)
        {
            // Key Exchange: https://tools.ietf.org/html/rfc4253#section-7.
            SequencePool sequencePool = connection.SequencePool;

            var remoteInit = ParseKeyExchangeInitMessage(serverKexInitMsg);

            // The chosen algorithm MUST be the first algorithm on the client's name-list
            // that is also on the server's name-list.
            Name encC2S = ChooseAlgorithm(settings.EncryptionAlgorithmsClientToServer, remoteInit.encryption_algorithms_client_to_server);
            Name encS2C = ChooseAlgorithm(settings.EncryptionAlgorithmsServerToClient, remoteInit.encryption_algorithms_server_to_client);
            Name macC2S = ChooseAlgorithm(settings.MacAlgorithmsClientToServer, remoteInit.mac_algorithms_client_to_server);
            Name macS2C = ChooseAlgorithm(settings.MacAlgorithmsServerToClient, remoteInit.mac_algorithms_server_to_client);
            Name comC2S = ChooseAlgorithm(settings.CompressionAlgorithmsClientToServer, remoteInit.compression_algorithms_client_to_server);
            Name comS2C = ChooseAlgorithm(settings.CompressionAlgorithmsServerToClient, remoteInit.compression_algorithms_server_to_client);

            if (encC2S.IsEmpty || encS2C.IsEmpty || macC2S.IsEmpty || macS2C.IsEmpty || comC2S.IsEmpty || comS2C.IsEmpty)
            {
                ThrowHelper.ThrowKeyExchangeFailed("No common encryption/integrity/compression algorithm.");
            }

            // Make an ordered list of host key algorithms. The key exchange algorithm will pick a compatible one.
            List<Name> hostKeyAlgorithms = new List<Name>(capacity: settings.ServerHostKeyAlgorithms.Count);
            foreach (var hostKeyAlgorithm in settings.ServerHostKeyAlgorithms)
            {
                if (remoteInit.server_host_key_algorithms.Contains(hostKeyAlgorithm))
                {
                    hostKeyAlgorithms.Add(hostKeyAlgorithm);
                }
            }

            // The first algorithm MUST be the preferred (and guessed) algorithm.  If
            // both sides make the same guess, that algorithm MUST be used.
            Name matchingKex = settings.KeyExchangeAlgorithms.Count == 0 ||
                    remoteInit.kex_algorithms.Length == 0 ||
                    settings.KeyExchangeAlgorithms[0] != remoteInit.kex_algorithms[0] ? default(Name) : settings.KeyExchangeAlgorithms[0];

            KeyExchangeOutput? keyExchangeOutput = null;
            Packet exchangeInitMsg = default;
            try
            {
                if (remoteInit.first_kex_packet_follows)
                {
                    exchangeInitMsg = await connection.ReceivePacketAsync(ct);

                    if (matchingKex.IsEmpty ||
                        settings.ServerHostKeyAlgorithms.Count == 0 ||
                        remoteInit.server_host_key_algorithms.Length == 0 ||
                        settings.ServerHostKeyAlgorithms[0] != remoteInit.server_host_key_algorithms[0])
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

                EncryptionFactory.Default.GetKeyAndIVLength(encC2S, out int encryptionKeyC2SLength, out int initialIVC2SLength);
                EncryptionFactory.Default.GetKeyAndIVLength(encS2C, out int encryptionKeyS2CLength, out int initialIVS2CLength);
                int integrityKeyC2SLength = HMacFactory.Default.GetKeyLength(macC2S);
                int integrityKeyS2CLength = HMacFactory.Default.GetKeyLength(macS2C);

                var keyExchangeInput = new KeyExchangeInput(hostKeyAlgorithms, exchangeInitMsg, clientKexInitMsg, serverKexInitMsg, connectionInfo,
                    initialIVC2SLength, initialIVS2CLength, encryptionKeyC2SLength, encryptionKeyS2CLength, integrityKeyC2SLength, integrityKeyS2CLength);

                foreach (var keyAlgorithm in settings.KeyExchangeAlgorithms)
                {
                    if (remoteInit.kex_algorithms.Contains(keyAlgorithm))
                    {
                        logger.KeyExchangeAlgorithm(keyAlgorithm);

                        using (var algorithm = KeyExchangeAlgorithmFactory.Default.Create(keyAlgorithm))
                        {
                            keyExchangeOutput = await algorithm.TryExchangeAsync(connection, keyExchangeInput, logger, ct);
                        }
                        if (keyExchangeOutput != null)
                        {
                            connectionInfo.SessionId ??= keyExchangeOutput.ExchangeHash;
                            break;
                        }

                        // Preferred algorithm must be used.
                        if (!matchingKex.IsEmpty)
                        {
                            ThrowHelper.ThrowKeyExchangeFailed("Preferred key exchange algorithm failed.");
                        }
                    }
                }

                // If no algorithm satisfying all these conditions can be found, the
                // connection fails, and both sides MUST disconnect.
                if (keyExchangeOutput == null)
                {
                    ThrowHelper.ThrowKeyExchangeFailed("Key exchange failed");
                }
            }
            finally
            {
                exchangeInitMsg.Dispose();
            }

            logger.AlgorithmsServerToClient(encS2C, macS2C, comS2C);
            logger.AlgorithmsClientToServer(encC2S, macC2S, comC2S);

            // Send SSH_MSG_NEWKEYS.
            {
                using Packet newKeysMsg = CreateNewKeysMessage(sequencePool);
                await connection.SendPacketAsync(newKeysMsg, ct);
            }

            // Receive SSH_MSG_NEWKEYS.
            using Packet newKeysReceivedMsg = await connection.ReceivePacketAsync(ct);
            ParseNewKeysMessage(newKeysReceivedMsg);

            var encrypt = EncryptionFactory.Default.CreateEncryptor(encC2S, keyExchangeOutput.EncryptionKeyC2S, keyExchangeOutput.InitialIVC2S);
            var macForEncoder = HMacFactory.Default.Create(macC2S, keyExchangeOutput.IntegrityKeyC2S);
            var decrypt = EncryptionFactory.Default.CreateDecryptor(encS2C, keyExchangeOutput.EncryptionKeyS2C, keyExchangeOutput.InitialIVS2C);
            var macForDecoder = HMacFactory.Default.Create(macS2C, keyExchangeOutput.IntegrityKeyS2C);

            connection.SetEncoderDecoder(new PacketEncoder(encrypt, macForEncoder), new PacketDecoder(sequencePool, decrypt, macForDecoder));

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
            ParseKeyExchangeInitMessage(Packet packet)
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

        public static Packet CreateKeyExchangeInitMessage(SequencePool sequencePool, ILogger logger, SshClientSettings settings)
        {
            using var packet = sequencePool.RentPacket();
            var writer = packet.GetWriter();
            writer.WriteMessageId(MessageId.SSH_MSG_KEXINIT);
            writer.WriteRandomBytes(16);
            writer.WriteNameList(settings.KeyExchangeAlgorithms);
            writer.WriteNameList(settings.ServerHostKeyAlgorithms);
            writer.WriteNameList(settings.EncryptionAlgorithmsClientToServer);
            writer.WriteNameList(settings.EncryptionAlgorithmsServerToClient);
            writer.WriteNameList(settings.MacAlgorithmsClientToServer);
            writer.WriteNameList(settings.MacAlgorithmsServerToClient);
            writer.WriteNameList(settings.CompressionAlgorithmsClientToServer);
            writer.WriteNameList(settings.CompressionAlgorithmsServerToClient);
            writer.WriteNameList(settings.LanguagesClientToServer);
            writer.WriteNameList(settings.LanguagesServerToClient);
            writer.WriteBoolean(false);
            writer.WriteUInt32(0);
            return packet.Move();
        }

        private static Packet CreateNewKeysMessage(SequencePool sequencePool)
        {
            using var packet = sequencePool.RentPacket();
            var writer = packet.GetWriter();
            writer.WriteMessageId(MessageId.SSH_MSG_NEWKEYS);
            return packet.Move();
        }

        private static void ParseNewKeysMessage(Packet packet)
        {
            var reader = packet.GetReader();
            reader.ReadMessageId(MessageId.SSH_MSG_NEWKEYS);
            reader.ReadEnd();
        }
    }
}
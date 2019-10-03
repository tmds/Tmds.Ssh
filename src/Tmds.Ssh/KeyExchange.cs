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
    internal delegate Task ExchangeKeysAsyncDelegate(SshConnection connection, Sequence clientKexInitMsg, Sequence serverKexInitMsg, ILogger logger, SshClientSettings settings, SshConnectionInfo connectionInfo, CancellationToken ct);
    sealed class KeyExchange
    {
        public static readonly ExchangeKeysAsyncDelegate Default = PerformDefaultExchange;

        private async static Task PerformDefaultExchange(SshConnection connection, Sequence clientKexInitMsg, Sequence serverKexInitMsg, ILogger logger, SshClientSettings settings, SshConnectionInfo connectionInfo, CancellationToken ct)
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

            Sequence? exchangeInitMsg = null;
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
                        exchangeInitMsg?.Dispose();
                        exchangeInitMsg = null;
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

                KeyExchangeOutput? keyExchangeOutput = null;
                foreach (var keyAlgorithm in settings.KeyExchangeAlgorithms)
                {
                    if (remoteInit.kex_algorithms.Contains(keyAlgorithm))
                    {
                        using (var algorithm = KeyExchangeAlgorithmFactory.Default.Create(keyAlgorithm))
                        {
                            keyExchangeOutput = await algorithm.TryExchangeAsync(hostKeyAlgorithms, exchangeInitMsg, clientKexInitMsg, serverKexInitMsg, connection, connectionInfo, logger, ct);
                        }
                        if (keyExchangeOutput != null)
                        {
                            connectionInfo.SessionId = keyExchangeOutput.ExchangeHash;
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
                exchangeInitMsg?.Dispose();
            }

            // Send SSH_MSG_NEWKEYS.
            using Sequence newKeysMsg = CreateNewKeysMessage(sequencePool);
            await connection.SendPacketAsync(newKeysMsg.AsReadOnlySequence(), ct);

            // Receive SSH_MSG_NEWKEYS.
            using Sequence? newKeysReceivedMsg = await connection.ReceivePacketAsync(ct);
            if (newKeysReceivedMsg == null)
            {
                ThrowHelper.ThrowProtocolUnexpectedPeerClose();
            }
            ParseNewKeysMessage(newKeysReceivedMsg);

            // TODO:connection.SetEncoderDecoder(.., ..);
            throw new NotImplementedException();

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
            ParseKeyExchangeInitMessage(Sequence packet)
        {
            var reader = new SequenceReader(packet);
            reader.ReadByte(MessageNumber.SSH_MSG_KEXINIT);
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

        public static Sequence CreateKeyExchangeInitMessage(SequencePool sequencePool, ILogger logger, SshClientSettings settings)
        {
            using var writer = new SequenceWriter(sequencePool);
            writer.WriteByte(MessageNumber.SSH_MSG_KEXINIT);
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
            return writer.BuildSequence();
        }

        private static Sequence CreateNewKeysMessage(SequencePool sequencePool)
        {
            using var writer = new SequenceWriter(sequencePool);
            writer.WriteByte(MessageNumber.SSH_MSG_NEWKEYS);
            return writer.BuildSequence();
        }

        private static void ParseNewKeysMessage(Sequence packet)
        {
            var reader = new SequenceReader(packet);
            reader.ReadByte(MessageNumber.SSH_MSG_NEWKEYS);
            reader.ReadEnd();
        }
    }
}
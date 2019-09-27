// This file is part of Tmds.Ssh which is released under LGPL-3.0.
// See file LICENSE for full license details.

using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Tmds.Ssh
{
    internal delegate Task ExchangeKeysAsyncDelegate(SshConnection sshConnection, Sequence remoteInitPacket, ILogger logger, SshClientSettings settings, CancellationToken token);
    sealed class KeyExchange
    {
        public static readonly ExchangeKeysAsyncDelegate Default = PerformDefaultExchange;

        private static Task PerformDefaultExchange(SshConnection sshConnection, Sequence remoteInitPacket, ILogger logger, SshClientSettings settings, CancellationToken token)
        {
            // Key Exchange: https://tools.ietf.org/html/rfc4253#section-7.

            var remoteInit = ParseKeyExchangeInitMessage(remoteInitPacket);

            // Configure sshConnection for encryption.
            return Task.CompletedTask;
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
            string[] kex_algorithms,
            string[] server_host_key_algorithms,
            string[] encryption_algorithms_client_to_server,
            string[] encryption_algorithms_server_to_client,
            string[] mac_algorithms_client_to_server,
            string[] mac_algorithms_server_to_client,
            string[] compression_algorithms_client_to_server,
            string[] compression_algorithms_server_to_client,
            string[] languages_client_to_server,
            string[] languages_server_to_client,
            bool first_kex_packet_follows)
            ParseKeyExchangeInitMessage(Sequence packet)
        {
            var reader = new SequenceReader(packet);
            reader.ReadByte(MessageNumber.SSH_MSG_KEXINIT);
            reader.Skip(16);
            string[] kex_algorithms = reader.ReadNameList();
            string[] server_host_key_algorithms = reader.ReadNameList();
            string[] encryption_algorithms_client_to_server = reader.ReadNameList();
            string[] encryption_algorithms_server_to_client = reader.ReadNameList();
            string[] mac_algorithms_client_to_server = reader.ReadNameList();
            string[] mac_algorithms_server_to_client = reader.ReadNameList();
            string[] compression_algorithms_client_to_server = reader.ReadNameList();
            string[] compression_algorithms_server_to_client = reader.ReadNameList();
            string[] languages_client_to_server = reader.ReadNameList();
            string[] languages_server_to_client = reader.ReadNameList();
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
            writer.WriteNameList(settings.KeyAlgorithms);
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
    }
}
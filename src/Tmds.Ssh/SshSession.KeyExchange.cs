// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Diagnostics;

namespace Tmds.Ssh;

sealed partial class SshSession
{
    private async Task PerformKeyExchangeAsync(KeyExchangeContext context, ReadOnlyPacket serverKexInitMsg, ReadOnlyPacket clientKexInitMsg, CancellationToken ct)
    {
        // Key Exchange: https://tools.ietf.org/html/rfc4253#section-7.
        SequencePool sequencePool = context.SequencePool;

        // This throws when serverKexInitMsg is not SSH2_MSG_KEXINIT which is required for strict kex.
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
            throw new ConnectFailedException(ConnectFailedReason.KeyExchangeFailed, "No common encryption algorithm.", ConnectionInfo);
        }

        if (comC2S.IsEmpty || comS2C.IsEmpty)
        {
            throw new ConnectFailedException(ConnectFailedReason.KeyExchangeFailed, "No common compression algorithm.", ConnectionInfo);
        }

        var encC2SAlg = PacketEncryptionAlgorithm.Find(encC2S);
        var encS2CAlg = PacketEncryptionAlgorithm.Find(encS2C);

        if ((!encC2SAlg.IsAuthenticated && macC2S.IsEmpty) ||
            (!encS2CAlg.IsAuthenticated && macS2C.IsEmpty))
        {
            throw new ConnectFailedException(ConnectFailedReason.KeyExchangeFailed, "No common integrity algorithm.", ConnectionInfo);
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

        List<Name> kexAlgorithms;
        if (matchingKex.IsEmpty)
        {
            kexAlgorithms = new List<Name>(capacity: context.KeyExchangeAlgorithms.Count);
            foreach (var keyAlgorithm in context.KeyExchangeAlgorithms)
            {
                if (remoteInit.kex_algorithms.Contains(keyAlgorithm))
                {
                    kexAlgorithms.Add(keyAlgorithm);
                }
            }
        }
        else
        {
            kexAlgorithms = [ matchingKex ];
        }

        KeyExchangeOutput? keyExchangeOutput = null;
        Packet firstPacket = default;
        try
        {
            if (remoteInit.first_kex_packet_follows)
            {
                // guess is accepted when both the kex algorithm and host key algorithm match.
                firstPacket = await context.ReceivePacketAsync(ct).ConfigureAwait(false);

                if (matchingKex.IsEmpty ||
                    context.ServerHostKeyAlgorithms.Count == 0 ||
                    remoteInit.server_host_key_algorithms.Length == 0 ||
                    context.ServerHostKeyAlgorithms[0] != remoteInit.server_host_key_algorithms[0])
                {
                    // Silently ignore if guessed wrong.
                    firstPacket.Dispose();
                    firstPacket = default;
                }
                else
                {
                    // Only accept the matched hostKeyAlgorithm.
                    if (hostKeyAlgorithms.Count > 1)
                    {
                        hostKeyAlgorithms.RemoveRange(1, hostKeyAlgorithms.Count - 1);
                    }
                }
            }

            Logger.KexAlgorithms(kexAlgorithms, hostKeyAlgorithms,
                encC2S, encS2C, macC2S, macS2C, comC2S, comS2C);

            var keyExchangeInput = new KeyExchangeInput(hostKeyAlgorithms, clientKexInitMsg, serverKexInitMsg, ConnectionInfo,
                encC2SAlg.IVLength, encS2CAlg.IVLength, encC2SAlg.KeyLength, encS2CAlg.KeyLength, hmacC2SAlg?.KeyLength ?? 0, hmacS2CAlg?.KeyLength ?? 0,
                context.MinimumRSAKeySize);

            foreach (var keyAlgorithm in kexAlgorithms)
            {
                Logger.ExchangingKeys(keyAlgorithm);

                using (var algorithm = KeyExchangeAlgorithmFactory.Default.Create(keyAlgorithm))
                {
                    keyExchangeOutput = await algorithm.TryExchangeAsync(context, context.HostKeyVerification, firstPacket.Move(), keyExchangeInput, Logger, ct).ConfigureAwait(false);
                }
                if (keyExchangeOutput != null)
                {
                    Logger.KeyExchangeCompleted();

                    ConnectionInfo.SessionId ??= keyExchangeOutput.ExchangeHash;
                    break;
                }
            }

            // If no algorithm satisfying all these conditions can be found, the
            // connection fails, and both sides MUST disconnect.
            if (keyExchangeOutput == null)
            {
                throw new ConnectFailedException(ConnectFailedReason.KeyExchangeFailed, "Key exchange failed.", ConnectionInfo);
            }
        }
        finally
        {
            firstPacket.Dispose();
        }

        // Send SSH_MSG_NEWKEYS.
        await context.SendPacketAsync(CreateNewKeysMessage(sequencePool), ct).ConfigureAwait(false);

        // Receive SSH_MSG_NEWKEYS.
        using Packet newKeysReceivedMsg = await context.ReceivePacketAsync(MessageId.SSH_MSG_NEWKEYS, ct).ConfigureAwait(false);
        ParseNewKeysMessage(newKeysReceivedMsg);

        IPacketEncryptor encryptor = encC2SAlg.CreatePacketEncryptor(keyExchangeOutput.EncryptionKeyC2S, keyExchangeOutput.InitialIVC2S, hmacC2SAlg, keyExchangeOutput.IntegrityKeyC2S);
        IPacketDecryptor decryptor = encS2CAlg.CreatePacketDecryptor(sequencePool, keyExchangeOutput.EncryptionKeyS2C, keyExchangeOutput.InitialIVS2C, hmacS2CAlg, keyExchangeOutput.IntegrityKeyS2C);

        if (context.EnableStrictKex && !ConnectionInfo.UseStrictKex)
        {
            ConnectionInfo.UseStrictKex = remoteInit.kex_algorithms.Contains(AlgorithmNames.ServerStrictKex);
        }
        context.SetEncryptorDecryptor(encryptor, decryptor, resetSequenceNumbers: ConnectionInfo.UseStrictKex);

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

    private (
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

        Logger.ServerKexInit(
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
            first_kex_packet_follows
        );

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

    private KeyExchangeContext CreateKeyExchangeContext(SshConnection connection, bool isInitialKex = true)
    {
        Debug.Assert(_settings is not null);

        TrustedHostKeys trustedKeys = GetKnownHostKeys();

        // Sort algorithms to prefer those we have keys for.
        List<Name> serverHostKeyAlgorithms = new List<Name>(_settings.ServerHostKeyAlgorithms);
        trustedKeys.SortAlgorithms(serverHostKeyAlgorithms);

        // TODO: remove old keys from KnownHostsFilePaths?
        // Add keys to first KnownHostsFilePaths.
        IReadOnlyList<string> userKnownHostsFilePaths = _settings.UserKnownHostsFilePathsOrDefault;
        string? updateKnownHostsFile = _settings.UpdateKnownHostsFileAfterAuthentication && userKnownHostsFilePaths.Count > 0 ? userKnownHostsFilePaths[0] : null;
        IHostKeyVerification hostKeyVerification = new HostKeyVerification(trustedKeys, _settings.HostAuthentication, updateKnownHostsFile, _settings.HashKnownHosts, Logger);

        return new KeyExchangeContext(connection, this, isInitialKex)
        {
            KeyExchangeAlgorithms = _settings.KeyExchangeAlgorithms,
            ServerHostKeyAlgorithms = serverHostKeyAlgorithms,
            EncryptionAlgorithmsClientToServer = _settings.EncryptionAlgorithmsClientToServer,
            EncryptionAlgorithmsServerToClient = _settings.EncryptionAlgorithmsServerToClient,
            MacAlgorithmsClientToServer = _settings.MacAlgorithmsClientToServer,
            MacAlgorithmsServerToClient = _settings.MacAlgorithmsServerToClient,
            CompressionAlgorithmsClientToServer = _settings.CompressionAlgorithmsClientToServer,
            CompressionAlgorithmsServerToClient = _settings.CompressionAlgorithmsServerToClient,
            LanguagesClientToServer = _settings.LanguagesClientToServer,
            LanguagesServerToClient = _settings.LanguagesServerToClient,
            HostKeyVerification = hostKeyVerification,
            MinimumRSAKeySize = _settings.MinimumRSAKeySize
        };
    }

    private TrustedHostKeys GetKnownHostKeys()
    {
        Debug.Assert(_settings is not null);

        string? ip = ConnectionInfo.IPAddress?.ToString();

        IEnumerable<string> knownHostsFiles = _settings.GlobalKnownHostsFilePathsOrDefault.Concat(_settings.UserKnownHostsFilePathsOrDefault);

        TrustedHostKeys knownHostsKeys = new();

        foreach (var knownHostFile in knownHostsFiles)
        {
            KnownHostsFile.AddHostKeysFromFile(knownHostFile, knownHostsKeys, ConnectionInfo.HostName, ip, ConnectionInfo.Port, Logger);
        }

        return knownHostsKeys;
    }

    private Packet CreateKeyExchangeInitMessage(KeyExchangeContext context)
    {
        List<Name> kexAlgorithms = context.KeyExchangeAlgorithms;
        if (context.EnableStrictKex)
        {
            kexAlgorithms = [..kexAlgorithms, AlgorithmNames.ClientStrictKex];
        }
        using var packet = _sequencePool.RentPacket();
        var writer = packet.GetWriter();
        writer.WriteMessageId(MessageId.SSH_MSG_KEXINIT);
        writer.WriteRandomBytes(16);
        writer.WriteNameList(kexAlgorithms);
        writer.WriteNameList(context.ServerHostKeyAlgorithms);
        writer.WriteNameList(context.EncryptionAlgorithmsClientToServer);
        writer.WriteNameList(context.EncryptionAlgorithmsServerToClient);
        writer.WriteNameList(context.MacAlgorithmsClientToServer);
        writer.WriteNameList(context.MacAlgorithmsServerToClient);
        writer.WriteNameList(context.CompressionAlgorithmsClientToServer);
        writer.WriteNameList(context.CompressionAlgorithmsServerToClient);
        writer.WriteNameList(context.LanguagesClientToServer);
        writer.WriteNameList(context.LanguagesServerToClient);
        writer.WriteBoolean(false);
        writer.WriteUInt32(0);

        Logger.ClientKexInit(
            kexAlgorithms,
            context.ServerHostKeyAlgorithms,
            context.EncryptionAlgorithmsClientToServer,
            context.EncryptionAlgorithmsServerToClient,
            context.MacAlgorithmsClientToServer,
            context.MacAlgorithmsServerToClient,
            context.CompressionAlgorithmsClientToServer,
            context.CompressionAlgorithmsServerToClient,
            context.LanguagesClientToServer,
            context.LanguagesServerToClient
        );

        return packet.Move();
    }
}

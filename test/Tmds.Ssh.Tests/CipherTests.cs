using System;
using Xunit;

using System.Threading.Tasks;
using System.Linq;
using System.Collections.Generic;

namespace Tmds.Ssh.Tests;

[Collection(nameof(SshServerCollection))]
public class CipherTests
{
    private readonly SshServer _sshServer;

    public CipherTests(SshServer sshServer)
    {
        _sshServer = sshServer;
    }

    [Theory]
    [MemberData(nameof(Ciphers))]
    public async Task ConnectWithDecryptionCipher(string cipher)
    {
        using var _ = await _sshServer.CreateClientAsync(SetDecryptionCipher(new Name(cipher)));
    }

    [Theory]
    [MemberData(nameof(Ciphers))]
    public async Task ConnectWithEncryptionCipher(string cipher)
    {
        using var _ = await _sshServer.CreateClientAsync(SetDecryptionCipher(new Name(cipher)));
    }

    public static IEnumerable<object[]> Ciphers()
        => SshClientSettings.SupportedEncryptionAlgorithms.Select(name => new [] { name.ToString() });

    private Action<SshClientSettings> SetEncryptionCipher(Name cipher)
        => (SshClientSettings settings) => { settings.EncryptionAlgorithmsClientToServer = [ cipher ]; };

    private Action<SshClientSettings> SetDecryptionCipher(Name cipher)
        => (SshClientSettings settings) => { settings.EncryptionAlgorithmsServerToClient = [ cipher ]; };
}

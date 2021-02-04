using System;
using Xunit;

namespace Tmds.Ssh.Tests
{
    [Collection(nameof(SshServerCollection))]
    public class UnitTest1
    {
        private readonly SshServer _sshServer;

        public UnitTest1(SshServer sshServer)
        {
            _sshServer = sshServer;
        }

        [Fact]
        public void Test1()
        { }
    }
}

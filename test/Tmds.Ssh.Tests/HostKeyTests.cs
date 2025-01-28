using Xunit;

namespace Tmds.Ssh.Managed.Tests;

public class HostKeyTests
{
    [Fact]
    public void CertificateInfo()
    {
        // ssh-keygen -h -s id_ca -I "Cert Identity" -n "server.example.com,hostname" -O extension:ext1 -O extension:ext2=value -z 1234 -V 20100101123000:20110101123000 id_ed25519.pub 
        // Signed user key id_ed25519-cert.pub: id "Cert Identity" serial 1234 for server.example.com,hostname valid from 2010-01-01T12:30:00 to 2011-01-01T12:30:00
        string typeName = "ssh-ed25519-cert-v01@openssh.com";
        byte[] rawData = Convert.FromBase64String("AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIGoinBqEiRvzv26kibhxBVMEst3FnL1waGvM3Fx23GA3AAAAINbz5ktoblIIPXUglgZCZ72DzhVmv0gFpC949TSJZbCTAAAAAAAABNIAAAACAAAADUNlcnQgSWRlbnRpdHkAAAAiAAAAEnNlcnZlci5leGFtcGxlLmNvbQAAAAhob3N0bmFtZQAAAABLPdy4AAAAAE0fEDgAAAAAAAAAIQAAAARleHQxAAAAAAAAAARleHQyAAAACQAAAAV2YWx1ZQAAAAAAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIJYhALd/lAi8iju7r03DLHAsW00oT/cXR1E/TTue09/9AAAAUwAAAAtzc2gtZWQyNTUxOQAAAEAgD1qPYsMTyYkKEoJZ3KVgEUH15WfoQwmY8k3s1G/nA4AsSeQs82BSzpiwvZMr8wiZIR9AJbBO4s0Pr5uLjwUL");

        HostKey hostKey = new HostKey(new SshKeyData(new Name(typeName), rawData));

        Assert.Equal(new Name(typeName), hostKey.ReceivedKeyType);

        HostCertificateInfo? certInfo = hostKey.CertificateInfo;
        Assert.NotNull(certInfo);

        Assert.Equal("Cert Identity", certInfo.Identifier);
        Assert.Equal(1234UL, certInfo.SerialNumber);
        Assert.Equal(typeName, certInfo.Type);

        Assert.Equal(new DateTimeOffset(2010, 1, 1, 11, 30, 0, 0, TimeSpan.Zero), certInfo.ValidAfter);
        Assert.Equal(new DateTimeOffset(2011, 1, 1, 11, 30, 0, 0, TimeSpan.Zero), certInfo.ValidBefore);
        Assert.Equal([ "server.example.com" ,"hostname"], certInfo.Principals);
    }
}

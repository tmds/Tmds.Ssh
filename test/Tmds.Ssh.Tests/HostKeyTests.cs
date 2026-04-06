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

    // ssh-keygen -h -s sshd_container/ca -I "server_key_rsa" -n "127.0.0.1,localhost" server_key_ed25519.pub
    private const string CertWithMatchingPrincipals = "AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIAp2tVPOaBtJqinbNeUu6zW5Cm/7MTdZamJiice8DrzhAAAAIJ2OJtN8Wfxu6si2e/Tlc2th7P7lVv6xKyhngjQGvHOZAAAAAAAAAAAAAAACAAAADnNlcnZlcl9rZXlfcnNhAAAAGgAAAAkxMjcuMC4wLjEAAAAJbG9jYWxob3N0AAAAAAAAAAD//////////wAAAAAAAAAAAAAAAAAAAhcAAAAHc3NoLXJzYQAAAAMBAAEAAAIBAK4bE8Qx2NCRkehY9vsoi5GI68a8cmI7+eSIMtf0LkNnfXbeeHoRXZqEU4UihEatO7QgB5CvAdh1TFBTybIxunaNn/BCIgEl0OfR7B1rcxCLLZJ2RmjsrrUHSNjeUvWcZ2O+l9b1pEDoZacEPe5+f9MEb57j4qTZB2Uy8Phn+xNFv65sh0EUtCCH75yGGdrEVjkQGXNT/y//EdLL4rgizu9DrX++ICZRMxJ7ADWkx1fiwxNubTJZuEXlrfIzuGX6hYlep48UmbQsjFm95nwPp/ku2R3vTSMyROBEAAUxuWj0blEX+nhwWat5ltRadYFCaYE74swp81X6g7Urs1Sv2Ha73pxu7sQ8HNTU7GAItnJuU5MKwG4pwTyxHL5fg8RcWohXPEiROHmIbCzi6kjnIcHKs8NbB8EVsvuxwFQBQTqqu4O9jUxZ4LnVmkrrOTo0355oFCUONIfyTKPDUaCsOwhNY0ASoKlNCKnN4ddAnCTKk/+bq7mCrw2rLbm7TnpqJ7tXOAbS+YAQzN+FE9DF70dcwzxqH84K2HZ3X4nZMXvGy+zxsBgQGed5WZjqtBMkS3RA+uITB+eL5ASHxgUK+fPBGh3t6znUPBkhmb1DedlW6wkXpJHKpaWrQruOw8sETQV4n5I1t+v43DBkqAYJNGbMQefYfpNheounGKGvtULxAAACFAAAAAxyc2Etc2hhMi01MTIAAAIAcfQDSQsktTUzxMZ1oj24omVW1sIIvsH+NGQsRYtrkQzLmLQbUhbyZxARQ5VFI8/L8i4n2xUkE6/jf5BH+CyeaATLidLkyiiuxMQPHYAE/s0IyEbnG1RxNgzeBCQmrYks+mUydf8MJgntW9pPC18QTboiEknvHhH8yE412IufY9g/cLc8ZYcf2QzjtYV3WWHtHxzT/r3txlRDANSo2cRibF0lGMZsC/9rkMv71yy/2lFK+QUYUHqsZ9Omx9KdP2wNotxPk3SBGmAFhlsBqJtccJ15BEBGfWpDgDY1hEZWrqRVnGGheUlDqMFR3otUpBUCZgkQfzsAF7BW4/x2Hf0lhpQ/vwTVYWO0H6ZinLfprp7XMR299P/UT3Y/0HRb/OmSXgIlziM1+bLkJfiOGUglihQy84am9eQhASUzX/FOSNoTa6zPwqzSkxfXxNf7R8aN0YPZiNc30ZEcqEo7gp2I4OMPkOGU4x4eZET+53YS5I8zClc2slT1CMLTBPLTV4H+/ISd9qC7wc1zaMGVekm8ue1YFvH+Q8yF/3vMjb7G9t+1m0KhZPQ/T+1eggR3iPQrQWj78OaVfrpWOELNtF2k2U6ahn5TRZphq5aOgT3U3HeJU4EM3ZOWqZfnLBOBJBY7Vi0mW4YwHpyZbzqd86ACZUMrUXSGqV/qHIduuNs9f5U=";

    // ssh-keygen -h -s sshd_container/ca -I "no_principals" server_key_ed25519.pub
    private const string CertWithNoPrincipals = "AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIORykCrYFtZ7tEZ13aYgIdXoDk/lny532xS7D+YZnQ4CAAAAIJ2OJtN8Wfxu6si2e/Tlc2th7P7lVv6xKyhngjQGvHOZAAAAAAAAAAAAAAACAAAADW5vX3ByaW5jaXBhbHMAAAAAAAAAAAAAAAD//////////wAAAAAAAAAAAAAAAAAAAhcAAAAHc3NoLXJzYQAAAAMBAAEAAAIBAK4bE8Qx2NCRkehY9vsoi5GI68a8cmI7+eSIMtf0LkNnfXbeeHoRXZqEU4UihEatO7QgB5CvAdh1TFBTybIxunaNn/BCIgEl0OfR7B1rcxCLLZJ2RmjsrrUHSNjeUvWcZ2O+l9b1pEDoZacEPe5+f9MEb57j4qTZB2Uy8Phn+xNFv65sh0EUtCCH75yGGdrEVjkQGXNT/y//EdLL4rgizu9DrX++ICZRMxJ7ADWkx1fiwxNubTJZuEXlrfIzuGX6hYlep48UmbQsjFm95nwPp/ku2R3vTSMyROBEAAUxuWj0blEX+nhwWat5ltRadYFCaYE74swp81X6g7Urs1Sv2Ha73pxu7sQ8HNTU7GAItnJuU5MKwG4pwTyxHL5fg8RcWohXPEiROHmIbCzi6kjnIcHKs8NbB8EVsvuxwFQBQTqqu4O9jUxZ4LnVmkrrOTo0355oFCUONIfyTKPDUaCsOwhNY0ASoKlNCKnN4ddAnCTKk/+bq7mCrw2rLbm7TnpqJ7tXOAbS+YAQzN+FE9DF70dcwzxqH84K2HZ3X4nZMXvGy+zxsBgQGed5WZjqtBMkS3RA+uITB+eL5ASHxgUK+fPBGh3t6znUPBkhmb1DedlW6wkXpJHKpaWrQruOw8sETQV4n5I1t+v43DBkqAYJNGbMQefYfpNheounGKGvtULxAAACFAAAAAxyc2Etc2hhMi01MTIAAAIAmn91tdpU2J2hNX55caIxshbVG21ELtPBNLKovP2Tbxa+cLJtUblUURMR8iBGlppJbRBf9uLeJGvAQ82lO+LIdpiJFre/tNQ6m3s22yqZ9zILqBFmiEK43fQO1ixC6Ter6zD6PB3svl9TDtzSO5S3vI3ivL/RtW5nDEeX+HUJF/fA9i1X5tZvSuB02a2/A+X6/4qlm3kKFpy81CjVNQ5rqEUaH7PJbwr/BWbiNMSzN1IkNBETrlveCjbiTrUuJ2dRe/gkbrrdiwZGGz+fF6ACTZSN2tGFnb8dmZPmEjlMlfIuGTieB6HIkJrhxCIR+fp557kuHSpTsHD50FICyndx9dVfaksTIIYCbQaUyO5FZdEbqkB0Oc6ljLlhcJi4xScXnecPsECigrqGw8mgJiTBrBGV+OonG/o2rrZkK4K0naXjHVu6+/GcU+5ILvAxRzbYIMWTl2a+7DPiI6HPy5c8rGXfxwUkGRB/pc2rcwdxb3HWJe4kTjTgmjwUhXQ1qLxl4dC+NimY2b3S/vPf39FicIuy0ZHhiexcq1+VyDcR97ynxtCZ9ywezdpTbFnZNFhemsCtfnbgX3qvE0BKoIDaCSHbZvJqP3b7e7qhPpHrJhCiG+dYvb0OGWOlSiOPCKexj+8iCM9WmyQQEJZ3zsdI2pznvmBaZD/9peiHTzm/EU0=";

    // ssh-keygen -h -s sshd_container/ca -I "other_principal" -n "other.example.com" server_key_ed25519.pub
    private const string CertWithOtherPrincipal = "AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIDqnjQaYOhXwyZE1aq924sJIHCekTZ7wdRQYv/v5K+K5AAAAIJ2OJtN8Wfxu6si2e/Tlc2th7P7lVv6xKyhngjQGvHOZAAAAAAAAAAAAAAACAAAAD290aGVyX3ByaW5jaXBhbAAAABUAAAARb3RoZXIuZXhhbXBsZS5jb20AAAAAAAAAAP//////////AAAAAAAAAAAAAAAAAAACFwAAAAdzc2gtcnNhAAAAAwEAAQAAAgEArhsTxDHY0JGR6Fj2+yiLkYjrxrxyYjv55Igy1/QuQ2d9dt54ehFdmoRThSKERq07tCAHkK8B2HVMUFPJsjG6do2f8EIiASXQ59HsHWtzEIstknZGaOyutQdI2N5S9ZxnY76X1vWkQOhlpwQ97n5/0wRvnuPipNkHZTLw+Gf7E0W/rmyHQRS0IIfvnIYZ2sRWORAZc1P/L/8R0sviuCLO70Otf74gJlEzEnsANaTHV+LDE25tMlm4ReWt8jO4ZfqFiV6njxSZtCyMWb3mfA+n+S7ZHe9NIzJE4EQABTG5aPRuURf6eHBZq3mW1Fp1gUJpgTvizCnzVfqDtSuzVK/YdrvenG7uxDwc1NTsYAi2cm5TkwrAbinBPLEcvl+DxFxaiFc8SJE4eYhsLOLqSOchwcqzw1sHwRWy+7HAVAFBOqq7g72NTFngudWaSus5OjTfnmgUJQ40h/JMo8NRoKw7CE1jQBKgqU0Iqc3h10CcJMqT/5uruYKvDastubtOemonu1c4BtL5gBDM34UT0MXvR1zDPGofzgrYdndfidkxe8bL7PGwGBAZ53lZmOq0EyRLdED64hMH54vkBIfGBQr588EaHe3rOdQ8GSGZvUN52VbrCRekkcqlpatCu47DywRNBXifkjW36/jcMGSoBgk0ZsxB59h+k2F6i6cYoa+1QvEAAAIUAAAADHJzYS1zaGEyLTUxMgAAAgBAzta9lZM4WoG3fhuUdqT5zQFuqje3s8t0d9gULiJx8mP7n/eISM1AjU7OUnU1du6b9D1LjfI89yoT2FiLvTnt7ZYG5kKrSwEim5jaqvx95u7FpIdLOhuXtMnoydF57wUNUyh7sG80DaAkE3q9TcxNFIv8c0dC4sK10sYSEBliZ2cyWiILmwhaEUHkciK+kLe0JzUrYretnbt2vJPp+emtbK1C9SFBEFH2n0ZYl0rsvg8IDgHTRBr7b9z862mOaIKb5UyOoTIr4ib5O+Tl8p/70QItMlZn9Z9JxQL6rszhOFxYGjeBkrUm32LSmuOOVD+0XIyna7zg2ssWv5k86+dPRQkg2aGY1rVeeJrII+909yEmNZx4tOkmveP21doYnRAWA7+M5kmur7Icch28MrmBzC5A3kams5Tv32ZiCLv941RfV5Y1zXYGqbWIcgswl3oOxU0Uk93bayb6Z5zjKMFdnI6jadfEmQbDN1N/pyQZWmB4nd9AlXEzDheetmi9ngP2WJwsVGgvbMHoSvmtZHwebCYgtSYBj8ZFPtrMP8K6I5MfNlq98aBZm18kr2+k0Kk/mt6hNf1si4wHKN8l20nmg8/E3VInUIOv0/HCkYTIIOeXJhhfpBlJ1d9acMFlMFQ5Ts+ZG54z1RihEtjHNR7m4cj7Tlt2THx1kP34nz+QiQ==";

    [Fact]
    public void CertificateWithNoPrincipals_DoesNotMatchAnyHost()
    {
        var certInfo = ParseCertificate(CertWithNoPrincipals);
        Assert.Empty(certInfo.Principals);

        var connectionInfo = new SshConnectionInfo { HostName = "127.0.0.1" };
        var ex = Assert.Throws<ConnectFailedException>(() =>
            HostKeyVerification.CheckCertificate(connectionInfo, certInfo, SshClientSettings.DefaultServerHostKeyCertificateAlgorithms));
        Assert.Equal(ConnectFailedReason.KeyExchangeFailed, ex.Reason);
    }

    [Fact]
    public void CertificateWithNonMatchingPrincipal_Fails()
    {
        var certInfo = ParseCertificate(CertWithOtherPrincipal);
        Assert.Equal(["other.example.com"], certInfo.Principals);

        var connectionInfo = new SshConnectionInfo { HostName = "127.0.0.1" };
        var ex = Assert.Throws<ConnectFailedException>(() =>
            HostKeyVerification.CheckCertificate(connectionInfo, certInfo, SshClientSettings.DefaultServerHostKeyCertificateAlgorithms));
        Assert.Equal(ConnectFailedReason.KeyExchangeFailed, ex.Reason);
    }

    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("localhost")]
    public void CertificateWithMatchingPrincipal_Succeeds(string hostname)
    {
        var certInfo = ParseCertificate(CertWithMatchingPrincipals);

        var connectionInfo = new SshConnectionInfo { HostName = hostname };
        HostKeyVerification.CheckCertificate(connectionInfo, certInfo, SshClientSettings.DefaultServerHostKeyCertificateAlgorithms);
    }

    private static HostCertificateInfo ParseCertificate(string base64)
    {
        string typeName = "ssh-ed25519-cert-v01@openssh.com";
        byte[] rawData = Convert.FromBase64String(base64);
        HostKey hostKey = new HostKey(new SshKeyData(new Name(typeName), rawData));
        return hostKey.CertificateInfo!;
    }
}

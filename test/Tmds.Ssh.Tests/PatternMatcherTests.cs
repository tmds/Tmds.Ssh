using Xunit;

namespace Tmds.Ssh.Tests;

public class PatternMatcherTests
{
    [Theory]
    [InlineData("server.example.com", "server.example.com", true)]
    [InlineData("Server.Example.COM", "server.example.com", true)]
    [InlineData("server.example.com", "Server.Example.COM", true)]
    [InlineData("other.example.com", "server.example.com", false)]
    [InlineData("*.example.com", "server.example.com", true)]
    [InlineData("*.example.com", "example.com", false)]
    [InlineData("*.example.com", "sub.server.example.com", true)]
    [InlineData("server?.example.com", "server1.example.com", true)]
    [InlineData("server?.example.com", "server.example.com", false)]
    [InlineData("server?.example.com", "server12.example.com", false)]
    [InlineData("*", "anything", true)]
    [InlineData("server*", "server.example.com", true)]
    [InlineData("server*", "server", true)]
    public void IsPatternMatch(string pattern, string value, bool expected)
    {
        Assert.Equal(expected, PatternMatcher.IsPatternMatch(pattern, value));
    }
}

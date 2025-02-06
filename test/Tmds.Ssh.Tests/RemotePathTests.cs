namespace Tmds.Ssh.Tests;

public class RemotePathTests
{
    [Theory]
    [InlineData("", "", "")]
    [InlineData("foo", "", "foo")]
    [InlineData("/", "", "/")]
    [InlineData("/foo", "", "/foo")]
    [InlineData(".", "", "")]
    [InlineData("..", "", "..")]
    [InlineData("", "bar", "bar")]
    [InlineData("foo", "bar", "foo/bar")]
    [InlineData("/", "bar", "/bar")]
    [InlineData("/foo", "bar", "/foo/bar")]
    [InlineData(".", "bar", "bar")]
    [InlineData("..", "bar", "../bar")]
    [InlineData("", "/bar", "/bar")]
    [InlineData("foo", "/bar", "/bar")]
    [InlineData("/", "/bar", "/bar")]
    [InlineData("/foo", "/bar", "/bar")]
    [InlineData(".", "/bar", "/bar")]
    [InlineData("..", "/bar", "/bar")]
    [InlineData("", ".", "")]
    [InlineData("foo", ".", "foo")]
    [InlineData("/", ".", "/")]
    [InlineData("/foo", ".", "/foo")]
    [InlineData(".", ".", "")]
    [InlineData("..", ".", "..")]
    [InlineData("", "..", "..")]
    [InlineData("foo", "..", "")]
    [InlineData("/", "..", "/")]
    [InlineData("/foo", "..", "/")]
    [InlineData(".", "..", "..")]
    [InlineData("..", "..", "../..")]
    [InlineData("/../a/.///", "", "/a")]
    [InlineData("../a/.///", "", "../a")]
    [InlineData("/b/../a/.///", "", "/a")]
    [InlineData("b/../a/.///", "", "a")]
    public void ResolvePath(string path1, string path2, string expected)
    {
        string result = RemotePath.ResolvePath([path1, path2]);
        Assert.Equal(expected, result);
    }
}
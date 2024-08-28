using Xunit;

namespace Tmds.Ssh.Tests;

// I couldn't find any vectors as this algorithm isn't in an RFC and is OpenBSD
// specific so I used a rust implementation for these vectors
// https://github.com/RustCrypto/password-hashes/blob/master/bcrypt-pbkdf/tests/test_vectors.rs

public class BCryptTests
{
    [Theory]
    [InlineData("password", "salt", 4, "5BBF0CC293587F1C3635555C27796598D47E579071BF427E9D8FBE842ABA34D9")]
    [InlineData("password", "\0", 4, "C12B566235EEE04C212598970A579A67")]
    [InlineData("\0", "salt", 4, "6051BE18C2F4F82CBF0EFEE5471B4BB9")]
    [InlineData("password\0", "salt\0", 4, "7410E44CF4FA07BFAAC8A928B1727FAC001375E7BF7384370F48EFD121743050")]
    [InlineData("pass\0wor", "sa\0l", 4, "C2BFFD9DB38F6569EFEF4372F4DE83C0")]
    [InlineData("pass\0word", "sa\0lt", 4, "4BA4AC3925C0E8D7F0CDB6BB1684A56F")]
    [InlineData("password", "salt", 8, "E1367EC5151A33FAAC4CC1C144CD23FA15D5548493ECC99B9B5D9C0D3B27BEC76227EA66088B849B20AB7AA478010246E74BBA51723FEFA9F9474D6508845E8D")]
    [InlineData("password", "salt", 42, "833CF0DCF56DB65608E8F0DC0CE882BD")]
    [InlineData(
        "Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.",
        "salis\0",
        8,
        "10978B07253DF57F71A162EB0E8AD30A")]
    public void BCryptKdfVectors(string password, string salt, int rounds, string expected)
    {
        byte[] passwordBytes = System.Text.Encoding.UTF8.GetBytes(password);
        byte[] saltBytes = System.Text.Encoding.UTF8.GetBytes(salt);
        byte[] actualBytes = new byte[expected.Length / 2];

        BCrypt.DeriveKeyFromPassword(passwordBytes, saltBytes, rounds, actualBytes);
        Assert.Equal(expected, Convert.ToHexString(actualBytes));
    }
}

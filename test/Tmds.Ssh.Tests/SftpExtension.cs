namespace Tmds.Ssh.Tests;

// Copy of Tmds.Ssh.SftpExtensions with public access.
[Flags]
public enum SftpExtension
{
    None = Tmds.Ssh.SftpExtension.None,
    CopyData = Tmds.Ssh.SftpExtension.CopyData
}
namespace Tmds.Ssh;

[Flags]
enum SftpExtensions
{
    // https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-extensions-00
    CopyData = 1 // copy-data 1
}
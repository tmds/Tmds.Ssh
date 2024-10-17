namespace Tmds.Ssh;

[Flags]
enum SftpExtension
{
    // https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-extensions-00https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-extensions-00#section-7
    CopyData = 1 // copy-data 1
}
namespace Tmds.Ssh
{
    public enum SftpError
    {
        None = 0,
        Eof = 1,
        NoSuchFile = 2,
        PermissionDenied = 3,
        Failure = 4,
        BadMessage = 5,
        // NoConnection = 6,
        // ConnectionLost = 7,
        Unsupported = 8
    }
}
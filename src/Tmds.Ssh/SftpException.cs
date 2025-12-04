// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

/// <summary>
/// Exception for SFTP errors.
/// </summary>
public class SftpException : IOException
{
    /// <summary>
    /// Gets the error code.
    /// </summary>
    public SftpError Error { get; private set; }

    internal SftpException(SftpError error) : base(GetSftpExceptionMessage(error))
    {
        Error = error;
    }

    private static string GetSftpExceptionMessage(SftpError error)
        => error switch
        {
            SftpError.NoSuchFile => "The remote path does not exist.",
            SftpError.PermissionDenied => "Access to the remote path is denied.",
            SftpError.Unsupported => "The operation is not supported.",
            SftpError.Eof => "The end of the stream is reached.",
            SftpError.Failure => "The operation failed.",
            SftpError.BadMessage => "Invalid argument or path too long.",
            _ => $"Unknown error: {error}."
        };
}

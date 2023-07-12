namespace Tmds.Ssh
{
    public class SftpException : SshOperationException
    {
        public SftpError Error { get; private set; }

        internal SftpException(SftpError error) : base(error.ToString())
        {
            Error = error;
        }
    }
}
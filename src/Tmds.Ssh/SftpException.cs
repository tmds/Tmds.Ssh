// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.IO;

namespace Tmds.Ssh
{
    public class SftpException : IOException
    {
        public SftpError Error { get; private set; }

        internal SftpException(SftpError error) : base(error.ToString())
        {
            Error = error;
        }
    }
}
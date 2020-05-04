// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;

namespace Tmds.Ssh
{
    [Serializable]
    public class SftpException : Exception
    {
        public SftpErrorCode ErrorCode { get; internal set; }
		
        internal SftpException(string message) : base(message) { }
        internal SftpException(string message, SftpErrorCode errorCode) : base(message)
        {
            ErrorCode = errorCode;
        }
        internal SftpException(string message, Exception inner) : base(message, inner) { }
    }
}
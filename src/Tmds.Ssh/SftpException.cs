// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;

namespace Tmds.Ssh
{
    [Serializable]
    public class SftpException : Exception
    {
        public SftpErrorCode ErrorCode { get; }

        internal SftpException(SftpErrorCode errorCode, string? message) : base(message ?? $"Error: {errorCode}")
        {
            ErrorCode = errorCode;
        }
    }
}
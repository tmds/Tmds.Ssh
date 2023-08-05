// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Collections.Generic;
using System.IO;

namespace Tmds.Ssh
{
    public sealed class FileEntryAttributes
    {
        public long? Length { get; set; }
        public int? Uid { get; set; }
        public int? Gid { get; set; }
        public PosixFileMode? FileMode { get; set; }
        public DateTimeOffset? LastAccessTime { get; set; } // ATime
        public DateTimeOffset? LastWriteTime { get; set; } // MTime
        public Dictionary<string, string>? ExtendedAttributes { get; set; }

        public UnixFileType? FileType => (UnixFileType?)(FileMode & (PosixFileMode)0xf000);
#if NET7_0_OR_GREATER
        public UnixFileMode? Permissions => (UnixFileMode?)(FileMode & (PosixFileMode)0x0fff);
#endif
    }
}
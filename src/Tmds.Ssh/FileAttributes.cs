// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Collections.Generic;

namespace Tmds.Ssh
{
    public sealed class FileAttributes
    {
        public long? Length { get; set; }
        public int? Uid { get; set; }
        public int? Gid { get; set; }
        public PosixFileMode? FileMode { get; set; }
        public DateTimeOffset? LastAccessTime { get; set; } // ATime
        public DateTimeOffset? LastWriteTime { get; set; } // MTime
        public Dictionary<string, string>? ExtendedAttributes { get; set; }
    }
}
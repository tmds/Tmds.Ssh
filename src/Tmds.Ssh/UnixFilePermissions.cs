// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

// values match System.IO.UnixFileMode.
[Flags]
public enum UnixFilePermissions : short
{
    None = 0,
    OtherExecute = 1,
    OtherWrite = 2,
    OtherRead = 4,
    GroupExecute = 8,
    GroupWrite = 16,
    GroupRead = 32,
    UserExecute = 64,
    UserWrite = 128,
    UserRead = 256,
    StickyBit = 512,
    SetGroup = 1024,
    SetUser = 2048,
}

public static class UnixFilePermissionsExtensions
{
#if NET7_0_OR_GREATER
        public static UnixFilePermissions ToUnixFilePermissions(this UnixFileMode mode)
            => (UnixFilePermissions)mode;

        public static UnixFileMode ToUnixFileMode(this UnixFilePermissions permissions)
            => (UnixFileMode)permissions;
#endif
    internal static int GetMode(this UnixFilePermissions permissions)
        => (int)permissions;
}

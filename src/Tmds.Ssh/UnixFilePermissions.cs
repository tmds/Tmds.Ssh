// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

/// <summary>
/// Unix file permissions flags.
/// </summary>
[Flags]
public enum UnixFilePermissions : short
{
    /// <summary>
    /// No permissions.
    /// </summary>
    None = 0,

    /// <summary>
    /// Execute permission for others.
    /// </summary>
    OtherExecute = 1,

    /// <summary>
    /// Write permission for others.
    /// </summary>
    OtherWrite = 2,

    /// <summary>
    /// Read permission for others.
    /// </summary>
    OtherRead = 4,

    /// <summary>
    /// Execute permission for group.
    /// </summary>
    GroupExecute = 8,

    /// <summary>
    /// Write permission for group.
    /// </summary>
    GroupWrite = 16,

    /// <summary>
    /// Read permission for group.
    /// </summary>
    GroupRead = 32,

    /// <summary>
    /// Execute permission for user.
    /// </summary>
    UserExecute = 64,

    /// <summary>
    /// Write permission for user.
    /// </summary>
    UserWrite = 128,

    /// <summary>
    /// Read permission for user.
    /// </summary>
    UserRead = 256,

    /// <summary>
    /// Sticky bit.
    /// </summary>
    StickyBit = 512,

    /// <summary>
    /// Set group ID on execution.
    /// </summary>
    SetGroup = 1024,

    /// <summary>
    /// Set user ID on execution.
    /// </summary>
    SetUser = 2048,
}

/// <summary>
/// Extension methods for UnixFilePermissions.
/// </summary>
public static class UnixFilePermissionsExtensions
{
#if NET7_0_OR_GREATER
        /// <summary>
        /// Converts UnixFileMode to UnixFilePermissions.
        /// </summary>
        /// <param name="mode">The <see cref="UnixFileMode"/>.</param>
        /// <returns>The <see cref="UnixFilePermissions"/>.</returns>
        public static UnixFilePermissions ToUnixFilePermissions(this UnixFileMode mode)
            => (UnixFilePermissions)mode;

        /// <summary>
        /// Converts UnixFilePermissions to UnixFileMode.
        /// </summary>
        /// <param name="permissions">The <see cref="UnixFilePermissions"/>.</param>
        /// <returns>The <see cref="UnixFileMode"/>.</returns>
        public static UnixFileMode ToUnixFileMode(this UnixFilePermissions permissions)
            => (UnixFileMode)permissions;
#endif
    internal static int GetMode(this UnixFilePermissions permissions)
        => (int)permissions;
}

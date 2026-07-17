// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

/// <summary>
/// Provides methods for working with SSH config files.
/// </summary>
public static class SshConfig
{
    /// <summary>
    /// Returns hosts defined in the default SSH config files.
    /// </summary>
    public static ISet<string> GetHosts()
        => GetHosts(SshConfigSettings.DefaultConfigFilePaths);

    /// <summary>
    /// Returns hosts defined in the specified SSH config files.
    /// Wildcards and negation patterns are filtered out. Include directives are followed.
    /// </summary>
    public static ISet<string> GetHosts(IReadOnlyList<string> configFilePaths)
    {
        ArgumentNullException.ThrowIfNull(configFilePaths);

        HashSet<string> hosts = new(StringComparer.OrdinalIgnoreCase);

        foreach (string filePath in configFilePaths)
        {
            SshConfigParser.CollectHosts(filePath, Path.GetDirectoryName(filePath) ?? "", hosts);
        }

        return hosts;
    }
}

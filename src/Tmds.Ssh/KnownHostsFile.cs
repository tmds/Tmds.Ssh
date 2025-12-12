// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;

namespace Tmds.Ssh;

static class KnownHostsFile
{
    public static void AddKnownHost(string knownHostsFile, string host, int port, PublicKey sshKey, bool hash)
    {
        string knownHostLine = FormatLine(host, port, sshKey, hash) + '\n';
        byte[] buffer = Encoding.UTF8.GetBytes(knownHostLine);

        string directoryPath = Path.GetDirectoryName(knownHostsFile)!;
        if (!Directory.Exists(directoryPath))
        {
            if (OperatingSystem.IsWindows())
            {
                Directory.CreateDirectory(directoryPath);
            }
            else
            {
                Directory.CreateDirectory(directoryPath, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            }
        }

        var fileStreamOptions = new FileStreamOptions()
        {
            Access = FileAccess.Write,
            Mode = FileMode.OpenOrCreate | FileMode.Append, // Unfortunately this is not O_APPEND atomic
            BufferSize = 0,
            Share = FileShare.ReadWrite
        };
        if (!OperatingSystem.IsWindows())
        {
            fileStreamOptions.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        }
        using var fileStream = new FileStream(knownHostsFile, fileStreamOptions);
        fileStream.Write(buffer);
    }

    private static string FormatLine(string host, int port, PublicKey key, bool hash = false)
    {
        if (port != 22)
        {
            host = $"[{host}]:{port}";
        }
        if (hash)
        {
            Span<byte> salt = stackalloc byte[20];
            RandomBytes.Fill(salt);
            Span<byte> destination = stackalloc byte[20];
            int bytesWritten = HMACSHA1.HashData(salt, Encoding.UTF8.GetBytes(host), destination);
            Debug.Assert(bytesWritten == 20);
            host = $"|1|{Convert.ToBase64String(salt)}|{Convert.ToBase64String(destination)}";
        }
        return $"{host} {key.Type} {Convert.ToBase64String(key.RawData.Span)}";
    }

    private static bool MaySkipFile(string path)
    {
        // We want to avoid skipping files that are not accessible and throw for those while opening.
        // File.Exists (and Directory.Exists) return false when a parent directory is not accessible.
        // We can open the file but that causes a first chance File/DirectoryNotFoundException.
        // The code below avoids that exception when the files live under a directory that is accessible.
        // This was added in particular for the checking of '/etc/ssh/ssh_known_hosts' (which often doesn't exist).

        // File exists, don't skip.
        if (File.Exists(path))
        {
            return false;
        }

        // The file does not exist, but that may be due to its parent directory being inaccessible.
        path = Path.GetFullPath(path);
        string directoryPath = Path.GetDirectoryName(path)!;
        do
        {
            if (!Directory.Exists(directoryPath))
            {
                // The directory does not exist, but that may be due to its parent directory being inaccessible.
                string parentPath = Path.GetDirectoryName(directoryPath)!;
                if (parentPath == directoryPath)
                {
                    // We're at the root and it doesn't exist.
                    // Try to open the file.
                    return false;
                }
                directoryPath = parentPath;
                continue;
            }
            // The directory exists, if we can see its children, we know we're able to check their existance.
            var enumerationOptions = new System.IO.EnumerationOptions()
            {
                IgnoreInaccessible = false,
                AttributesToSkip = FileAttributes.None,
                ReturnSpecialDirectories = true,
                RecurseSubdirectories = false
            };
            try
            {
                IEnumerable<string> entries = Directory.EnumerateFileSystemEntries(directoryPath, "*", enumerationOptions);
                foreach (var entry in entries)
                {
                    break;
                }
                // Skip the file.
                return true;
            }
            catch
            {
                // Some error occurred, probably unauthorized access.
                // Try to open the file.
                return false;
            }
        } while (true);
    }

    public static void AddHostKeysFromFile(string filename, TrustedHostKeys hostKeys, string host, string? ip, int port, ILogger<SshClient> logger)
    {
        if (MaySkipFile(filename))
        {
            return;
        }

        IEnumerable<string> lines;
        try
        {
            lines = File.ReadLines(filename);
            logger.LoadingKnownHostKeys(filename);
        }
        // If the file is not accessible the method throws UnauthorizedAccessException.
        // We intentionally don't catch that exception because the file may contain revoked keys.
        catch (IOException ex)
        {
            logger.CanNotReadKnownHostKeys(filename, ex.Message);
            return;
        }

        host = host.ToLowerInvariant();
        if (host == ip)
        {
            ip = null;
        }
        ip = ip?.ToLowerInvariant();

        foreach (var line in lines)
        {
            // Skip comment lines.
            if (line.StartsWith('#'))
            {
                continue;
            }

            // Each line in these files contains the following fields: markers (optional), hostnames, keytype, base64-encoded key, comment.  The fields are separated by spaces.
            string[] lineParts = line.Split(new [] { ' ', '\t' }, System.StringSplitOptions.RemoveEmptyEntries);

            bool hasMarker = lineParts.Length > 0 && lineParts[0][0] == '@';
            if ((hasMarker && lineParts.Length < 4) ||
                (!hasMarker && lineParts.Length < 3))
            {
                continue;
            }

            // Skip comment lines.
            if (lineParts[0][0] == '#')
            {
                continue;
            }

            int idx = 0;
            string? markers = !hasMarker ? null : lineParts[idx++];
            string hostnames = lineParts[idx++];
            string keytype = lineParts[idx++];
            string base64key = lineParts[idx++];

            MatchType matchType = IsMatch(hostnames, host, ip, port);
            if (matchType == MatchType.NoMatch)
            {
                continue;
            }

            bool revoked = markers == "@revoked";
            bool certauth = markers == "@cert-authority";

            byte[] key;
            try
            {
                key = Convert.FromBase64String(base64key);
            }
            catch (FormatException)
            {
                continue;
            }

            SshKeyData sshKey = new SshKeyData(new Name(keytype), key);

            if (revoked)
            {
                hostKeys.AddRevokedKey(sshKey);
            }
            else if (certauth)
            {
                hostKeys.AddCAKey(sshKey);
            }
            else
            {
                hostKeys.AddTrustedKey(sshKey, isPatternMatch: matchType == MatchType.PatternMatch);
            }
        }
    }

    private static MatchType IsMatch(string hostnamesPattern, string host, string? ip, int port)
    {
        string[] patterns = hostnamesPattern.Split(',', StringSplitOptions.RemoveEmptyEntries);

        foreach (var pattern in patterns)
        {
            string s = pattern;
            bool negate = s[0] == '!';
            if (negate)
            {
                s = s.Substring(1);
            }

            MatchType matchType = IsHostNameMatch(s, host, ip, port);

            if (matchType == MatchType.NoMatch)
            {
                continue;
            }

            // if the host name matches a negated pattern, it is not accepted (by that line)
            if (negate)
            {
                return MatchType.NoMatch;
            }

            return matchType;
        }

        return MatchType.NoMatch;
    }

    private static MatchType IsHostNameMatch(string pattern, string host, string? ip, int port)
    {
        if (pattern == "*")
        {
            return MatchType.PatternMatch;
        }

        bool hashed = pattern.Length > 0 && pattern[0] == '|';

        if (hashed)
        {
            if (!pattern.StartsWith("|1|"))
            {
                return MatchType.NoMatch;
            }

            string[] split = pattern.Substring(3).Split('|');
            if (split.Length != 2)
            {
                return MatchType.NoMatch;
            }
            byte[] salt = new byte[20];
            if (!Convert.TryFromBase64String(split[0], salt, out int saltLength) || saltLength != 20)
            {
                return MatchType.NoMatch;
            }
            byte[] hash = new byte[20];
            if (!Convert.TryFromBase64String(split[1], hash, out int hashLength) || hashLength != 20)
            {
                return MatchType.NoMatch;
            }

            using var hmac = new HMac(HashAlgorithmName.SHA1, 20, 20, salt);
            if (port != 22)
            {
                host = $"[{host}]:{port}";
            }
            hmac.AppendData(Encoding.UTF8.GetBytes(host));
            if (hmac.CheckHashAndReset(hash))
            {
                return MatchType.ExactMatch;
            }
            if (ip != null)
            {
                if (port != 22)
                {
                    ip = $"[{ip}]:{port}";
                }
                hmac.AppendData(Encoding.UTF8.GetBytes(ip));
                if (hmac.CheckHashAndReset(hash))
                {
                    return MatchType.ExactMatch;
                }
            }

            return MatchType.NoMatch;
        }
        else
        {
            // A hostname or address may optionally be
            // enclosed within ‘[’ and ‘]’ brackets then followed by ‘:’ and a non-standard port number.
            if (port != 22 || (pattern.Length > 0 && pattern[0] == '['))
            {
                int endOfBracket = pattern.IndexOf(']');
                if (endOfBracket == -1)
                {
                    return MatchType.NoMatch;;
                }
                if (pattern.Length < (endOfBracket + 2))
                {
                    return MatchType.NoMatch;;
                }
                if (!int.TryParse(pattern.AsSpan(endOfBracket + 2), out int parsedPort))
                {
                    return MatchType.NoMatch;;
                }
                if (parsedPort != port)
                {
                    return MatchType.NoMatch;;
                }
                pattern = pattern.Substring(1, endOfBracket - 1);
            }

            bool containsWildCards = pattern.Contains("*") || pattern.Contains("?");
            if (containsWildCards)
            {
                string regexPattern =
                    "^" +
                    pattern.ToLowerInvariant()
                        .Replace(".", "\\.")
                        .Replace("*", ".*")
                        .Replace("?", ".?")
                    + "$";

                bool isMatch = Regex.IsMatch(host, regexPattern) ||
                                (ip != null && Regex.IsMatch(ip, regexPattern));
                
                return isMatch ? MatchType.PatternMatch : MatchType.NoMatch;
            }
            else
            {
                pattern = pattern.ToLowerInvariant();

                bool isMatch = pattern == host || pattern == ip;

                return isMatch ? MatchType.ExactMatch : MatchType.NoMatch;
            }
        }
    }

    private enum MatchType
    {
        NoMatch,
        ExactMatch,
        PatternMatch
    }
}

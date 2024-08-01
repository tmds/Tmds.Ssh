// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using static System.Environment;

namespace Tmds.Ssh;

static class KnownHostsFile
{
    private static readonly char[] WhitespaceSeparators = { ' ', '\t' };

    public static void AddKnownHost(string knownHostsFile, string host, int port, HostKey key)
    {
        string knownHostLine = FormatLine(host, port, key) + '\n';
        byte[] buffer = Encoding.UTF8.GetBytes(knownHostLine);

        string directoryPath = Path.GetDirectoryName(knownHostsFile)!;
        if (!Directory.Exists(directoryPath))
        {
            if (!OperatingSystem.IsWindows())
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

    public static string FormatLine(string host, int port, HostKey key)
    {
        bool nonStandardPort = port != 22;
        return nonStandardPort ? $"[{host}]:{port} {key.Type} {Convert.ToBase64String(key.RawKey)}"
                               : $"{host} {key.Type} {Convert.ToBase64String(key.RawKey)}";
    }

    public static void AddHostKeysFromFile(string filename, TrustedHostKeys hostKeys, string host, string? ip, int port)
    {
        IEnumerable<string> lines;
        try
        {
            if (File.Exists(filename))
            {
                lines = File.ReadLines(filename);
            }
            else
            {
                return;
            }
        }
        catch (IOException)
        {
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
            string[] lineParts = line.Split(WhitespaceSeparators, System.StringSplitOptions.RemoveEmptyEntries);

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

            bool certauth = markers == "@cert-authority";
            if (certauth)
            {
                continue;
            }

            MatchType matchType = IsMatch(hostnames, host, ip, port);
            if (matchType == MatchType.NoMatch)
            {
                continue;
            }

            bool revoked = markers == "@revoked";

            byte[] key;
            try
            {
                key = Convert.FromBase64String(base64key);
            }
            catch (FormatException)
            {
                continue;
            }

            HostKey hostKey = new HostKey(new Name(keytype), key);

            if (revoked)
            {
                hostKeys.AddRevokedKey(hostKey);
            }
            else
            {
                hostKeys.AddTrustedKey(hostKey, isPatternMatch: matchType == MatchType.PatternMatch);
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

            // A hostname or address may optionally be
            // enclosed within ‘[’ and ‘]’ brackets then followed by ‘:’ and a non-standard port number.
            if (port != 22 || (s.Length > 0 && s[0] == '['))
            {
                int endOfBracket = s.IndexOf(']');
                if (endOfBracket == -1)
                {
                    continue;
                }
                if (s.Length < (endOfBracket + 2))
                {
                    continue;
                }
                if (!int.TryParse(s.AsSpan(endOfBracket + 2), out int parsedPort))
                {
                    continue;
                }
                if (parsedPort != port)
                {
                    continue;
                }
                s = s.Substring(1, endOfBracket - 1);
            }

            MatchType matchType = IsHostNameMatch(s, host, ip);

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

    private static MatchType IsHostNameMatch(string pattern, string host, string? ip)
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
            hmac.AppendData(Encoding.UTF8.GetBytes(host));
            if (hmac.CheckHashAndReset(hash))
            {
                return MatchType.ExactMatch;
            }
            if (ip != null)
            {
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

// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Tmds.Ssh
{
    static class KnownHostsFile
    {
        private static readonly char[] WhitespaceSeparators = { ' ', '\t' };

        public static HostKeyVerificationResult CheckHost(string filename, string host, string? ip, int port, SshKey key)
        {
            HostKeyVerificationResult result = HostKeyVerificationResult.Unknown;

            string[] lines;
            try
            {
                if (File.Exists(filename))
                {
                    lines = File.ReadAllLines(filename);
                }
                else
                {
                    return HostKeyVerificationResult.Unknown;
                }
            }
            catch (IOException)
            {
                return HostKeyVerificationResult.Unknown;
            }

            host = host.ToLowerInvariant();
            if (host == ip)
            {
                ip = null;
            }
            ip = ip?.ToLowerInvariant();

            string? keyDataBase64 = null;

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

                if (!IsMatch(hostnames, host, ip, port))
                {
                    continue;
                }

                bool revoked = markers == "@revoked";

                if (keytype != key.Type)
                {
                    if (!revoked && result == HostKeyVerificationResult.Unknown)
                    {
                        result = HostKeyVerificationResult.Changed;
                    }
                    continue;
                }

                if (keyDataBase64 == null)
                {
                    keyDataBase64 = Convert.ToBase64String(key.Data);
                }

                if (keyDataBase64 != base64key)
                {
                    if (!revoked && result == HostKeyVerificationResult.Unknown)
                    {
                        result = HostKeyVerificationResult.Changed;
                    }
                    continue;
                }

                if (revoked)
                {
                    return HostKeyVerificationResult.Revoked;
                }

                result = HostKeyVerificationResult.Trusted;
            }

            return result;
        }

        private static bool IsMatch(string hostnamesPattern, string host, string? ip, int port)
        {
            string[] patterns = hostnamesPattern.Split(',', StringSplitOptions.RemoveEmptyEntries);

            bool match = false;

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

                bool patternMatch = IsHostNameMatch(s, host, ip);

                if (patternMatch)
                {
                    if (negate)
                    {
                        return false;
                    }
                    match = true;
                }
            }

            return match;
        }

        private static bool IsHostNameMatch(string pattern, string host, string? ip)
        {
            if (pattern == "*")
            {
                return true;
            }

            bool hashed = pattern.Length > 0 && pattern[0] == '|';

            if (hashed)
            {
                if (!pattern.StartsWith("|1|"))
                {
                    return false;
                }

                string[] split = pattern.Substring(3).Split('|');
                if (split.Length != 2)
                {
                    return false;
                }
                byte[] salt = new byte[20];
                if (!Convert.TryFromBase64String(split[0], salt, out int saltLength) || saltLength != 20)
                {
                    return false;
                }
                byte[] hash = new byte[20];
                if (!Convert.TryFromBase64String(split[1], hash, out int hashLength) || hashLength != 20)
                {
                    return false;
                }

                using var hmac = new HMac(HashAlgorithmName.SHA1, 20, 20, salt);
                hmac.AppendData(Encoding.UTF8.GetBytes(host));
                if (hmac.CheckHashAndReset(hash))
                {
                    return true;
                }
                if (ip != null)
                {
                    hmac.AppendData(Encoding.UTF8.GetBytes(ip));
                    if (hmac.CheckHashAndReset(hash))
                    {
                        return true;
                    }
                }

                return false;
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
                    return Regex.IsMatch(host, regexPattern) ||
                        (ip != null && Regex.IsMatch(ip, regexPattern));
                }
                else
                {
                    pattern = pattern.ToLowerInvariant();
                    return pattern == host || pattern == ip;
                }
            }
        }
    }
}
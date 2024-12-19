// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Globalization;
using System.IO.Enumeration;

namespace Tmds.Ssh;

sealed class SshConfig
{
    private const int MaxKeywordLength = 50; // large enough to fit keywords.
    private const string WhiteSpace = " \t";
    private static readonly string Home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile, Environment.SpecialFolderOption.DoNotVerify);
    private static readonly List<string> ListOfNone = [];

    public enum StrictHostKeyChecking
    {
        Yes,
        AcceptNew,
        No,
        Ask
    }

    public enum AlgorithmListOperation
    {
        Prepend,
        Append,
        Remove,
        Set,
        Filter
    }

    public struct AlgorithmList
    {
        public Name[] Algorithms { get; set; } // AlgorithmListOperation.{Prepend,Append,Set}
        public string PatternList { get; set; }  // AlgorithmListOperation.{Remove,Filter}
        public AlgorithmListOperation Operation { get; set; }
    }

    public string? HostName { get; set; }
    public string? UserName { get; set; }
    public int? Port { get; set; }
    public int? ConnectTimeout { get; set; }
    public List<string>? GlobalKnownHostsFiles { get; set; }
    public List<string>? UserKnownHostsFiles { get; set; }
    public AlgorithmList? Ciphers { get; set; }
    public bool? Compression { get; set; }
    public bool? IdentitiesOnly { get; set; }
    public AlgorithmList? HostKeyAlgorithms { get; set; }
    public AlgorithmList? KexAlgorithms { get; set; }
    public AlgorithmList? Macs { get; set; }
    public AlgorithmList? PublicKeyAcceptedAlgorithms { get; set; }
    public int? RequiredRSASize { get; set; }
    public Name[]? PreferredAuthentications { get; set; }
    public bool? PubKeyAuthentication { get; set; }
    public bool? GssApiAuthentication { get; set; }
    public bool? GssApiDelegateCredentials { get; set; }
    public string? GssApiServerIdentity { get; set; }
    public List<string>? IdentityFiles { get; set; }
    public StrictHostKeyChecking? HostKeyChecking { get; set; }
    public bool? HashKnownHosts { get; set; }
    public List<string>? SendEnv { get; set; }
    public bool? TcpKeepAlive { get; set; }
    public int? ServerAliveCountMax { get; set; }
    public int? ServerAliveInterval { get; set; }

    internal static ValueTask<SshConfig> DetermineConfigForHost(string? userName, string host, int? port, IReadOnlyDictionary<SshConfigOption, SshConfigOptionValue>? options, IReadOnlyList<string> configFiles, CancellationToken cancellationToken)
    {
        SshConfig config = new SshConfig()
        {
            UserName = userName,
            Port = port
        };

        if (options is not null)
        {
            ConfigureFromOptions(config, options);
        }

        string originalhost = host;

        bool performSecondPass = false;
        foreach (var configFile in configFiles)
        {
            string includeBasePath = Path.GetDirectoryName(configFile)!;
            ConfigureFromConfigFile(config, host, originalhost, configFile, includeBasePath, ref performSecondPass, isSecondPass: false);
        }

        config.HostName ??= host; // TODO: TOKEN expand.
        host = config.HostName;

        if (performSecondPass)
        {
            foreach (var configFile in configFiles)
            {
                string includeBasePath = Path.GetDirectoryName(configFile)!;
                ConfigureFromConfigFile(config, host, originalhost, configFile, includeBasePath, ref performSecondPass, isSecondPass: true);
            }
        }

        return ValueTask.FromResult(config);
    }

    private static void ConfigureFromOptions(SshConfig config, IReadOnlyDictionary<SshConfigOption, SshConfigOptionValue> options)
    {
        Span<char> keywordBuffer = stackalloc char[MaxKeywordLength];
        Span<char> keywordBufferLowerBuffer = stackalloc char[MaxKeywordLength];
        foreach (var option in options)
        {
            if (!Enum.TryFormat(option.Key, keywordBuffer, out int length))
            {
                throw new NotSupportedException($"Can not format keyword: {option.Value}.");
            }
            ReadOnlySpan<char> keyword = keywordBuffer.Slice(0, length);
            length = keyword.Slice(0, length).ToLowerInvariant(keywordBufferLowerBuffer);
            keyword = keywordBufferLowerBuffer.Slice(0, length);
            if (option.Value.IsSingleValue)
            {
                HandleMatchedKeyword(config, keyword, option.Value.FirstValue);
            }
            else
            {
                foreach (var value in option.Value.Values)
                {
                    HandleMatchedKeyword(config, keyword, value);
                }
            }
        }
    }

    private static void ConfigureFromConfigFile(SshConfig config, string host, string originalhost, string filename, string includeBasePath, ref bool performSecondPass, bool isSecondPass)
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

        Span<char> keywordBuffer = stackalloc char[MaxKeywordLength];
        bool isMatch = true;
        foreach (var l in lines)
        {
            ReadOnlySpan<char> remainder = l.AsSpan();
            remainder = remainder.Trim(WhiteSpace);

            // Comment
            if (remainder.StartsWith("#"))
            {
                continue;
            }

            if (TryGetNextToken(ref remainder, out ReadOnlySpan<char> configKeyword))
            {
                int length = configKeyword.ToLowerInvariant(keywordBuffer);
                if (length == -1)
                {
                    // keyword was larger than keywordBuffer
                    continue;
                }
                ReadOnlySpan<char> keyword = keywordBuffer.Slice(0, length);

                switch (keyword)
                {
                    case "host":
                        bool anyMatch = false;
                        // patterns are separated by whitespace.
                        while (TryGetNextToken(ref remainder, out ReadOnlySpan<char> pattern))
                        {
                            bool isNegate = PatternMatcher.IsNegate(ref pattern);
                            if (PatternMatcher.IsPatternListMatch(pattern, host))
                            {
                                anyMatch = !isNegate;

                                // If a negated entry is matched, then the Host entry is ignored, regardless of whether any other patterns on the line match.
                                if (isNegate)
                                {
                                    break;
                                }
                            }
                        }
                        isMatch = anyMatch;
                        continue;
                    case "match":
                        isMatch = IsMatchMatch(config, host, originalhost, remainder, ref performSecondPass, isSecondPass);
                        continue;
                }

                if (!isMatch)
                {
                    continue;
                }

                if (keyword.SequenceEqual("include"))
                {
                    while (TryGetNextToken(ref remainder, out ReadOnlySpan<char> pathPattern))
                    {
                        string path = TildeExpand(pathPattern);
                        if (!Path.IsPathRooted(path))
                        {
                            path = Path.Join(includeBasePath, path);
                        }
                        foreach (var includefile in Glob(path))
                        {
                            ConfigureFromConfigFile(config, host, originalhost, includefile, includeBasePath, ref performSecondPass, isSecondPass);
                        }
                    }

                    continue;
                }

                HandleMatchedKeyword(config, keyword, remainder);
            }
        }
    }

    private static void HandleMatchedKeyword(SshConfig config, ReadOnlySpan<char> keyword, ReadOnlySpan<char> keywordValue)
    {
        ReadOnlySpan<char> remainder = keywordValue;

        switch (keyword)
        {
            case "hostname":
                config.HostName ??= NextTokenAsStringOrDefault(ref remainder);
                break;

            case "user":
                config.UserName ??= NextTokenAsStringOrDefault(ref remainder);
                break;

            case "port":
                config.Port ??= NextTokenAsInt(keyword, ref remainder);
                break;

            case "connecttimeout":
                config.ConnectTimeout ??= NextTokenAsInt(keyword, ref remainder);
                break;

            // host key options
            case "globalknownhostsfile":
                if (config.GlobalKnownHostsFiles == null)
                {
                    config.GlobalKnownHostsFiles = new();
                    while (TryGetNextToken(ref remainder, out ReadOnlySpan<char> pathPattern))
                    {
                        if (pathPattern.Equals("none", StringComparison.OrdinalIgnoreCase))
                        {
                            break;
                        }

                        string path = TildeExpand(pathPattern);
                        config.GlobalKnownHostsFiles.Add(path);
                    }
                }
                break;
            case "userknownhostsfile":
                if (config.UserKnownHostsFiles == null)
                {
                    config.UserKnownHostsFiles = new();
                    while (TryGetNextToken(ref remainder, out ReadOnlySpan<char> pathPattern))
                    {
                        if (pathPattern.Equals("none", StringComparison.OrdinalIgnoreCase))
                        {
                            break;
                        }

                        string path = TildeExpand(pathPattern);
                        // TODO: TOKEN expand.
                        // TODO: envvar expand.
                        config.UserKnownHostsFiles.Add(path);
                    }
                }
                break;

            case "hashknownhosts":
                config.HashKnownHosts ??= ParseYesNoKeywordValue(keyword, ref remainder);
                break;

            case "stricthostkeychecking":
                if (!config.HostKeyChecking.HasValue)
                {
                    ReadOnlySpan<char> value = GetKeywordValue(keyword, ref remainder);

                    if (value.Equals("no", StringComparison.OrdinalIgnoreCase) ||
                        value.Equals("off", StringComparison.OrdinalIgnoreCase))
                    {
                        config.HostKeyChecking = StrictHostKeyChecking.No;
                    }
                    else if (value.Equals("accept-new", StringComparison.OrdinalIgnoreCase))
                    {
                        config.HostKeyChecking = StrictHostKeyChecking.AcceptNew;
                    }
                    else if (value.Equals("yes", StringComparison.OrdinalIgnoreCase))
                    {
                        config.HostKeyChecking = StrictHostKeyChecking.Yes;
                    }
                    else
                    {
                        ThrowUnsupportedKeywordValue(keyword, value);
                    }
                }
                break;

            case "preferredauthentications":
            {
                ReadOnlySpan<char> authentications = GetKeywordValue(keyword, ref remainder);
                config.PreferredAuthentications ??= ParseNameList(authentications);
                break;
            }
            case "pubkeyauthentication":
            {
                if (!config.PubKeyAuthentication.HasValue)
                {
                    ReadOnlySpan<char> value = GetKeywordValue(keyword, ref remainder);

                    if (value.Equals("no", StringComparison.OrdinalIgnoreCase))
                    {
                        config.PubKeyAuthentication = false;
                    }
                    else if (value.Equals("yes", StringComparison.OrdinalIgnoreCase) ||
                                value.Equals("unbound", StringComparison.OrdinalIgnoreCase) ||
                                value.Equals("host-bound", StringComparison.OrdinalIgnoreCase))
                    {
                        config.PubKeyAuthentication = true;
                    }
                    else
                    {
                        ThrowUnsupportedKeywordValue(keyword, value);
                    }
                }
                break;
            }
            case "identityfile":
            {
                ReadOnlySpan<char> value = GetKeywordValue(keyword, ref remainder);

                if (value.Equals("none", StringComparison.OrdinalIgnoreCase))
                {
                    config.IdentityFiles = ListOfNone;
                }

                if (!object.ReferenceEquals(config.IdentityFiles, ListOfNone))
                {
                    config.IdentityFiles ??= new();

                    // Don't add duplicates.
                    bool found = false;
                    string path = TildeExpand(value);
                    // TODO: TOKEN expand.
                    for (int i = 0; i < config.IdentityFiles.Count; i++)
                    {
                        StringComparison comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
                        if (string.Equals(path, config.IdentityFiles[i], comparison))
                        {
                            found = true;
                            break;
                        }
                    }
                    if (!found)
                    {
                        config.IdentityFiles.Add(path);
                    }
                }
                break;
            }
            case "gssapiauthentication":
            {
                config.GssApiAuthentication ??= ParseYesNoKeywordValue(keyword, ref remainder);
                break;
            }
            case "gssapidelegatecredentials":
            {
                config.GssApiDelegateCredentials ??= ParseYesNoKeywordValue(keyword, ref remainder);
                break;
            }
            case "gssapiserveridentity":
            {
                config.GssApiServerIdentity ??= NextTokenAsStringOrDefault(ref remainder);
                break;
            }

            case "requiredrsasize":
                config.RequiredRSASize ??= NextTokenAsInt(keyword, ref remainder);
                break;

            case "sendenv":
                while (TryGetNextToken(ref remainder, out ReadOnlySpan<char> pattern))
                {
                    if (pattern.StartsWith("-"))
                    {
                        pattern = pattern.Slice(1);
                        if (config.SendEnv != null)
                        {
                            for (int i = 0; i < config.SendEnv.Count;)
                            {
                                if (PatternMatcher.IsPatternMatch(pattern, config.SendEnv[i]))
                                {
                                    config.SendEnv.RemoveAt(i);
                                }
                                else
                                {
                                    i++;
                                }
                            }
                        }
                    }
                    else
                    {
                        config.SendEnv ??= new();
                        config.SendEnv.Add(pattern.ToString());
                    }
                }
                break;

            case "ciphers":
                config.Ciphers ??= ReadAlgorithmList(keyword, remainder);
                break;
            case "hostkeyalgorithms":
                config.HostKeyAlgorithms ??= ReadAlgorithmList(keyword, remainder);
                break;
            case "kexalgorithms":
                config.KexAlgorithms ??= ReadAlgorithmList(keyword, remainder);
                break;
            case "macs":
                config.Macs ??= ReadAlgorithmList(keyword, remainder);
                break;
            case "pubkeyacceptedalgorithms":
                config.PublicKeyAcceptedAlgorithms ??= new AlgorithmList()
                {
                    Algorithms = Array.Empty<Name>(),
                    Operation = AlgorithmListOperation.Filter,
                    PatternList = remainder.Trim(WhiteSpace).ToString()
                };
                break;
            case "compression":
                config.Compression ??= ParseYesNoKeywordValue(keyword, ref remainder);
                break;

            case "tcpkeepalive":
                config.TcpKeepAlive ??= ParseYesNoKeywordValue(keyword, ref remainder);
                break;

            case "serveralivecountmax":
                config.ServerAliveCountMax ??= NextTokenAsInt(keyword, ref remainder);
                break;

            case "serveraliveinterval":
                config.ServerAliveInterval ??= NextTokenAsInt(keyword, ref remainder);
                break;

            /* The following options are unsupported,
               we have some basic handling that checks the option value indicates the feature is disabled */
            case "permitlocalcommand":
                ThrowUnsupportedWhenKeywordValueIsNot(keyword, ref remainder, "no");
                break;
            case "localcommand":
                break; // throw for permitlocalcommand.
            case "checkhostip":
                ThrowUnsupportedWhenKeywordValueIsNot(keyword, ref remainder, "no");
                break;
            case "canonicalizehostname":
                ThrowUnsupportedWhenKeywordValueIsNot(keyword, ref remainder, "no");
                // If this is implemented, it needs to set performSecondPass = true.
                break;
            case "canonicaldomains":
            case "canonicalizefallbacklocal":
            case "canonicalizemaxdots":
            case "canonicalizepermittedcnames":
                break; // throw for canonicalizehostname.
            case "clearallforwardings":
                ThrowUnsupportedWhenKeywordValueIsNot(keyword, ref remainder, "no");
                break;
            case "dynamicforward":
            case "exitonforwardfailure":
            case "forwardagent":
            case "forwardx11":
            case "forwardx11timeout":
            case "forwardx11trusted":
            case "gatewayports":
            case "localforward":
            case "permitremoteopen":
            case "remoteforward":
                break; // throw for clearallforwardings.
            case "passwordauthentication":
                ThrowUnsupportedWhenKeywordValueIsNot(keyword, ref remainder, "no");
                break;
            case "batchmode":
                ThrowUnsupportedWhenKeywordValueIsNot(keyword, ref remainder, "yes");
                break;
            case "kbdinteractiveauthentication":
                ThrowUnsupportedWhenKeywordValueIsNot(keyword, ref remainder, "yes");
                break;

            case "identitiesonly":
                config.IdentitiesOnly ??= ParseYesNoKeywordValue(keyword, ref remainder);
                break;

            /* Ignored options */
            // Logging related options
            case "loglevel":
            case "logverbose":
            case "syslogfacility":
            // Application/UX options
            case "enableescapecommandline":
            case "escapechar":
            case "requestty":
            case "sessiontype":
            case "stdinnull":
            case "forkafterauthentication":
            case "channeltimeout":
            case "obsecurekeystroketiming":
            case "visualhostkey":
            case "fingerprinthash":
            // Session sharing options
            case "controlmaster":
            case "controlsocket":
            case "controlpersist":
            // Unsupported options - support may be added later.
            case "verifyhostkeydns":        // DNS based key verification is not supported
            case "hostbasedauthentication": // host-based auth is not supported
            case "enablesshkeysign":        // host-based auth is not supported
            case "hostbasedacceptedalgorithms": // host-based auth is not supported
            case "connectionattempts":      // Only a single attempt is supported (currently)
            case "certificatefile":         // certificate based auth is not supported
            case "casignaturealgorithms":   // certificate based auth is not supported
            case "addkeystoagent":          // auth agent is not supported
            case "identityagent":           // auth agent is not supported
            case "pkcs11provider":          // not supported
            case "securitykeyprovider":     // not supported
            case "kbdinteractivedevices":   // keyboard-interactive auth is not supported
            case "gssapikeyexchange":       // gssapikeyexchange is not supported
            case "gssapikexalgorithms":     // gssapikeyexchange is not supported
            case "nohostauthenticationforlocalhost": // not supported
            case "updatehostkeys":          // unsupported. This is for updating the known hosts file with keys the server sends us
            case "ignoreunknown":           // unsupported.
                break;

            /* Unsupported options */
            // case "rekeylimit":
            // case "addressfamily":
            // case "bindaddress":
            // case "bindinterface":
            // case "ipqos":
            // case "streamlocalbindmask":
            // case "streamlocalbindunlink":
            // case "setenv":
            // case "tag":
            // case "proxycommand":
            // case "proxyjump":
            // case "hostkeyalias":
            // case "knownhostscommand":
            // case "revokedhostkeys":
            // case "remotecommand":
            default:
                ThrowUnsupportedKeyword(keyword, remainder);
                break;
        }
    }

    private static ReadOnlySpan<char> GetKeywordValue(scoped ReadOnlySpan<char> keyword, ref ReadOnlySpan<char> remainder)
    {
        if (!TryGetNextToken(ref remainder, out ReadOnlySpan<char> value))
        {
            throw new InvalidDataException($"Value for '{keyword}' can not be empty.");
        }

        return value;
    }

    private static AlgorithmList ReadAlgorithmList(ReadOnlySpan<char> keyword, ReadOnlySpan<char> remainder)
    {
        ReadOnlySpan<char> algorithms = GetKeywordValue(keyword, ref remainder);

        AlgorithmListOperation operation = AlgorithmListOperation.Set;
        string patternList = "";
        if (algorithms.StartsWith("+"))
        {
            operation = AlgorithmListOperation.Append;
            algorithms = algorithms.Slice(1);
        }
        else if (algorithms.StartsWith("-"))
        {
            operation = AlgorithmListOperation.Remove;
            patternList = algorithms.Slice(1).Trim(WhiteSpace).ToString();
            algorithms = default;
        }
        else if (algorithms.StartsWith("^"))
        {
            operation = AlgorithmListOperation.Prepend;
            algorithms = algorithms.Slice(1);
        }

        return new AlgorithmList()
        {
            Operation = operation,
            Algorithms = ParseNameList(algorithms),
            PatternList = patternList
        };
    }

    private static Name[] ParseNameList(ReadOnlySpan<char> list)
    {
        int itemCount = list.Count(',') + 1;
        Name[] items = new Name[itemCount];
        for (int i = 0; i < itemCount; i++)
        {
            int idx = list.IndexOf(',');
            items[i] = new Name(idx == -1 ? list : list.Slice(0, idx));
            list = list.Slice(idx + 1);
        }
        return items;
    }

    private static void ThrowUnsupportedKeyword(ReadOnlySpan<char> keyword, ReadOnlySpan<char> remainder)
    {
        throw new NotSupportedException($"Unsupported keyword: '{keyword}' (value: '{remainder}').");
    }

    private static bool ParseYesNoKeywordValue(scoped ReadOnlySpan<char> keyword, ref ReadOnlySpan<char> remainder)
    {
        ReadOnlySpan<char> value = GetKeywordValue(keyword, ref remainder);
        if (value.Equals("yes", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }
        else if (value.Equals("no", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }
        else
        {
            ThrowUnsupportedKeywordValue(keyword, value);
            return false; // unreachable
        }
    }

    private static void ThrowUnsupportedWhenKeywordValueIsNot(scoped ReadOnlySpan<char> keyword, ref ReadOnlySpan<char> remainder, ReadOnlySpan<char> expected)
    {
        if (!TryGetNextToken(ref remainder, out ReadOnlySpan<char> value) && value.Equals(expected, StringComparison.OrdinalIgnoreCase))
        {
            ThrowUnsupportedKeywordValue(keyword, value);
        }
    }

    private static void ThrowUnsupportedKeywordValue(ReadOnlySpan<char> keyword, ReadOnlySpan<char> value)
    {
        throw new NotSupportedException($"Unsupported value '{value}' for keyword '{keyword}'.");
    }

    private static int NextTokenAsInt(scoped ReadOnlySpan<char> keyword, ref ReadOnlySpan<char> remainder)
    {
        ReadOnlySpan<char> r = remainder;
        if (!TryGetNextToken(ref remainder, out ReadOnlySpan<char> value) ||
            !int.TryParse(value, CultureInfo.InvariantCulture, out int i))
        {
            throw new InvalidDataException($"Can not parse value '{r}' for keyword '{keyword}' as integer.");
        }
        return i;
    }

    private static string TildeExpand(ReadOnlySpan<char> path)
    {
        if (path.StartsWith("~"))
        {
            return Path.Join(Home, path.Slice(1).ToString());
        }
        return path.ToString();
    }

    private static IEnumerable<string> Glob(string pathPattern)
    {
        int globStartPos = pathPattern.IndexOfAny(['*', '?', '[', ']']);
        bool isGlobPattern = globStartPos >= 0;
        if (!isGlobPattern)
        {
            return [pathPattern];
        }

        if (pathPattern.IndexOfAny(['[', ']']) >= 0)
        {
            throw new NotSupportedException($"Glob pattern {pathPattern} is not supported.");
        }

        pathPattern = Path.GetFullPath(pathPattern);
        int separatorPos = pathPattern.AsSpan(0, globStartPos).LastIndexOfAny([Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar]);
        string basePath = pathPattern.Substring(0, separatorPos + 1);
        var fse = new FileSystemEnumerable<string>(basePath,
            transform: (ref FileSystemEntry entry) => entry.ToFullPath(),
            options: new System.IO.EnumerationOptions()
            {
                AttributesToSkip = 0,
                RecurseSubdirectories = true,
            }
        )
        {
            ShouldIncludePredicate = (ref FileSystemEntry entry) => PatternMatcher.IsPatternMatch(pathPattern.AsSpan(), entry.ToFullPath().AsSpan())
        };

        string[] paths = fse.ToArray();
        Array.Sort(paths, StringComparer.InvariantCulture);
        return paths;
    }

    private static bool IsMatchMatch(SshConfig config, string host, string originalhost, ReadOnlySpan<char> matchPattern, ref bool performSecondPass, bool isFinal)
    {
        bool hasMatches = false;

        if (config.HostName != null)
        {
            host = config.HostName; // TODO: TOKEN expand.
        }

        Span<char> attributeBuffer = stackalloc char[20];
        while (TryGetNextToken(ref matchPattern, out ReadOnlySpan<char> t))
        {
            int length = t.ToLowerInvariant(attributeBuffer);
            if (length == 0)
            {
                break;
            }
            // token is larger than buffer.
            if (length == -1)
            {
                throw new NotImplementedException($"Unsupported attribute: {t.ToString()}");
            }
            ReadOnlySpan<char> attribute = attributeBuffer.Slice(0, length);
            bool negate = attribute[0] == '!';
            if (negate)
            {
                attribute = attribute.Slice(1);
            }

            bool isMatch;
            switch (attribute)
            {
                case "all":
                    isMatch = true;
                    break;
                case "final":
                    isMatch = isFinal;
                    performSecondPass = true;
                    break;
                case "canonical":
                    isMatch = isFinal;
                    break;
                default:
                    if (!TryGetNextToken(ref matchPattern, out ReadOnlySpan<char> arg))
                    {
                        throw new InvalidDataException($"Argument value expected for {attribute.ToString()}");
                    }
                    switch (attribute)
                    {
                        case "host":
                            isMatch = PatternMatcher.IsPatternListMatch(arg, host);
                            break;
                        case "originalhost":
                            isMatch = PatternMatcher.IsPatternListMatch(arg, originalhost);
                            break;
                        case "user":
                            isMatch = PatternMatcher.IsPatternListMatch(arg, config.UserName ?? Environment.UserName);
                            break;
                        case "localuser":
                            isMatch = PatternMatcher.IsPatternListMatch(arg, Environment.UserName);
                            break;
                        case "tagged":
                        case "exec": // note: TOKEN expand.
                        default:
                            throw new NotImplementedException($"Unsupported attribute: {attribute.ToString()}");
                    }
                    break;
            }
            // Return 'false' when there is no match, or a match that is negated.
            if (isMatch == negate)
            {
                return false;
            }

            hasMatches = true;
        }

        return hasMatches;
    }

    static string? NextTokenAsStringOrDefault(ref ReadOnlySpan<char> remainder)
    {
        if (TryGetNextToken(ref remainder, out ReadOnlySpan<char> token))
        {
            return token.ToString();
        }
        else
        {
            return null;
        }
    }

    static bool TryGetNextToken(ref ReadOnlySpan<char> remainder, out ReadOnlySpan<char> token)
    {
        if (remainder.StartsWith("\""))
        {
            remainder = remainder.Slice(1);
            int closingPos = remainder.IndexOf('"');
            if (closingPos == -1)
            {
                token = remainder;
                remainder = default;
                return true;
            }
            else
            {
                token = remainder.Slice(0, closingPos);
                remainder = remainder.Slice(closingPos + 1);
                remainder = remainder.TrimStart(WhiteSpace);
                return true;
            }
        }
        else
        {
            int closingPos = remainder.IndexOfAny($"{WhiteSpace}\"=");
            if (closingPos == -1)
            {
                token = remainder;
                remainder = default;
                return !token.IsEmpty;
            }
            else
            {
                token = remainder.Slice(0, closingPos);
                remainder = remainder.Slice(closingPos);
                remainder = remainder.TrimStart(WhiteSpace);
                if (remainder.Length > 0 && remainder[0] == '=')
                {
                    remainder = remainder.Slice(1);
                    remainder = remainder.TrimStart(WhiteSpace);
                }
                return true;
            }
        }
    }
}


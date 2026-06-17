using System.CommandLine;
using System.CommandLine.Help;
using System.Diagnostics;
using Microsoft.Extensions.Logging;
using Tmds.Ssh;

var sourcesArgs = new Argument<string[]>("source")
{
    Description = $"Source path(s){Environment.NewLine}- To copy a file or directory, leave the source path without a trailing '/'{Environment.NewLine}- To copy the *contents* of a directory, add a trailing '/' to the path{Environment.NewLine}To copy from a remote system, prefix the path with '<ssh destination>:'. For example: 'user@host.com:/home/user/file'",
    Arity = ArgumentArity.OneOrMore
};
var destArg = new Argument<string[]>("destination")
{
    Description = $"Destination path{Environment.NewLine}- When the '-n' option is *not* specified, the directory path to copy to.{Environment.NewLine}- When the '-n' option is specified, the path includes the target name for the file or directory{Environment.NewLine}  This allows renaming the file or directory. Only a single source can be specified{Environment.NewLine}The destination directory and its parents are created if they don’t exist{Environment.NewLine}To copy to a remote system, prefix the path with '<ssh destination>:'. For example: 'user@host.com:/tmp'",
    Arity = ArgumentArity.ExactlyOne
};
var pathsArg = new Argument<string[]>("paths")
{
    Arity = ArgumentArity.OneOrMore
};
var overwriteOption = new Option<bool>("-o", ["--overwrite"])
{
    Description = "Overwrites existing files"
};
var renameOption = new Option<bool>("-n")
{
    Description = "Treat the destination as a path including the filename/directory name (for renaming)"
};
var informationVerbosityOption = new Option<bool>("-v")
{
    Description = "Log at information level"
};
var debugVerbosityOption = new Option<bool>("-vv")
{
    Description = "Log at debug level"
};
var traceVerbosityOption = new Option<bool>("-vvv")
{
    Description = "Log at trace level"
};
var sshConfigOptions = new Option<string[]>("--ssh-option")
{
    Description = $"Set an SSH Config option, for example: Ciphers=chacha20-poly1305@openssh.com{Environment.NewLine}Supported options: {string.Join(", ", Enum.GetValues<SshConfigOption>().Select(o => o.ToString()))}",
    Arity = ArgumentArity.ZeroOrMore
};

var rootCommand = new RootCommand("Copy files between hosts using SSH/SFTP");
rootCommand.Options.Add(overwriteOption);
rootCommand.Options.Add(renameOption);
rootCommand.Options.Add(sshConfigOptions);
rootCommand.Options.Add(informationVerbosityOption);
rootCommand.Options.Add(debugVerbosityOption);
rootCommand.Options.Add(traceVerbosityOption);
for (int i = 0; i < rootCommand.Options.Count; i++)
{
    // RootCommand has a default HelpOption, we need to update its Action.
    if (rootCommand.Options[i] is HelpOption defaultHelpOption)
    {
        defaultHelpOption.Action = new CustomHelpAction((HelpAction)defaultHelpOption.Action!);
        break;
    }
}


// System.CommandLine is greedy, it doesn't support requiring a single destination argument as the last argument.
if (IsHelp(args))
{
    // Show these as separate arguments in help.
    rootCommand.Arguments.Add(sourcesArgs);
    rootCommand.Arguments.Add(destArg);
}
else
{
    rootCommand.Arguments.Add(pathsArg);
}

rootCommand.SetAction(
(ParseResult parseResult, CancellationToken ct) =>
{
    string[] paths = parseResult.GetValue(pathsArg)!;
    bool informationVerbosity = parseResult.GetValue(informationVerbosityOption);
    bool debugVerbosity = parseResult.GetValue(debugVerbosityOption);
    bool traceVerbosity = parseResult.GetValue(traceVerbosityOption);
    bool overwrite = parseResult.GetValue(overwriteOption);
    bool includesName = parseResult.GetValue(renameOption);
    string[] options = parseResult.GetValue(sshConfigOptions)!;
    return CopyAsync(paths, informationVerbosity, debugVerbosity, traceVerbosity, options, overwrite, includesName)
        .ContinueWith(task => task.Result, ct);
});

try
{
    ParseResult parseResult = rootCommand.Parse(args);
    return await parseResult.InvokeAsync();
}
catch (Exception ex)
{
    Console.Error.WriteLine("The command failed:");
    Console.Error.WriteLine(ex);
    return 1;
}

bool IsHelp(string[] args)
{
    if (args.Length < 2) // source and destination arg are required
    {
        return true;
    }
    var helpOption = new HelpOption();
    if (args.Contains(helpOption.Name))
    {
        return true;
    }
    foreach (var alias in helpOption.Aliases)
    {
        if (args.Contains(alias))
        {
            return true;
        }
    }
    return false;
}

static async Task<int> CopyAsync(string[] paths, bool informationVerbosity, bool debugVerbosity, bool traceVerbosity, string[] options, bool overwrite, bool includesName)
{
    if (paths.Length < 2)
    {
        Console.Error.WriteLine("Arguments must at least include a source and a destination.");
        return 1;
    }

    string[] sources = paths[..^1].ToArray();
    string destination = paths[^1];
    Location destinationLocation = Location.Parse(destination);

    if (includesName && sources.Length > 1)
    {
        Console.Error.WriteLine("The '-n' option is specified but multiple sources are provided. Only a single source may be specified when the '-n' option is used.");
        return 1;
    }

    foreach (var source in sources)
    {
        Location sourceLocation = Location.Parse(source);
        if (sourceLocation.IsLocal == true && destinationLocation.IsLocal == true)
        {
            Console.Error.WriteLine("Cannot perform local copies.");
            return 1;
        }
        if (sourceLocation.IsLocal == false && destinationLocation.IsLocal == false)
        {
            Console.Error.WriteLine("Cannot perform remote copies.");
            return 1;
        }
    }

    LogLevel logLevel;
    if (traceVerbosity)
    {
        logLevel = LogLevel.Trace;
    }
    else if (debugVerbosity)
    {
        logLevel = LogLevel.Debug;
    }
    else if (informationVerbosity)
    {
        logLevel = LogLevel.Information;
    }
    else
    {
        logLevel = LogLevel.None;
    }

    using ILoggerFactory? loggerFactory = logLevel == LogLevel.None ? null :
        LoggerFactory.Create(builder =>
        {
            builder.AddConsole();
            builder.SetMinimumLevel(logLevel);
        });

    return await DoCopyAsync(sources, destinationLocation, options, loggerFactory, overwrite, includesName);
}

static async Task<int> DoCopyAsync(string[] sources, Location destinationLocation, string[] options, ILoggerFactory? loggerFactory, bool overwrite, bool includesName)
{
    Dictionary<string, SftpClient> clients = new();

    foreach (var source in sources)
    {
        Location sourceLocation = Location.Parse(source);
        string sshDestination = (sourceLocation.IsLocal ? destinationLocation : sourceLocation).SshDestination!;

        SftpClient sftpClient = await GetConnectedClientAsync(clients, sshDestination, options, loggerFactory);

        var progress = new ConsoleProgress();
        Task<int> transferOperation = sourceLocation.IsLocal
            ? UploadAsync(sourceLocation.Path, sftpClient, destinationLocation.Path, overwrite, includesName, progress)
            : DownloadAsync(sftpClient, sourceLocation.Path, destinationLocation.Path, overwrite, includesName, progress);

        if (!Console.IsOutputRedirected && progress.IsStarted /* when a transfer was started */)
        {
            await progress.WriteProgressToConsoleAsync();
        }

        int rv = await transferOperation;
        if (rv != 0)
        {
            // Failed, don't continue with other sources.
            return rv;
        }
    }

    return 0;
}

static async ValueTask<SftpClient> GetConnectedClientAsync(Dictionary<string, SftpClient> clients, string sshDestination, string[] options, ILoggerFactory? loggerFactory)
{
    if (!clients.TryGetValue(sshDestination, out SftpClient? sftpClient))
    {
        SshConfigSettings configSettings = CreateSshConfigSettings(options);
        sftpClient = new SftpClient(sshDestination, configSettings, loggerFactory);
        await sftpClient.ConnectAsync();
        clients[sshDestination] = sftpClient;
    }
    return sftpClient;
}

static async Task<int> DownloadAsync(SftpClient sftpClient, string remoteSourcePath, string targetPath, bool overwrite, bool includesName, SftpProgressHandler? progress)
{
    string sourceFileName = GetRemoteFileName(remoteSourcePath);
    bool copyEntries = sourceFileName == "." || sourceFileName == "";

    if (includesName && copyEntries)
    {
        Console.Error.WriteLine("The '-n' option is specified but the source ends with a trailing slash to copy multiple directory entries.");
        return 1;
    }

    var sourceAttributes = await sftpClient.GetAttributesAsync(remoteSourcePath, followLinks: true);
    if (sourceAttributes is null)
    {
        Console.Error.WriteLine($"Source '{remoteSourcePath}' is not found.");
        return 1;
    }

    switch (sourceAttributes.FileType)
    {
        case UnixFileType.Directory:
            if (!copyEntries && !includesName)
            {
                targetPath = Path.Join(targetPath, sourceFileName);
            }
            await sftpClient.DownloadDirectoryEntriesAsync(remoteSourcePath, targetPath, new() { Overwrite = overwrite }, progress);
            break;
        case UnixFileType.RegularFile:
            if (copyEntries)
            {
                Console.Error.WriteLine($"'{remoteSourcePath}' is a file but the path ends with a trailing slash. To copy a file, remove the trailing slash.");
                return 1;
            }
            Directory.CreateDirectory(includesName ? Path.GetDirectoryName(targetPath)! : targetPath);
            if (!includesName)
            {
                targetPath = Path.Join(targetPath, sourceFileName);
            }
            await sftpClient.DownloadFileAsync(remoteSourcePath, targetPath, overwrite, progress);
            break;
        default:
            Console.Error.WriteLine($"Cannot copy file of type {sourceAttributes.FileType}.");
            return 1;
    }

    return 0;

    static string GetRemoteFileName(string remoteSourcePath)
    {
        int pathSeparatorIndex = remoteSourcePath.IndexOf('/');
        if (pathSeparatorIndex >= 0)
        {
            return remoteSourcePath.Substring(pathSeparatorIndex + 1);
        }
        return remoteSourcePath;
    }
}

static async Task<int> UploadAsync(string localSourcePath, SftpClient sftpClient, string remoteDestinationPath, bool overwrite, bool includesName, SftpProgressHandler? progress)
{
    string sourceFileName = Path.GetFileName(localSourcePath);
    bool copyEntries = sourceFileName == "." || sourceFileName == "";
    if (includesName && copyEntries)
    {
        Console.Error.WriteLine("The '-n' option is specified but the source ends with a trailing slash to copy multiple directory entries.");
        return 1;
    }

    bool sourceIsDir = Directory.Exists(localSourcePath);

    if (sourceIsDir)
    {
        if (!copyEntries && !includesName)
        {
            remoteDestinationPath = RemotePathCombine(remoteDestinationPath, sourceFileName);
        }
        await sftpClient.UploadDirectoryEntriesAsync(localSourcePath, remoteDestinationPath, new() { Overwrite = overwrite }, progress);
    }
    else
    {
        if (copyEntries)
        {
            Console.Error.WriteLine($"'{localSourcePath}' is a file but the path ends with a trailing slash. To copy a file, remove the trailing slash.");
            return 1;
        }
        ValueTask createDir = sftpClient.CreateDirectoryAsync(includesName ? GetRemoteDirectoryName(remoteDestinationPath) : remoteDestinationPath);
        if (!includesName)
        {
            remoteDestinationPath = RemotePathCombine(remoteDestinationPath, sourceFileName);
        }
        try
        {
            await sftpClient.UploadFileAsync(localSourcePath, remoteDestinationPath, overwrite, createPermissions: null, progress);
        }
        finally
        {
            try
            {
                await createDir;
            }
            catch
            { }
        }
    }

    return 0;

    static string RemotePathCombine(string path1, string path2)
    {
        if (string.IsNullOrEmpty(path1))
        {
            return path2;
        }
        if (string.IsNullOrEmpty(path2))
        {
            return path1;
        }
        return $"{path1}/{path2}";
    }


    static string GetRemoteDirectoryName(string remoteSourcePath)
    {
        int pathSeparatorIndex = remoteSourcePath.IndexOf('/');
        if (pathSeparatorIndex >= 0)
        {
            return remoteSourcePath.Substring(0, pathSeparatorIndex);
        }
        return remoteSourcePath;
    }
}

static SshConfigSettings CreateSshConfigSettings(string[] options)
{
    SshConfigSettings configSettings = new SshConfigSettings();

    Dictionary<SshConfigOption, SshConfigOptionValue> optionsDict = new();
    foreach (var option in options)
    {
        string[] split = option.Split('=', 2);
        if (split.Length != 2)
        {
            throw new ArgumentException($"Option '{option}' is not in the <Key>=<Value> format.");
        }
        if (Enum.TryParse<SshConfigOption>(split[0], ignoreCase: true, out var key))
        {
            optionsDict[key] = split[1];
        }
        else
        {
            throw new ArgumentException($"Unsupported option: {option}.");
        }
    }
    configSettings.Options = optionsDict;

    configSettings.PasswordPrompt = (PasswordPromptContext ctx, CancellationToken ct) =>
    {
        if (ctx.IsBatchMode)
        {
            return ValueTask.FromResult((string?)null);
        }

        if (ctx.Attempt > 1)
        {
            Console.WriteLine("Permission denied, please try again.");
        }

        string prompt = $"{ctx.ConnectionInfo.UserName}@{ctx.ConnectionInfo.HostName}'s password: ";
        return ReadPasswordFromConsole(prompt);
    };

    configSettings.HostAuthentication = (HostAuthenticationContext ctx, CancellationToken ct) =>
    {
        if (ctx.IsBatchMode)
        {
            return ValueTask.FromResult(false);
        }

        if (Console.IsInputRedirected || Console.IsOutputRedirected)
        {
            return ValueTask.FromResult(false);
        }

        PublicKey key = ctx.ConnectionInfo.ServerKey.Key;
        string hostName = ctx.ConnectionInfo.HostName;
        string keyType = key.Type.ToUpperInvariant();
        if (keyType.StartsWith("SSH-"))
        {
            keyType = keyType.Substring(4);
        }
        string fingerprint = key.SHA256FingerPrint;
        Console.WriteLine($"The authenticity of host '{hostName}' can't be established.");
        Console.WriteLine($"{keyType} key fingerprint is SHA256:{fingerprint}.");
        while (true)
        {
            Console.Write($"Are you sure you want to continue connecting (yes/no)? ");
            string? response = Console.ReadLine();
            switch (response)
            {
                case "no":
                case null:
                    return ValueTask.FromResult(false);
                case "yes":
                    return ValueTask.FromResult(true);
                default:
                    continue;
            }
        }
    };

    return configSettings;
}

static ValueTask<string?> ReadPasswordFromConsole(string? prompt = null)
{
    if (Console.IsInputRedirected || Console.IsOutputRedirected)
    {
        return ValueTask.FromResult((string?)null);
    }

    if (!string.IsNullOrEmpty(prompt))
    {
        Console.Write(prompt);
    }

    var password = string.Empty;
    ConsoleKeyInfo key;
    do
    {
        key = Console.ReadKey(intercept: true);
        if (key.Key == ConsoleKey.Enter)
        {
            Console.WriteLine();
            break;
        }
        else if (key.Key == ConsoleKey.Backspace)
        {
            if (password.Length > 0)
            {
                password = password[..^1];
            }
        }
        else if (key.KeyChar != '\0')
        {
            password += key.KeyChar;
        }
    } while (true);
    return ValueTask.FromResult((string?)password);
}

sealed class Location
{
    public bool IsLocal => SshDestination is null;
    public required string? SshDestination { get; init; }
    public required string Path { get; init; }

    public static Location Parse(string value)
    {
        int colonPos = value.IndexOf(':');
        if (colonPos != -1)
        {
            return new Location
            {
                SshDestination = value.Substring(0, colonPos),
                Path = value.Substring(colonPos + 1)
            };
        }
        else
        {
            return new Location
            {
                SshDestination = null,
                Path = value
            };
        }
    }
}

sealed class ConsoleProgress : SftpProgressHandler
{
    private const int RefreshInterval = 100; // Refresh the output every 100ms.
    private const int SampleCount = 50; // ~5 seconds at 100ms interval

    private readonly TaskCompletionSource _completed = new();

    private long _startTime;
    private long _endTime;
    private long _totalBytesTransferred;
    private int _discoveredEntries;
    private int _completedEntries;
    private bool _allDiscovered;
    private Exception? _exception;

    private readonly (long timestamp, long bytes)[] _samples = new (long, long)[SampleCount];
    private int _sampleIndex;
    private int _samplesFilled;
    public bool IsStarted => _startTime != 0;

    private TimeSpan ElapsedTime
    {
        get
        {
            long endTime = Volatile.Read(ref _endTime);
            if (endTime == 0)
            {
                endTime = Stopwatch.GetTimestamp();
                if (_completed.Task.IsCompleted)
                {
                    endTime = Volatile.Read(ref _endTime);
                }
            }
            return Stopwatch.GetElapsedTime(_startTime, endTime);
        }
    }

    protected override void Start()
        => _startTime = Stopwatch.GetTimestamp();

    protected override void EntryStart(int index, UnixFileType type, Entry entry)
    {
        if (type == UnixFileType.RegularFile)
        {
            Interlocked.Increment(ref _discoveredEntries);
        }
    }

    protected override void DataTransferred(int index, long bytesTransferred, long offset)
        => Interlocked.Add(ref _totalBytesTransferred, bytesTransferred);

    protected override void EntriesDiscovered()
        => Volatile.Write(ref _allDiscovered, true);

    protected override void EntryCompleted(int index, UnixFileType type)
    {
        if (type == UnixFileType.RegularFile)
        {
            Interlocked.Increment(ref _completedEntries);
        }
    }

    protected override void Completed(Exception? exception)
    {
        Volatile.Write(ref _exception, exception);
        Volatile.Write(ref _endTime, Stopwatch.GetTimestamp());
        _completed.TrySetResult();
    }

    public async Task WriteProgressToConsoleAsync()
    {
        if (!IsStarted)
        {
            throw new InvalidOperationException("Progress handler has not been started.");
        }

        while (true)
        {
            bool isCompleted = _completed.Task.IsCompleted;

            long now = Stopwatch.GetTimestamp();
            long transferred = Volatile.Read(ref _totalBytesTransferred);
            bool allDiscovered = Volatile.Read(ref _allDiscovered);
            int completed = Volatile.Read(ref _completedEntries);
            int discovered = Volatile.Read(ref _discoveredEntries);

            RecordSample(now, transferred);

            if (isCompleted)
            {
                if (Volatile.Read(ref _exception) is null)
                {
                    ClearLine();
                    if (discovered > 0)
                    {
                        TimeSpan elapsed = ElapsedTime;
                        string speed = FormatAverageSpeed(transferred, elapsed);
                        string fileWord = completed == 1 ? "file" : "files";
                        WriteProgressLine($"Finished copying {completed} {fileWord} in {FormatElapsed(elapsed)}", $"{FormatSize(transferred, 10)}  {speed,12}");
                        Console.WriteLine();
                    }
                }
                else
                {
                    ClearLine();
                }
                break;
            }

            if (discovered > 0)
            {
                string suffix = allDiscovered ? "" : "+";
                string speed = FormatCurrentSpeed();
                string fileWord = discovered == 1 ? "file" : "files";
                WriteProgressLine($"Copied {completed} out of {discovered}{suffix} {fileWord}...", $"{FormatSize(transferred, 10)}  {speed,12}");
            }

            await Task.WhenAny(_completed.Task, Task.Delay(RefreshInterval));
        }
    }

    private void RecordSample(long timestamp, long totalBytes)
    {
        _samples[_sampleIndex] = (timestamp, totalBytes);
        _sampleIndex = (_sampleIndex + 1) % SampleCount;
        if (_samplesFilled < SampleCount)
        {
            _samplesFilled++;
        }
    }

    private string FormatCurrentSpeed()
    {
        if (_samplesFilled < 2)
        {
            return "?/s";
        }
        int oldestIndex = _samplesFilled < SampleCount ? 0 : _sampleIndex;
        var oldest = _samples[oldestIndex];
        var newest = _samples[(_sampleIndex - 1 + SampleCount) % SampleCount];
        double windowSeconds = Stopwatch.GetElapsedTime(oldest.timestamp, newest.timestamp).TotalSeconds;
        double bytesPerSecond = (newest.bytes - oldest.bytes) / windowSeconds;
        return $"{FormatSize(bytesPerSecond)}/s";
    }

    private static void ClearLine()
    {
        Console.Write($"\r{new string(' ', Console.WindowWidth - 1)}\r");
    }

    private static string FormatAverageSpeed(long bytes, TimeSpan elapsed)
    {
        if (elapsed.TotalSeconds < 0.001)
        {
            return "?/s";
        }
        double bytesPerSecond = bytes / elapsed.TotalSeconds;
        return $"{FormatSize(bytesPerSecond)}/s";
    }

    private static readonly string[] s_sizeUnits = ["bytes", "KiB", "MiB", "GiB", "TiB"];

    private static string FormatSize(double bytes, int padTo = 0)
    {
        int unit = 0;
        double size = bytes;
        while (size >= 1024 && unit < s_sizeUnits.Length - 1)
        {
            size /= 1024;
            unit++;
        }
        string result = unit == 0 ? $"{(int)size} {s_sizeUnits[unit]}" : $"{size:F1} {s_sizeUnits[unit]}";
        return padTo > 0 ? result.PadLeft(padTo) : result;
    }

    private static string FormatElapsed(TimeSpan elapsed)
    {
        return elapsed.TotalHours >= 1 ? elapsed.ToString(@"h\:mm\:ss")
             : elapsed.TotalMinutes >= 1 ? elapsed.ToString(@"m\:ss")
             : $"{elapsed.TotalSeconds:F1}s";
    }

    private static void WriteProgressLine(string left, string right)
    {
        int width = Console.WindowWidth - 1;
        int padding = width - left.Length - right.Length;
        ClearLine();
        if (padding >= 1)
        {
            Console.Write($"{left}{new string(' ', padding)}{right}");
        }
        else
        {
            Console.Write(left);
        }
    }
}

internal class CustomHelpAction : System.CommandLine.Invocation.SynchronousCommandLineAction
{
    private readonly HelpAction _defaultHelp;

    public CustomHelpAction(HelpAction action) => _defaultHelp = action;

    public override int Invoke(ParseResult parseResult)
    {
        int result = _defaultHelp.Invoke(parseResult);

        Console.WriteLine("Examples:");
        Console.WriteLine("  $ ssh-cp file.txt user@host:/tmp               # Copy local file to remote");
        Console.WriteLine("  $ ssh-cp dir/ user@host:/tmp/dir-copy          # Copy contents of dir to remote");
        Console.WriteLine("  $ ssh-cp user@host:/tmp/file.txt ./local-dir   # Copy remote file to local");
        Console.WriteLine("  $ ssh-cp -n file.txt user@host:dir/newname.txt # Rename file during copy");

        return result;

    }
}

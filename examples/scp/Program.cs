using Tmds.Ssh;

if (args.Length < 2)
{
    Console.Error.WriteLine("Specify a source and target argument.");
    return 1;
}

Location source = Location.Parse(args[0]);
Location destination = Location.Parse(args[1]);

if (source.IsLocal == true && destination.IsLocal == true)
{
    Console.Error.WriteLine("Cannot perform local copies.");
    return 1;
}
if (source.IsLocal == false && destination.IsLocal == false)
{
    Console.Error.WriteLine("Cannot perform remote copies.");
    return 1;
}

string sshDestination = source.SshDestination ?? destination.SshDestination!;

using SshClient client = new SshClient(sshDestination, SshConfigOptions.Default);

await client.ConnectAsync();

using SftpClient sftpClient = await client.OpenSftpClientAsync();

if (source.IsLocal)
{
    bool isDirectory = Directory.Exists(source.Path);

    if (isDirectory)
    {
        await sftpClient.CreateDirectoryAsync(destination.Path);
        await sftpClient.UploadDirectoryEntriesAsync(source.Path, destination.Path);
    }
    else
    {
        await sftpClient.UploadFileAsync(source.Path, destination.Path);
    }
}
else
{
    var attributes = await sftpClient.GetAttributesAsync(source.Path, followLinks: true);
    if (attributes is null)
    {
        Console.Error.WriteLine($"Source '{source.Path}' is not found.");
        return 1;
    }

    switch (attributes.FileType)
    {
        case UnixFileType.Directory:
            Directory.CreateDirectory(destination.Path);
            await sftpClient.DownloadDirectoryEntriesAsync(source.Path, destination.Path);
            break;
        case UnixFileType.RegularFile:
            await sftpClient.DownloadFileAsync(source.Path, destination.Path);
            break;
        default:
            Console.Error.WriteLine($"Cannot copy file of type {attributes.FileType}.");
            return 1;

    }
}

return 0;

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
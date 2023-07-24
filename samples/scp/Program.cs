using Tmds.Ssh;

if (args.Length < 2)
{
    Console.Error.WriteLine("Specify a source and target argument.");
    return 1;
}

Location source = Location.Parse(args[0]);
Location destination = Location.Parse(args[1]);

if (source.IsLocal == destination.IsLocal)
{
    if (source.IsLocal)
    {
        Console.Error.WriteLine("Cannot copy between local directories.");
    }
    else
    {
        Console.Error.WriteLine("Cannot copy between remote directories.");
    }
    return 1;
}

string sshDestination = source.SshDestination ?? destination.SshDestination;

using SshClient client = new SshClient(sshDestination);

await client.ConnectAsync();

using SftpClient sftpClient = await client.CreateSftpClientAsync();

if (source.IsLocal)
{
    await sftpClient.CreateDirectoryAsync(destination.Path);
    await sftpClient.UploadDirectoryEntriesAsync(source.Path, destination.Path);
}
else
{
    Directory.CreateDirectory(destination.Path);
    await sftpClient.DownloadDirectoryEntriesAsync(source.Path, destination.Path);
}

return 0;

sealed class Location
{
    public bool IsLocal => SshDestination is null;
    public string? SshDestination { get; init; }
    public string Path { get; init; }

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
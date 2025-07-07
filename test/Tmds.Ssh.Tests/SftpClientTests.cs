using Xunit;
using Xunit.Sdk;

namespace Tmds.Ssh.Tests;

[Collection(nameof(SshServerCollection))]
public class SftpClientTests
{
    const int PacketSize = 32768; // roughly amount of bytes sent/received in a regular single sftp packet.
    const int MultiPacketSize = 2 * 256 * 1024 + 1024; // Requires multiple packets on OpenSSH with default limits@openssh.com config.

    private readonly SshServer _sshServer;
    private readonly ITestOutputHelper _output;

    private void WriteMessage(string message)
    {
        _output.WriteLine(message);
    }

    public SftpClientTests(SshServer sshServer, ITestOutputHelper output)
    {
        _sshServer = sshServer;
        _output = output;
    }

    [Fact]
    public async Task OpenSftpClientAsync()
    {
        using var client = await _sshServer.CreateClientAsync();
        using var sftpClient = await client.OpenSftpClientAsync();

        await sftpClient.GetRealPathAsync("");

        sftpClient.Dispose();
        Assert.True(sftpClient.IsDisposed);
        Assert.False(client.IsDisposed);
    }

    [Fact]
    public async Task WorkingDirectoryPath()
    {
        using var client = await _sshServer.CreateClientAsync();
        using var sftpClient = await client.OpenSftpClientAsync();

        Assert.Equal(_sshServer.TestUserHome, sftpClient.WorkingDirectory.Path);
    }

    [Fact]
    public async Task SftpDirectoryUsesRelativePaths()
    {
        using var client = await _sshServer.CreateClientAsync();
        using var sftpClient = await client.OpenSftpClientAsync();

        string directoryPath = $"/tmp/{Path.GetRandomFileName()}";

        // Directory itself.
        var sftpDirectory = sftpClient.GetDirectory(directoryPath);
        foreach (var path in new[] { ".", "", directoryPath })
        {
            FileEntryAttributes? attributes = await sftpDirectory.GetAttributesAsync(path);
            Assert.Null(attributes);
        }

        await sftpDirectory.CreateNewDirectoryAsync("");

        foreach (var path in new[] { ".", "", directoryPath })
        {
            FileEntryAttributes? attributes = await sftpDirectory.GetAttributesAsync(path);
            Assert.NotNull(attributes);
        }

        // File in the directory.
        string fileName = Path.GetRandomFileName();
        var file = await sftpDirectory.CreateNewFileAsync(fileName, FileAccess.Write);
        file.Dispose();

        foreach (var path in new[] { fileName, $"{directoryPath}/{fileName}" })
        {
            FileEntryAttributes? attributes = await sftpDirectory.GetAttributesAsync(path);
            Assert.NotNull(attributes);
        }
        {
            FileEntryAttributes? attributes = await sftpClient.GetAttributesAsync($"{directoryPath}/{fileName}");
            Assert.NotNull(attributes);
        }
    }

    [Fact]
    public async Task GetDirectoryResolvesPaths()
    {
        using var client = await _sshServer.CreateClientAsync();
        using var sftpClient = await client.OpenSftpClientAsync();

        SftpDirectory dir = sftpClient.GetDirectory("/base");

        Assert.Equal("/base/relative", dir.GetDirectory("relative").Path);
        Assert.Equal("/absolute", dir.GetDirectory("/absolute").Path);
    }

    [Fact]
    public async Task SftpClientCtorFromSshClient()
    {
        using var client = await _sshServer.CreateClientAsync();
        using var sftpClient = new SftpClient(client);

        await sftpClient.GetRealPathAsync("");

        sftpClient.Dispose();
        Assert.True(sftpClient.IsDisposed);
        Assert.False(client.IsDisposed);
    }

    [Fact]
    public async Task SftpClientCtorFromSshClientSettings()
    {
        using var sftpClient = new SftpClient(_sshServer.CreateSshClientSettings());

        await sftpClient.GetRealPathAsync("");

        sftpClient.Dispose();
        Assert.True(sftpClient.IsDisposed);
        Assert.True(sftpClient.SshClient.IsDisposed);
    }

    [InlineData(10)]
    [InlineData(10 * 1024)] // 10 kiB
    [InlineData(MultiPacketSize)]
    [Theory]
    public async Task ReadWriteFile(int fileSize)
    {
        using var sftpClient = await _sshServer.CreateSftpClientAsync();
        string filename = $"/tmp/{Path.GetRandomFileName()}";

        byte[] writeBuffer = new byte[fileSize];

        using var writeFile = await sftpClient.CreateNewFileAsync(filename, FileAccess.Write);
        Random.Shared.NextBytes(writeBuffer);
        await writeFile.WriteAsync(writeBuffer.AsMemory(0, fileSize));
        Assert.Equal(fileSize, writeFile.Position);
        await writeFile.CloseAsync();

        byte[] receiveBuffer = new byte[fileSize + 10];

        using var readFile = await sftpClient.OpenFileAsync(filename, FileAccess.Read);
        Assert.NotNull(readFile);
        int bytesReceived = 0;
        int bytesRead = 0;
        while (bytesReceived < fileSize)
        {
            bytesRead = await readFile.ReadAsync(receiveBuffer);
            Assert.Equal(writeBuffer.AsSpan(bytesReceived, bytesRead).ToArray(), receiveBuffer.AsSpan(0, bytesRead).ToArray());
            bytesReceived += bytesRead;
        }
        bytesRead = await readFile.ReadAsync(receiveBuffer);
        Assert.Equal(0, bytesRead);
        Assert.Equal(fileSize, bytesReceived);
        Assert.Equal(fileSize, readFile.Position);
        await readFile.CloseAsync();
    }

    [Fact]
    public async Task CreateDeleteDirectory()
    {
        using var sftpClient = await _sshServer.CreateSftpClientAsync();
        string path = $"/tmp/{Path.GetRandomFileName()}";

        await sftpClient.CreateNewDirectoryAsync(path);

        var attributes = await sftpClient.GetAttributesAsync(path);
        Assert.NotNull(attributes);
        Assert.Equal(UnixFileType.Directory, attributes.FileType);

        await sftpClient.DeleteDirectoryAsync(path);
        attributes = await sftpClient.GetAttributesAsync(path);
        Assert.Null(attributes);
    }

    [Fact]
    public async Task DeleteDirectoryDefaultIsNotRecursive()
    {
        using var sftpClient = await _sshServer.CreateSftpClientAsync();

        string directoryPath = $"/tmp/{Path.GetRandomFileName()}";
        await sftpClient.CreateNewDirectoryAsync(directoryPath);
        await sftpClient.CreateDirectoryAsync($"{directoryPath}/child1");

        await Assert.ThrowsAsync<SftpException>(async () => await sftpClient.DeleteDirectoryAsync(directoryPath));
    }

    [Fact]
    public async Task DeleteDirectoryRecursive()
    {
        using var sftpClient = await _sshServer.CreateSftpClientAsync();

        string directoryPath = $"/tmp/{Path.GetRandomFileName()}";
        await sftpClient.CreateNewDirectoryAsync(directoryPath);
        await sftpClient.CreateDirectoryAsync($"{directoryPath}/child1");
        await sftpClient.CreateDirectoryAsync($"{directoryPath}/child1/grandchild1");
        await sftpClient.CreateDirectoryAsync($"{directoryPath}/child1/grandchild2");
        using var file1 = await sftpClient.CreateNewFileAsync($"{directoryPath}/child1/grandchild2/file1", FileAccess.Write);
        await file1.CloseAsync();
        await sftpClient.CreateDirectoryAsync($"{directoryPath}/child2");
        using var file2 = await sftpClient.CreateNewFileAsync($"{directoryPath}/file2", FileAccess.Write);
        await file2.CloseAsync();
        await sftpClient.CreateDirectoryAsync($"{directoryPath}/child2/grandchild1");
        await sftpClient.CreateDirectoryAsync($"{directoryPath}/child2/grandchild2");

        await sftpClient.DeleteDirectoryAsync(directoryPath, recursive: true);

        var attributes = await sftpClient.GetAttributesAsync(directoryPath);
        Assert.Null(attributes);
    }

    [Fact]
    public async Task CreateNewDirectoryThrowsIfExists()
    {
        using var sftpClient = await _sshServer.CreateSftpClientAsync();
        string path = $"/tmp/{Path.GetRandomFileName()}";

        await sftpClient.CreateNewDirectoryAsync(path);

        await Assert.ThrowsAsync<SftpException>(async () => await sftpClient.CreateNewDirectoryAsync(path));
    }

    [Fact]
    public async Task CreateDirectoryDoesntThrowIfExists()
    {
        using var sftpClient = await _sshServer.CreateSftpClientAsync();
        string path = $"/tmp/{Path.GetRandomFileName()}";

        await sftpClient.CreateDirectoryAsync(path);

        await sftpClient.CreateDirectoryAsync(path);
    }

    [InlineData(true)]
    [InlineData(false)]
    [Theory]
    public async Task CreateDirectoryCreatesParentDirectories(bool createParents)
    {
        using var sftpClient = await _sshServer.CreateSftpClientAsync();
        string path = $"/tmp/{Path.GetRandomFileName()}/child/subchild//";

        if (createParents)
        {
            await sftpClient.CreateDirectoryAsync(path, createParents);

            var attributes = await sftpClient.GetAttributesAsync(path);
            Assert.NotNull(attributes);
            Assert.Equal(UnixFileType.Directory, attributes.FileType);
        }
        else
        {
            await Assert.ThrowsAsync<SftpException>(async () => await sftpClient.CreateDirectoryAsync(path, createParents));
        }
    }

    [Fact]
    public async Task RemoveFile()
    {
        using var sftpClient = await _sshServer.CreateSftpClientAsync();
        string path = $"/tmp/{Path.GetRandomFileName()}";

        using var file = await sftpClient.CreateNewFileAsync(path, FileAccess.Write);
        await file.CloseAsync();

        var attributes = await sftpClient.GetAttributesAsync(path);
        Assert.NotNull(attributes);
        Assert.Equal(UnixFileType.RegularFile, attributes.FileType);

        await sftpClient.DeleteFileAsync(path);
        attributes = await sftpClient.GetAttributesAsync(path);
        Assert.Null(attributes);
    }

    [Fact]
    public async Task Rename()
    {
        using var sftpClient = await _sshServer.CreateSftpClientAsync();
        string path = $"/tmp/{Path.GetRandomFileName()}";

        using var file = await sftpClient.CreateNewFileAsync(path, FileAccess.Write);
        await file.CloseAsync();

        var attributes = await sftpClient.GetAttributesAsync(path);
        Assert.NotNull(attributes);
        Assert.Equal(UnixFileType.RegularFile, attributes.FileType);

        string newpath = $"/tmp/{Path.GetRandomFileName()}";
        await sftpClient.RenameAsync(path, newpath);

        attributes = await sftpClient.GetAttributesAsync(path);
        Assert.Null(attributes);

        attributes = await sftpClient.GetAttributesAsync(newpath);
        Assert.NotNull(attributes);
        Assert.Equal(UnixFileType.RegularFile, attributes.FileType);
    }

    [Fact]
    public async Task GetAttributes()
    {
        using var sftpClient = await _sshServer.CreateSftpClientAsync();
        string path = $"/tmp/{Path.GetRandomFileName()}";

        DateTimeOffset someTimeAgo = DateTimeOffset.Now - TimeSpan.FromSeconds(5);

        int fileLength = 12;
        using var file = await sftpClient.CreateNewFileAsync(path, FileAccess.Write);
        await file.WriteAsync(new byte[fileLength]);

        var attributes = await file.GetAttributesAsync();
        CheckFileAttributes(attributes);

        await file.CloseAsync();

        attributes = await sftpClient.GetAttributesAsync(path);
        CheckFileAttributes(attributes);

        void CheckFileAttributes(FileEntryAttributes? attributes)
        {
            Assert.NotNull(attributes);
            Assert.Equal(UnixFileType.RegularFile, attributes.FileType);
            Assert.Equal(fileLength, attributes.Length);
            Assert.True(attributes.Uid >= 1000);
            Assert.True(attributes.Gid >= 1000);
            Assert.True(attributes.LastAccessTime >= someTimeAgo);
            Assert.True(attributes.LastWriteTime >= someTimeAgo);
        }
    }

    [Fact]
    public async Task OpenFileNotExistsReturnsNull()
    {
        using var sftpClient = await _sshServer.CreateSftpClientAsync();
        string path = $"/tmp/{Path.GetRandomFileName()}";

        using var file = await sftpClient.OpenFileAsync(path, FileAccess.Write);
        Assert.Null(file);
    }

    [Fact]
    public async Task AttributesNotExistsReturnsNull()
    {
        using var sftpClient = await _sshServer.CreateSftpClientAsync();
        string path = $"/tmp/{Path.GetRandomFileName()}";

        var attributes = await sftpClient.GetAttributesAsync(path);
        Assert.Null(attributes);
    }

    [Fact]
    public async Task FileNotExistsDeleteDoesNotThrow()
    {
        using var sftpClient = await _sshServer.CreateSftpClientAsync();
        string path = $"/tmp/{Path.GetRandomFileName()}";

        await sftpClient.DeleteFileAsync(path);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task DirectoryNotExistsDeleteDoesNotThrow(bool recurse)
    {
        using var sftpClient = await _sshServer.CreateSftpClientAsync();
        string path = $"/tmp/{Path.GetRandomFileName()}";

        await sftpClient.DeleteDirectoryAsync(path, recurse);
    }

    [Fact]
    public async Task EnumerateDirectory()
    {
        using var sftpClient = await _sshServer.CreateSftpClientAsync();
        string directoryPath = $"/tmp/{Path.GetRandomFileName()}";

        await sftpClient.CreateNewDirectoryAsync(directoryPath);

        const int FileCount = 1024;
        const int DirCount = 512;

        for (int i = 0; i < DirCount; i++)
        {
            await sftpClient.CreateNewDirectoryAsync($"{directoryPath}/dir{i}");
        }

        for (int i = 0; i < FileCount; i++)
        {
            using var file = await sftpClient.CreateNewFileAsync($"{directoryPath}/file{i}", FileAccess.Write);
            await file.CloseAsync();
        }

        var entries = await sftpClient.GetDirectoryEntriesAsync(directoryPath).ToListAsync();
        Assert.Equal(FileCount + DirCount, entries.Count);

        var fileEntries = entries.Where(e => e.Attributes.FileType == UnixFileType.RegularFile).ToList();
        Assert.Equal(FileCount, fileEntries.Count);
        foreach (var file in fileEntries)
        {
            Assert.StartsWith($"{directoryPath}/file", file.Path);
        }

        var dirEntries = entries.Where(e => e.Attributes.FileType == UnixFileType.Directory).ToList();
        Assert.Equal(DirCount, dirEntries.Count);
        foreach (var dir in dirEntries)
        {
            Assert.StartsWith($"{directoryPath}/dir", dir.Path);
        }
    }

    [InlineData(true)]
    [InlineData(false)]
    [Theory]
    public async Task EnumerateDirectoryRecursive(bool recurse)
    {
        using var sftpClient = await _sshServer.CreateSftpClientAsync();
        string directoryPath = $"/tmp/{Path.GetRandomFileName()}";

        await sftpClient.CreateNewDirectoryAsync(directoryPath);

        using var file = await sftpClient.CreateNewFileAsync($"{directoryPath}/file", FileAccess.Write);
        await file.CloseAsync();

        await sftpClient.CreateNewDirectoryAsync($"{directoryPath}/childdir");

        using var file2 = await sftpClient.CreateNewFileAsync($"{directoryPath}/childdir/file2", FileAccess.Write);
        await file2.CloseAsync();

        List<(string Path, FileEntryAttributes Attributes)> entries = await sftpClient.GetDirectoryEntriesAsync(directoryPath, new EnumerationOptions() { RecurseSubdirectories = recurse }).ToListAsync();

        if (recurse == true)
        {
            Assert.Equal(
                new HashSet<string>(new[] { $"{directoryPath}/file", $"{directoryPath}/childdir", $"{directoryPath}/childdir/file2" }),
                entries.Select(entry => entry.Path).ToHashSet()
            );

            // Recursion happens at the end.
            Assert.Equal($"{directoryPath}/childdir/file2", entries[2].Path);
        }
        else
        {
            Assert.Equal(
                new HashSet<string>(new[] { $"{directoryPath}/file", $"{directoryPath}/childdir" }),
                entries.Select(entry => entry.Path).ToHashSet()
            );
        }
    }

    [InlineData(true)]
    [InlineData(false)]
    [Theory]
    public async Task EnumerateDirectoryShouldInclude(bool value)
    {
        using var sftpClient = await _sshServer.CreateSftpClientAsync();
        string directoryPath = $"/tmp/{Path.GetRandomFileName()}";

        await sftpClient.CreateNewDirectoryAsync(directoryPath);

        for (int i = 0; i < 2; i++)
        {
            using var file = await sftpClient.CreateNewFileAsync($"{directoryPath}/file{i}", FileAccess.Write);
            await file.CloseAsync();
        }

        List<(string Path, FileEntryAttributes Attributes)> entries = await sftpClient.GetDirectoryEntriesAsync(directoryPath,
            new EnumerationOptions() { ShouldInclude = (ref SftpFileEntry entry) => value }).ToListAsync();

        if (value == true)
        {
            Assert.Equal(2, entries.Count);
        }
        else
        {
            Assert.Empty(entries);
        }
    }

    [InlineData(true)]
    [InlineData(false)]
    [Theory]
    public async Task EnumerateDirectoryShouldRecurse(bool value)
    {
        using var sftpClient = await _sshServer.CreateSftpClientAsync();
        string directoryPath = $"/tmp/{Path.GetRandomFileName()}";

        await sftpClient.CreateNewDirectoryAsync($"{directoryPath}/dir", createParents: true);

        for (int i = 0; i < 2; i++)
        {
            using var file = await sftpClient.CreateNewFileAsync($"{directoryPath}/dir/file{i}", FileAccess.Write);
            await file.CloseAsync();
        }

        List<(string Path, FileEntryAttributes Attributes)> entries = await sftpClient.GetDirectoryEntriesAsync(directoryPath,
            new EnumerationOptions() { ShouldRecurse = (ref SftpFileEntry entry) => value, RecurseSubdirectories = true }).ToListAsync();

        if (value == true)
        {
            Assert.Equal(3, entries.Count);
        }
        else
        {
            Assert.Single(entries);
        }
    }

    [Fact]
    public async Task EnumerateDirectoryFileTypeFilter()
    {
        using var sftpClient = await _sshServer.CreateSftpClientAsync();
        string directoryPath = $"/tmp/{Path.GetRandomFileName()}";

        await sftpClient.CreateNewDirectoryAsync($"{directoryPath}/child1/child2/", createParents: true);

        using var file = await sftpClient.CreateNewFileAsync($"{directoryPath}/child1/child2/file", FileAccess.Write);
        await file.CloseAsync();

        List<(string Path, FileEntryAttributes Attributes)> entries = await sftpClient.GetDirectoryEntriesAsync(directoryPath,
            new EnumerationOptions() { RecurseSubdirectories = true, FileTypeFilter = UnixFileTypeFilter.RegularFile }).ToListAsync();

        Assert.Single(entries);
        var entry = entries[0];
        Assert.Equal(UnixFileType.RegularFile, entry.Attributes.FileType);
        Assert.Equal($"{directoryPath}/child1/child2/file", entry.Path);
    }

    [InlineData(true, true)]
    [InlineData(true, false)]
    [InlineData(false, false)]
    [Theory]
    public async Task EnumerateDirectoryFollowFileLinks(bool follow, bool broken)
    {
        using var sftpClient = await _sshServer.CreateSftpClientAsync();
        string directoryPath = $"/tmp/{Path.GetRandomFileName()}";

        await sftpClient.CreateNewDirectoryAsync(directoryPath);

        const int FileLength = 1024;

        if (!broken)
        {
            using var file = await sftpClient.CreateNewFileAsync($"{directoryPath}/file", FileAccess.Write);
            await file.WriteAsync(new byte[FileLength]);
            await file.CloseAsync();
        }

        await sftpClient.CreateSymbolicLinkAsync($"{directoryPath}/link", $"{directoryPath}/file");

        List<(string Path, FileEntryAttributes Attributes)> entries = await sftpClient.GetDirectoryEntriesAsync(directoryPath, new EnumerationOptions() { FollowFileLinks = follow }).ToListAsync();

        if (broken)
        {
            Assert.Single(entries);

            var entry = entries[0];
            Assert.Equal(UnixFileType.SymbolicLink, entry.Attributes.FileType);
            Assert.Equal($"{directoryPath}/link", entry.Path);
        }
        else
        {
            Assert.Equal(2, entries.Count);
            Assert.Equal(
                new HashSet<string>(new[] { $"{directoryPath}/file", $"{directoryPath}/link" }),
                entries.Select(entry => entry.Path).ToHashSet()
            );
            var fileEntry = entries[0];
            var linkEntry = entries[1];
            if (fileEntry.Path.EndsWith("link"))
            {
                (fileEntry, linkEntry) = (linkEntry, fileEntry);
            }

            Assert.Equal(UnixFileType.RegularFile, fileEntry.Attributes.FileType);
            Assert.Equal(FileLength, fileEntry.Attributes.Length);

            if (follow)
            {
                Assert.Equal(fileEntry.Attributes.FileType, linkEntry.Attributes.FileType);
                Assert.Equal(fileEntry.Attributes.Length, linkEntry.Attributes.Length);
            }
            else
            {
                Assert.Equal(UnixFileType.SymbolicLink, linkEntry.Attributes.FileType);
                Assert.NotEqual(FileLength, linkEntry.Attributes.Length);
            }
        }
    }

    [InlineData(true)]
    [InlineData(false)]
    [Theory]
    public async Task EnumerateDirectoryFollowDirectoryLinks(bool follow)
    {
        using var sftpClient = await _sshServer.CreateSftpClientAsync();
        string directoryPath = $"/tmp/{Path.GetRandomFileName()}";

        await sftpClient.CreateNewDirectoryAsync(directoryPath);

        await sftpClient.CreateDirectoryAsync($"{directoryPath}/dir");

        await sftpClient.CreateSymbolicLinkAsync($"{directoryPath}/link", $"{directoryPath}/dir");

        List<(string Path, FileEntryAttributes Attributes)> entries = await sftpClient.GetDirectoryEntriesAsync(directoryPath, new EnumerationOptions() { FollowDirectoryLinks = follow }).ToListAsync();

        Assert.Equal(2, entries.Count);
        Assert.Equal(
            new HashSet<string>(new[] { $"{directoryPath}/dir", $"{directoryPath}/link" }),
            entries.Select(entry => entry.Path).ToHashSet()
        );
        var dirEntry = entries[0];
        var linkEntry = entries[1];
        if (dirEntry.Path.EndsWith("link"))
        {
            (dirEntry, linkEntry) = (linkEntry, dirEntry);
        }

        Assert.Equal(UnixFileType.Directory, dirEntry.Attributes.FileType);

        if (follow)
        {
            Assert.Equal(dirEntry.Attributes.FileType, linkEntry.Attributes.FileType);
        }
        else
        {
            Assert.Equal(UnixFileType.SymbolicLink, linkEntry.Attributes.FileType);
        }
    }

    [Fact]
    public async Task EnumerateRootDirectory()
    {
        using var sftpClient = await _sshServer.CreateSftpClientAsync();

        var entries = await sftpClient.GetDirectoryEntriesAsync("/").ToListAsync();
        Assert.NotEmpty(entries);

        foreach (var entry in entries)
        {
            string path = entry.Path;
            Assert.True(path.Length > 2);
            Assert.StartsWith("/", path);
            Assert.False(path.StartsWith("//"));
        }
    }

    [Fact]
    public async Task EnumerateRootNotFound()
    {
        using var sftpClient = await _sshServer.CreateSftpClientAsync();

        string path = "/no_such_dir";
        var exception = await Assert.ThrowsAsync<SftpException>(() => sftpClient.GetDirectoryEntriesAsync(path).ToListAsync().AsTask());
        Assert.Equal(SftpError.NoSuchFile, exception.Error);
    }

    [Fact]
    public async Task EnumerateNestedDirNotFoundDoesNotThrow()
    {
        using var sftpClient = await _sshServer.CreateSftpClientAsync();

        string directoryPath = $"/tmp/{Path.GetRandomFileName()}";
        await sftpClient.CreateNewDirectoryAsync(directoryPath);
        string childDirectoryPath = $"{directoryPath}/child";
        await sftpClient.CreateDirectoryAsync(childDirectoryPath);
        string childChildDirectoryPath = $"{childDirectoryPath}/nestedchild";
        await sftpClient.CreateDirectoryAsync(childChildDirectoryPath);

        bool childDirWasReturned = false;
        int count = 0;
        await foreach (var entry in sftpClient.GetDirectoryEntriesAsync(directoryPath, new Tmds.Ssh.EnumerationOptions() { RecurseSubdirectories = true }))
        {
            count++;
            childDirWasReturned = entry.Path == childDirectoryPath;

            // Delete the nested directories before we recurse into them.
            await sftpClient.DeleteDirectoryAsync(childChildDirectoryPath);
            await sftpClient.DeleteDirectoryAsync(childDirectoryPath);
        }

        Assert.True(childDirWasReturned);
        Assert.Equal(1, count);
    }

    [Fact]
    public void DefaultEnumerationOptions()
    {
        var options = new EnumerationOptions();

        Assert.False(options.RecurseSubdirectories);
    }

    [Fact]
    public async Task UploadDownloadDirectory()
    {
        using var sftpClient = await _sshServer.CreateSftpClientAsync();

        string sourcePath = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
        string destinationPath = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());

        try
        {
            // Create a local directory and populate it with files.
            string childDirPath = Path.Combine(sourcePath, "childdir");
            Directory.CreateDirectory(childDirPath);
            byte[] buffer = new byte[PacketSize * 2];
            foreach (bool inChild in new[] { false, true })
            {
                for (int i = 0; i < 128; i++)
                {
                    using FileStream fs = new FileStream(Path.Combine(inChild ? childDirPath : sourcePath, $"file{i}"),
                                            FileMode.CreateNew, FileAccess.Write, FileShare.None, bufferSize: 0);

                    // create files with random bytes that are sent in one or two packets.
                    int length = PacketSize - PacketSize / 2 + Random.Shared.Next(PacketSize);
                    Random.Shared.NextBytes(buffer.AsSpan(0, length));
                    fs.Write(buffer.AsSpan(0, length));
                }
            }

            // Upload
            string remoteDirPath = $"/tmp/{Path.GetRandomFileName()}";
            await sftpClient.CreateNewDirectoryAsync(remoteDirPath);
            await sftpClient.UploadDirectoryEntriesAsync(sourcePath, remoteDirPath);

            // Download
            Directory.CreateDirectory(destinationPath);
            await sftpClient.DownloadDirectoryEntriesAsync(remoteDirPath, destinationPath);

            // Verify the download matches the source directory that was uploaded.
            byte[] buffer2 = new byte[PacketSize * 2];
            string[] sourceFiles = Directory.GetFiles(sourcePath, "*", SearchOption.AllDirectories);
            foreach (var sourceFile in sourceFiles)
            {
                string destinationFile = Path.Join(destinationPath, sourceFile.Substring(sourcePath.Length));
                using FileStream src = File.OpenRead(sourceFile);
                using FileStream dst = File.OpenRead(destinationFile);
                int length = (int)src.Length;
                Assert.Equal(length, dst.Length);
                src.ReadAtLeast(buffer, length);
                dst.ReadAtLeast(buffer2, length);
                Assert.True(buffer.AsSpan(0, length).SequenceEqual(buffer2.AsSpan(0, length)));
            }
            string[] destinationFiles = Directory.GetFiles(destinationPath, "*", SearchOption.AllDirectories);
            Assert.Equal(sourceFiles.Length, destinationFiles.Length);
        }
        finally
        {
            foreach (string dir in new[] { sourcePath, destinationPath })
            {
                try
                {
                    Directory.Delete(dir, true);
                }
                catch
                { }
            }
        }
    }

    [InlineData(0)]
    [InlineData(10)]
    [InlineData(MultiPacketSize)]
    [Theory]
    public async Task UploadDownloadFile(int fileSize)
    {
        using var sftpClient = await _sshServer.CreateSftpClientAsync();

        string sourcePath = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
        string destinationPath = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());

        try
        {
            byte[] buffer = new byte[fileSize];
            using FileStream fs = new FileStream(sourcePath, FileMode.CreateNew, FileAccess.Write, FileShare.None, bufferSize: 0);
            Random.Shared.NextBytes(buffer);
            fs.Write(buffer);
            fs.Dispose();

            // Upload
            string remotePath = $"/tmp/{Path.GetRandomFileName()}";
            await sftpClient.UploadFileAsync(sourcePath, remotePath);

            // Download
            await sftpClient.DownloadFileAsync(remotePath, destinationPath);

            // Verify the downloaded file matches the source file that was uploaded.
            using FileStream dst = File.OpenRead(destinationPath);
            int length = (int)dst.Length;
            Assert.Equal(fileSize, length);
            byte[] buffer2 = new byte[fileSize];
            dst.ReadAtLeast(buffer2, length);
            Assert.True(buffer.AsSpan(0, length).SequenceEqual(buffer2.AsSpan(0, length)));
        }
        finally
        {
            foreach (string dir in new[] { sourcePath, destinationPath })
            {
                try
                {
                    File.Delete(dir);
                }
                catch
                { }
            }
        }
    }

    [InlineData(0)]
    [InlineData(10)]
    [InlineData(10 * MultiPacketSize)] // Ensure some pipelined writing.
    [Theory]
    public async Task UploadDownloadFileWithStream(int size)
    {
        using var sftpClient = await _sshServer.CreateSftpClientAsync();
        
        byte[] sourceData = new byte[size];
        Random.Shared.NextBytes(sourceData);
        MemoryStream uploadStream = new MemoryStream(sourceData);

        string remotePath = $"/tmp/{Path.GetRandomFileName()}";
        await sftpClient.UploadFileAsync(uploadStream, remotePath);
        Assert.Equal(sourceData.Length, uploadStream.Position);

        await using var downloadStream = new MemoryStream();
        await sftpClient.DownloadFileAsync(remotePath, downloadStream);
        Assert.Equal(sourceData, downloadStream.ToArray());
    }

    [InlineData(0)]
    [InlineData(10)]
    [InlineData(10 * MultiPacketSize)]
    [Theory]
    public async Task UploadDownloadFileWithAsyncStream(int size)
    {
        using var sftpClient = await _sshServer.CreateSftpClientAsync();
        
        byte[] sourceData = new byte[size];
        Random.Shared.NextBytes(sourceData);
        Stream uploadStream = new NonSeekableAsyncStream(sourceData);

        string remotePath = $"/tmp/{Path.GetRandomFileName()}";
        await sftpClient.UploadFileAsync(uploadStream, remotePath);

        await using var downloadStream = new NonSeekableAsyncStream();
        await sftpClient.DownloadFileAsync(remotePath, downloadStream);
        Assert.Equal(sourceData, downloadStream.ToArray());
    }

    [Fact]
    public async Task DownloadFileThrowsWhenNotFound()
    {
        using var sftpClient = await _sshServer.CreateSftpClientAsync();

        string remotePath = $"/tmp/{Path.GetRandomFileName()}";
        string destinationPath = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());

        SftpException ex = await Assert.ThrowsAsync<SftpException>(() => sftpClient.DownloadFileAsync(remotePath, destinationPath).AsTask());
        Assert.Equal(SftpError.NoSuchFile, ex.Error);
    }

    [Fact]
    public async Task ReadCreateLink()
    {
        using var sftpClient = await _sshServer.CreateSftpClientAsync();

        string linkPath = $"/tmp/{Path.GetRandomFileName()}";
        string contentOfLink = "link_content";

        await sftpClient.CreateSymbolicLinkAsync(linkPath, contentOfLink);

        Assert.Equal(contentOfLink, await sftpClient.GetLinkTargetAsync(linkPath));
    }

    [InlineData(true)]
    [InlineData(false)]
    [Theory]
    public async Task DownloadUploadBrokenLink(bool follow)
    {
        using var sftpClient = await _sshServer.CreateSftpClientAsync();

        string sourceDir = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
        Directory.CreateDirectory(sourceDir);
        string linkName = "link";
        string contentOfLink = "link_content";
        File.CreateSymbolicLink(Path.Combine(sourceDir, linkName), contentOfLink);

        string remoteDir = $"/tmp/{Path.GetRandomFileName()}";
        await sftpClient.CreateNewDirectoryAsync(remoteDir);
        await sftpClient.UploadDirectoryEntriesAsync(sourceDir, remoteDir, new UploadEntriesOptions() { FollowDirectoryLinks = follow, FollowFileLinks = follow });

        Assert.Equal(contentOfLink, await sftpClient.GetLinkTargetAsync($"{remoteDir}/{linkName}"));

        string dstDir = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
        Directory.CreateDirectory(dstDir);
        await sftpClient.DownloadDirectoryEntriesAsync(remoteDir, dstDir);

        Assert.Equal(contentOfLink, new FileInfo(Path.Combine(dstDir, linkName)).LinkTarget);
    }

    [Fact]
    public async Task DownloadNoIncludeSubdirectories()
    {
        using var sftpClient = await _sshServer.CreateSftpClientAsync();
        string directoryPath = $"/tmp/{Path.GetRandomFileName()}";

        await sftpClient.CreateNewDirectoryAsync($"{directoryPath}/child1/child2/", createParents: true);

        var file = await sftpClient.CreateNewFileAsync($"{directoryPath}/child1/child2/file", FileAccess.Write);
        await file.CloseAsync();

        file = await sftpClient.CreateNewFileAsync($"{directoryPath}/rootfile", FileAccess.Write);
        await file.CloseAsync();

        string dstDir = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
        Directory.CreateDirectory(dstDir);
        await sftpClient.DownloadDirectoryEntriesAsync(directoryPath, dstDir,
            new DownloadEntriesOptions() { IncludeSubdirectories = false });

        Assert.True(File.Exists($"{dstDir}/rootfile"));
        Assert.False(Directory.Exists($"{dstDir}/child1"));
    }

    [InlineData(true)]
    [InlineData(false)]
    [Theory]
    public async Task DownloadTargetDirectoryCreationNone(bool dstExists)
    {
        using var sftpClient = await _sshServer.CreateSftpClientAsync();
        string directoryPath = $"/tmp/{Path.GetRandomFileName()}";

        await sftpClient.CreateNewDirectoryAsync($"{directoryPath}");
        var file = await sftpClient.CreateNewFileAsync($"{directoryPath}/file", FileAccess.Write);
        await file.CloseAsync();

        string dstDir = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
        if (dstExists)
        {
            Directory.CreateDirectory(dstDir);
        }

        if (dstExists)
        {
            await sftpClient.DownloadDirectoryEntriesAsync(directoryPath, dstDir);
        }
        else
        {
            await Assert.ThrowsAsync<DirectoryNotFoundException>(async () => await sftpClient.DownloadDirectoryEntriesAsync(directoryPath, dstDir));
        }
    }

    [InlineData(true, true)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(false, false)]
    [Theory]
    public async Task DownloadTargetDirectoryCreationCreate(bool dstWithParents, bool dstExists)
    {
        using var sftpClient = await _sshServer.CreateSftpClientAsync();
        string directoryPath = $"/tmp/{Path.GetRandomFileName()}";

        await sftpClient.CreateNewDirectoryAsync($"{directoryPath}");

        string dstDir = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
        if (dstWithParents)
        {
            dstDir = Path.Combine(dstDir, Path.GetRandomFileName());
        }
        if (dstExists)
        {
            Directory.CreateDirectory(dstDir);
        }

        var options = new DownloadEntriesOptions { TargetDirectoryCreation = TargetDirectoryCreation.Create };
        if (dstWithParents && !dstExists)
        {
            await Assert.ThrowsAsync<DirectoryNotFoundException>(async () => await sftpClient.DownloadDirectoryEntriesAsync(directoryPath, dstDir, options));
        }
        else
        {
            await sftpClient.DownloadDirectoryEntriesAsync(directoryPath, dstDir, options);
        }
    }

    [InlineData(true, true)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(false, false)]
    [Theory]
    public async Task DownloadTargetDirectoryCreationCreateWithParents(bool dstWithParents, bool dstExists)
    {
        using var sftpClient = await _sshServer.CreateSftpClientAsync();
        string directoryPath = $"/tmp/{Path.GetRandomFileName()}";

        await sftpClient.CreateNewDirectoryAsync($"{directoryPath}");

        string dstDir = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
        if (dstWithParents)
        {
            dstDir = Path.Combine(dstDir, Path.GetRandomFileName());
        }
        if (dstExists)
        {
            Directory.CreateDirectory(dstDir);
        }

        var options = new DownloadEntriesOptions { TargetDirectoryCreation = TargetDirectoryCreation.CreateWithParents };
        await sftpClient.DownloadDirectoryEntriesAsync(directoryPath, dstDir, options);
    }

    [InlineData(true, true)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(false, false)]
    [Theory]
    public async Task DownloadTargetDirectoryCreationCreateNew(bool dstWithParents, bool dstExists)
    {
        using var sftpClient = await _sshServer.CreateSftpClientAsync();
        string directoryPath = $"/tmp/{Path.GetRandomFileName()}";

        await sftpClient.CreateNewDirectoryAsync($"{directoryPath}");

        string dstDir = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
        if (dstWithParents)
        {
            dstDir = Path.Combine(dstDir, Path.GetRandomFileName());
        }
        if (dstExists)
        {
            Directory.CreateDirectory(dstDir);
        }

        var options = new DownloadEntriesOptions { TargetDirectoryCreation = TargetDirectoryCreation.CreateNew };
        if (dstExists)
        {
            await Assert.ThrowsAsync<IOException>(async () => await sftpClient.DownloadDirectoryEntriesAsync(directoryPath, dstDir, options));
        }
        else if (dstWithParents)
        {
            await Assert.ThrowsAsync<DirectoryNotFoundException>(async () => await sftpClient.DownloadDirectoryEntriesAsync(directoryPath, dstDir, options));
        }
        else
        {
            await sftpClient.DownloadDirectoryEntriesAsync(directoryPath, dstDir, options);
        }
    }

    [Fact]
    public async Task DownloadFileTypeFilterCreatesParentDirs()
    {
        using var sftpClient = await _sshServer.CreateSftpClientAsync();
        string directoryPath = $"/tmp/{Path.GetRandomFileName()}";

        await sftpClient.CreateNewDirectoryAsync($"{directoryPath}/child1/child2/", createParents: true);

        using var file = await sftpClient.CreateNewFileAsync($"{directoryPath}/child1/child2/file", FileAccess.Write);
        await file.CloseAsync();

        string dstDir = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
        Directory.CreateDirectory(dstDir);
        await sftpClient.DownloadDirectoryEntriesAsync(directoryPath, dstDir,
            new DownloadEntriesOptions() { FileTypeFilter = UnixFileTypeFilter.RegularFile });

        Assert.True(File.Exists($"{dstDir}/child1/child2/file"));
    }

    [InlineData(true)]
    [InlineData(false)]
    [Theory]
    public async Task UploadFollowFileLinks(bool follow)
    {
        using var sftpClient = await _sshServer.CreateSftpClientAsync();

        string sourceDir = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
        Directory.CreateDirectory(sourceDir);
        File.OpenWrite($"{sourceDir}/file").Dispose();
        File.CreateSymbolicLink(Path.Combine(sourceDir, "link"), "file");

        string remoteDir = $"/tmp/{Path.GetRandomFileName()}";
        await sftpClient.CreateNewDirectoryAsync(remoteDir);
        await sftpClient.UploadDirectoryEntriesAsync(sourceDir, remoteDir, new UploadEntriesOptions() { FollowFileLinks = follow });

        if (follow)
        {
            var attributes = await sftpClient.GetAttributesAsync($"{remoteDir}/link", followLinks: false);
            Assert.NotNull(attributes);
            Assert.Equal(UnixFileType.RegularFile, attributes.FileType);
        }
        else
        {
            Assert.Equal("file", await sftpClient.GetLinkTargetAsync($"{remoteDir}/link"));
        }
    }

    [InlineData(true)]
    [InlineData(false)]
    [Theory]
    public async Task UploadFollowDirectoryLinks(bool follow)
    {
        using var sftpClient = await _sshServer.CreateSftpClientAsync();

        string sourceDir = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
        Directory.CreateDirectory(sourceDir);
        Directory.CreateDirectory($"{sourceDir}/dir");
        File.CreateSymbolicLink(Path.Combine(sourceDir, "link"), "dir");

        string remoteDir = $"/tmp/{Path.GetRandomFileName()}";
        await sftpClient.CreateNewDirectoryAsync(remoteDir);
        await sftpClient.UploadDirectoryEntriesAsync(sourceDir, remoteDir, new UploadEntriesOptions() { FollowDirectoryLinks = follow });

        if (follow)
        {
            var attributes = await sftpClient.GetAttributesAsync($"{remoteDir}/link", followLinks: false);
            Assert.NotNull(attributes);
            Assert.Equal(UnixFileType.Directory, attributes.FileType);
        }
        else
        {
            Assert.Equal("dir", await sftpClient.GetLinkTargetAsync($"{remoteDir}/link"));
        }
    }

    [InlineData(true)]
    [InlineData(false)]
    [Theory]
    public async Task UploadShouldRecurse(bool recurse)
    {
        using var sftpClient = await _sshServer.CreateSftpClientAsync();

        string sourceDir = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
        Directory.CreateDirectory(sourceDir);
        string childDir = $"{sourceDir}/dir";
        Directory.CreateDirectory(childDir);
        File.OpenWrite($"{childDir}/file").Dispose();

        string remoteDir = $"/tmp/{Path.GetRandomFileName()}";
        await sftpClient.CreateNewDirectoryAsync(remoteDir);
        await sftpClient.UploadDirectoryEntriesAsync(sourceDir, remoteDir, new UploadEntriesOptions()
        {
            ShouldRecurse = (ref LocalFileEntry entry) =>
            {
                Assert.Equal(childDir, entry.ToFullPath());
                return recurse;
            }
        });

        var fileAttributes = await sftpClient.GetAttributesAsync($"{remoteDir}/dir/file");
        if (recurse)
        {
            Assert.NotNull(fileAttributes);
        }
        else
        {
            Assert.Null(fileAttributes);
        }

        var dirAttributes = await sftpClient.GetAttributesAsync($"{remoteDir}/dir");
        Assert.NotNull(dirAttributes);
    }

    [Fact]
    public async Task UploadNoIncludeSubdirectories()
    {
        using var sftpClient = await _sshServer.CreateSftpClientAsync();

        string sourceDir = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
        Directory.CreateDirectory(sourceDir);
        File.OpenWrite($"{sourceDir}/rootfile").Dispose();
        string childDir = $"{sourceDir}/dir";
        Directory.CreateDirectory(childDir);
        File.OpenWrite($"{childDir}/file").Dispose();

        string remoteDir = $"/tmp/{Path.GetRandomFileName()}";
        await sftpClient.CreateNewDirectoryAsync(remoteDir);
        await sftpClient.UploadDirectoryEntriesAsync(sourceDir, remoteDir, new UploadEntriesOptions()
        {
            IncludeSubdirectories = false
        });

        var dirAttributes = await sftpClient.GetAttributesAsync($"{remoteDir}/dir");
        Assert.Null(dirAttributes);

        var fileAttributes = dirAttributes = await sftpClient.GetAttributesAsync($"{remoteDir}/rootfile");
        Assert.NotNull(dirAttributes);
    }

    [InlineData(true)]
    [InlineData(false)]
    [Theory]
    public async Task UploadTargetDirectoryCreationNone(bool dstExists)
    {
        using var sftpClient = await _sshServer.CreateSftpClientAsync();

        string sourceDir = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
        Directory.CreateDirectory(sourceDir);
        File.OpenWrite(Path.Combine(sourceDir, Path.GetRandomFileName())).Dispose();

        string dstDir = $"/tmp/{Path.GetRandomFileName()}";
        if (dstExists)
        {
            await sftpClient.CreateNewDirectoryAsync($"{dstDir}", createParents: true);
        }

        if (dstExists)
        {
            await sftpClient.UploadDirectoryEntriesAsync(sourceDir, dstDir);
        }
        else
        {
            var ex = await Assert.ThrowsAsync<SftpException>(async () => await sftpClient.UploadDirectoryEntriesAsync(sourceDir, dstDir));
            Assert.Equal(SftpError.NoSuchFile, ex.Error); // Parent not found.
        }
    }

    [InlineData(true, true)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(false, false)]
    [Theory]
    public async Task UploadTargetDirectoryCreationCreate(bool dstWithParents, bool dstExists)
    {
        using var sftpClient = await _sshServer.CreateSftpClientAsync();

        string sourceDir = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
        Directory.CreateDirectory(sourceDir);

        string dstDir = $"/tmp/{Path.GetRandomFileName()}";
        if (dstWithParents)
        {
            dstDir = $"/{dstDir}/{Path.GetRandomFileName()}";
        }
        if (dstExists)
        {
            await sftpClient.CreateNewDirectoryAsync($"{dstDir}", createParents: true);
        }

        var options = new UploadEntriesOptions { TargetDirectoryCreation = TargetDirectoryCreation.Create };
        if (dstWithParents && !dstExists)
        {
            var ex = await Assert.ThrowsAsync<SftpException>(async () => await sftpClient.UploadDirectoryEntriesAsync(sourceDir, dstDir, options));
            Assert.Equal(SftpError.NoSuchFile, ex.Error); // Parent not found.
        }
        else
        {
            await sftpClient.UploadDirectoryEntriesAsync(sourceDir, dstDir, options);
        }
    }

    [InlineData(true, true)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(false, false)]
    [Theory]
    public async Task UploadTargetDirectoryCreationCreateWithParents(bool dstWithParents, bool dstExists)
    {
        using var sftpClient = await _sshServer.CreateSftpClientAsync();

        string sourceDir = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
        Directory.CreateDirectory(sourceDir);

        string dstDir = $"/tmp/{Path.GetRandomFileName()}";
        if (dstWithParents)
        {
            dstDir = $"/{dstDir}/{Path.GetRandomFileName()}";
        }
        if (dstExists)
        {
            await sftpClient.CreateNewDirectoryAsync($"{dstDir}", createParents: true);
        }

        var options = new UploadEntriesOptions { TargetDirectoryCreation = TargetDirectoryCreation.CreateWithParents };
        await sftpClient.UploadDirectoryEntriesAsync(sourceDir, dstDir, options);
    }

    [InlineData(true, true)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(false, false)]
    [Theory]
    public async Task UploadTargetDirectoryCreationCreateNew(bool dstWithParents, bool dstExists)
    {
        using var sftpClient = await _sshServer.CreateSftpClientAsync();

        string sourceDir = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
        Directory.CreateDirectory(sourceDir);

        string dstDir = $"/tmp/{Path.GetRandomFileName()}";
        if (dstWithParents)
        {
            dstDir = $"/{dstDir}/{Path.GetRandomFileName()}";
        }
        if (dstExists)
        {
            await sftpClient.CreateNewDirectoryAsync($"{dstDir}", createParents: true);
        }

        var options = new UploadEntriesOptions { TargetDirectoryCreation = TargetDirectoryCreation.CreateNew };
        if (dstExists)
        {
            var ex = await Assert.ThrowsAsync<SftpException>(async () => await sftpClient.UploadDirectoryEntriesAsync(sourceDir, dstDir, options));
            Assert.Equal(SftpError.Failure, ex.Error); // Directory already exists.
        }
        else if (dstWithParents)
        {
            var ex = await Assert.ThrowsAsync<SftpException>(async () => await sftpClient.UploadDirectoryEntriesAsync(sourceDir, dstDir, options));
            Assert.Equal(SftpError.NoSuchFile, ex.Error); // Parent not found.
        }
        else
        {
            await sftpClient.UploadDirectoryEntriesAsync(sourceDir, dstDir, options);
        }
    }

    [Fact]
    public async Task FullPath()
    {
        using var sftpClient = await _sshServer.CreateSftpClientAsync();

        string fullPath = await sftpClient.GetRealPathAsync(".");
        Assert.StartsWith(_sshServer.TestUserHome, fullPath);
    }

    [Fact]
    public async Task SetAttributes()
    {
        const int Length = 1024;
        DateTimeOffset LastAccessTime = new DateTimeOffset(new DateTime(2024, 4, 23, 21, 50, 13, DateTimeKind.Utc));
        DateTimeOffset LastWriteTime = new DateTimeOffset(new DateTime(2024, 4, 26, 20, 11, 20, DateTimeKind.Utc));
        UnixFilePermissions Permissions = UnixFilePermissions.GroupRead;

        using var sftpClient = await _sshServer.CreateSftpClientAsync();

        string filename = $"/tmp/{Path.GetRandomFileName()}";
        using var file = await sftpClient.CreateNewFileAsync(filename, FileAccess.Write);
        file.Dispose();

        await sftpClient.SetAttributesAsync(
            /* path: */ filename,
            /* permissions: */ Permissions,
            /* times: */ (LastAccessTime, LastWriteTime),
            /* length: */ Length,
            /* ids: */ default,
            /* extendedAttributes: */ null);

        FileEntryAttributes? attributes = await sftpClient.GetAttributesAsync(filename);
        Assert.NotNull(attributes);
        Assert.Equal(Length, attributes.Length);
        Assert.Equal(Permissions, attributes.Permissions);
        Assert.Equal(LastAccessTime, attributes.LastAccessTime);
        Assert.Equal(LastWriteTime, attributes.LastWriteTime);
    }

    [Fact]
    public async Task SetAttributesHandle()
    {
        const int Length = 1024;

        using var sftpClient = await _sshServer.CreateSftpClientAsync();

        string filename = $"/tmp/{Path.GetRandomFileName()}";
        using var file = await sftpClient.CreateNewFileAsync(filename, FileAccess.Write);
        await file.SetAttributesAsync(length: Length);
        file.Dispose();

        FileEntryAttributes? attributes = await sftpClient.GetAttributesAsync(filename);
        Assert.NotNull(attributes);
        Assert.Equal(Length, attributes.Length);
    }

    [Fact]
    public async Task SetLength()
    {
        const int Length = 1024;

        using var sftpClient = await _sshServer.CreateSftpClientAsync();

        string filename = $"/tmp/{Path.GetRandomFileName()}";
        using var file = await sftpClient.CreateNewFileAsync(filename, FileAccess.Write);
        await file.SetLengthAsync(Length);

        long length = await file.GetLengthAsync();

        Assert.Equal(Length, length);
    }

    [Fact]
    public async Task SetLengthTruncates()
    {
        const int Length = 1024;

        using var sftpClient = await _sshServer.CreateSftpClientAsync();

        string filename = $"/tmp/{Path.GetRandomFileName()}";
        using var file = await sftpClient.CreateNewFileAsync(filename, FileAccess.Write);
        await file.WriteAsync(new byte[Length]);
        Assert.Equal(Length, file.Position);

        int truncatedLength = Length / 2;
        await file.SetLengthAsync(truncatedLength);
        Assert.Equal(truncatedLength, file.Position);
        Assert.Equal(truncatedLength, await file.GetLengthAsync());
    }

    [InlineData(true)]
    [InlineData(false)]
    [Theory]
    public async Task Seekable(bool value)
    {
        using var sftpClient = await _sshServer.CreateSftpClientAsync();
        string filename = $"/tmp/{Path.GetRandomFileName()}";
        using var file = await sftpClient.CreateNewFileAsync(filename, FileAccess.Write, new FileOpenOptions() { Seekable = value });
        Assert.Equal(value, file.CanSeek);
    }

    [Fact]
    public async Task CacheLength()
    {
        const int Length = 128;
        int totalLength = 0;
        using var sftpClient = await _sshServer.CreateSftpClientAsync();
        string filename = $"/tmp/{Path.GetRandomFileName()}";

        {
            using var file = await sftpClient.CreateNewFileAsync(filename, FileAccess.Write);

            // These throw when CacheLength is false.
            Assert.Throws<NotSupportedException>(() => file.Length);
            Assert.Throws<NotSupportedException>(() => file.Seek(0, SeekOrigin.Begin));

            await file.WriteAsync(new byte[Length]);
            totalLength += Length;
        }

        {
            using var file = await sftpClient.OpenFileAsync(filename, FileAccess.Write | FileAccess.Read, new FileOpenOptions() { CacheLength = true });
            Assert.NotNull(file);

            // Check the cached length.
            Assert.Equal(Length, file.Length);
            Assert.Equal(0, file.Position);

            // Read to the end.
            int bytesRead = await file.ReadAsync(new byte[Length * 2]);
            Assert.Equal(Length, bytesRead);
            Assert.Equal(totalLength, file.Position);
            Assert.Equal(totalLength, file.Length);

            // Make the file longer.
            await file.WriteAsync(new byte[Length]);
            totalLength += Length;
            Assert.Equal(totalLength, file.Position);
            Assert.Equal(totalLength, file.Length);

            // Seek from Begin.
            file.Seek(100, SeekOrigin.Begin);
            Assert.Equal(100, file.Position);
            Assert.Equal(totalLength, file.Length);

            // Seek from End backwards 100.
            file.Seek(-100, SeekOrigin.End);
            Assert.Equal(totalLength - 100, file.Position);
            Assert.Equal(totalLength, file.Length);

            // Seek from End forward 100.
            file.Seek(100, SeekOrigin.End);
            Assert.Equal(totalLength + 100, file.Position);
            Assert.Equal(totalLength, file.Length);

            // Move back from current 150.
            file.Seek(-150, SeekOrigin.Current);
            Assert.Equal(totalLength - 50, file.Position);
            Assert.Equal(totalLength, file.Length);

            // Truncate using SetLengthAsync.
            int truncatedLength = 50;
            await file.SetLengthAsync(truncatedLength);
            Assert.Equal(truncatedLength, file.Position);
            Assert.Equal(truncatedLength, file.Length);
        }
    }

    [InlineData(0, SftpExtension.CopyData)]
    [InlineData(10, SftpExtension.CopyData)]
    [InlineData(MultiPacketSize, SftpExtension.CopyData)]
    [InlineData(0, SftpExtension.None)]
    [InlineData(10, SftpExtension.None)]
    [InlineData(MultiPacketSize, SftpExtension.None)]
    [Theory]
    public async Task CopyFile(int fileSize, SftpExtension sftpExtensions)
    {
        using var sftpClient = await _sshServer.CreateSftpClientAsync(sftpExtensions);

        (string sourceFileName, byte[] sourceData) = await CreateRemoteFileWithRandomDataAsync(sftpClient, fileSize);

        string destinationFileName = $"/tmp/{Path.GetRandomFileName()}";
        await sftpClient.CopyFileAsync(sourceFileName, destinationFileName);

        await AssertRemoteFileContentEqualsAsync(sftpClient, sourceData, destinationFileName);
    }

    [InlineData(true, SftpExtension.CopyData)]
    [InlineData(false, SftpExtension.CopyData)]
    [InlineData(true, SftpExtension.None)]
    [InlineData(false, SftpExtension.None)]
    [Theory]
    public async Task CopyFileOverwrite(bool overwrite, SftpExtension sftpExtensions)
    {
        using var sftpClient = await _sshServer.CreateSftpClientAsync(sftpExtensions);

        (string sourceFileName, byte[] sourceData) = await CreateRemoteFileWithRandomDataAsync(sftpClient, length: 10);
        (string destinationFileName, byte[] destinationData) = await CreateRemoteFileWithRandomDataAsync(sftpClient, length: 10);

        Task copyTask = sftpClient.CopyFileAsync(sourceFileName, destinationFileName, overwrite).AsTask();

        if (overwrite)
        {
            await copyTask;
        }
        else
        {
            await Assert.ThrowsAsync<SftpException>(() => copyTask);
        }

        byte[] expectedData = overwrite ? sourceData : destinationData;
        await AssertRemoteFileContentEqualsAsync(sftpClient, expectedData, destinationFileName);
    }

    [InlineData(SftpExtension.CopyData)]
    [InlineData(SftpExtension.None)]
    [Theory]
    public async Task CopyFileToSelfDoesntLooseData(SftpExtension sftpExtensions)
    {
        using var sftpClient = await _sshServer.CreateSftpClientAsync(sftpExtensions);

        (string sourceFileName, byte[] sourceData) = await CreateRemoteFileWithRandomDataAsync(sftpClient, length: 10);

        await sftpClient.CopyFileAsync(sourceFileName, sourceFileName, overwrite: true);

        await AssertRemoteFileContentEqualsAsync(sftpClient, sourceData, sourceFileName);
    }

    [InlineData(SftpExtension.CopyData)]
    [InlineData(SftpExtension.None)]
    [Theory]
    public async Task CopyFileOverwriteToLargerTruncates(SftpExtension sftpExtensions)
    {
        using var sftpClient = await _sshServer.CreateSftpClientAsync(sftpExtensions);

        const int SourceLength = 10;
        (string sourceFileName, byte[] sourceData) = await CreateRemoteFileWithRandomDataAsync(sftpClient, length: SourceLength);
        const int DestinationLength = SourceLength + SourceLength;
        (string destinationFileName, byte[] destinationData) = await CreateRemoteFileWithRandomDataAsync(sftpClient, length: DestinationLength);

        await sftpClient.CopyFileAsync(sourceFileName, destinationFileName, overwrite: true).AsTask();

        await AssertRemoteFileContentEqualsAsync(sftpClient, sourceData, destinationFileName);
    }

    private async Task AssertRemoteFileContentEqualsAsync(SftpClient client, byte[] expected, string remoteFileName)
    {
        using var readFile = await client.OpenFileAsync(remoteFileName, FileAccess.Read);
        Assert.NotNull(readFile);
        var memoryStream = new MemoryStream();
        await readFile.CopyToAsync(memoryStream);
        Assert.Equal(expected, memoryStream.ToArray());
    }

    private async Task<(string filename, byte[] data)> CreateRemoteFileWithRandomDataAsync(SftpClient client, int length)
    {
        string filename = $"/tmp/{Path.GetRandomFileName()}";
        byte[] data = new byte[10];
        Random.Shared.NextBytes(data);
        using var writeFile = await client.CreateNewFileAsync(filename, FileAccess.Write);
        await writeFile.WriteAsync(data.AsMemory());
        return (filename, data);
    }

    [InlineData(true)]
    [InlineData(false)]
    [Theory]
    public async Task AutoConnect(bool autoConnect)
    {
        using var client = await _sshServer.CreateSftpClientAsync(
            configureSsh: settings => settings.AutoConnect = autoConnect,
            connect: false
        );

        if (autoConnect)
        {
            await client.GetRealPathAsync("");
        }
        else
        {
            await Assert.ThrowsAsync<InvalidOperationException>(() => client.GetRealPathAsync("").AsTask());
        }
    }

    [Fact]
    public async Task AutoConnectAllowsExplicitConnectBeforeImplicitConnect()
    {
        using var client = await _sshServer.CreateSftpClientAsync(
            configureSsh: settings => settings.AutoConnect = true,
            connect: false
        );

        await client.ConnectAsync();

        await client.GetRealPathAsync("");
    }

    [Fact]
    public async Task AutoConnectDisallowsExplicitConnectAfterImplicitConnect()
    {
        // If a user calls ConnectAsync, we require it to happen before performing operations.
        // If there is an issue connecting, this ConnectAsync will throw the connect exception.
        // And, its cancellation token enables cancelling the connect.
        using var client = await _sshServer.CreateSftpClientAsync(
            configureSsh: settings => settings.AutoConnect = true,
            connect: false
        );

        var pending = client.GetRealPathAsync("");

        await Assert.ThrowsAsync<InvalidOperationException>(() => client.ConnectAsync());
    }

    [InlineData(true)]
    [InlineData(false)]
    [Theory]
    public async Task AutoReconnect(bool autoReconnect)
    {
        using var client = await _sshServer.CreateSftpClientAsync(
            configureSsh: settings => settings.AutoReconnect = autoReconnect
        );

        await client.GetRealPathAsync("");

        client.SshClient.ForceConnectionClose();

        if (autoReconnect)
        {
            await client.GetRealPathAsync("");
        }
        else
        {
            await Assert.ThrowsAsync<SshConnectionClosedException>(() => client.GetRealPathAsync("").AsTask());
        }
    }

    [Fact]
    public async Task DownloadSpecialZeroLengthFile()
    {
        using var sftpClient = await _sshServer.CreateSftpClientAsync();

        var ms = new MemoryStream();
        await sftpClient.DownloadFileAsync("/proc/self/mountinfo", ms);

        Assert.NotEqual(0, ms.Length);
    }

    [Fact]
    public async Task UploadSpecialZeroLengthFile()
    {
        if (!File.Exists("/proc/self/mountinfo"))
        {
            throw SkipException.ForSkip("The local system does not support /proc/self/mountinfo.");
        }

        using var sftpClient = await _sshServer.CreateSftpClientAsync();

        string remotePath = $"/tmp/{Path.GetRandomFileName()}";
        await sftpClient.UploadFileAsync("/proc/self/mountinfo", remotePath);

        var attributes = await sftpClient.GetAttributesAsync(remotePath);
        Assert.NotNull(attributes);
        Assert.NotEqual(0, attributes.Length);
    }

    sealed class NonSeekableAsyncStream : Stream
    {
        private readonly MemoryStream _innerStream = new();

        public NonSeekableAsyncStream()
        {
            _innerStream = new();
        }

        public NonSeekableAsyncStream(byte[] data)
        {
            _innerStream = new(data);
        }

        public byte[] ToArray()
            => _innerStream.ToArray();

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => true;

        public override long Length => throw new NotImplementedException();

        public override long Position
        {
            get => throw new NotImplementedException();
            set => throw new NotImplementedException();
        }

        public override void Flush()
        {
            throw new NotImplementedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            return _innerStream.Read(buffer, offset, count);
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotImplementedException();
        }

        public override void SetLength(long value)
        {
            throw new NotImplementedException();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            _innerStream.Write(buffer, offset, count);
        }
    }
}

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Xunit;

namespace Tmds.Ssh.Tests;

[Collection(nameof(SshServerCollection))]
public class SftpClientTests
{
    const int PacketSize = 32768; // roughly amount of bytes sent/received in a single sftp packet.

    private readonly SshServer _sshServer;

    public SftpClientTests(SshServer sshServer)
    {
        _sshServer = sshServer;
    }

    [Fact]
    public async Task OpenClient()
    {
        using var client = await _sshServer.CreateClientAsync();
        using var sftpClient = await client.CreateSftpClientAsync();
    }

    [InlineData(10)]
    [InlineData(10 * 1024)] // 10 kiB
    [InlineData(2 * PacketSize + 1024)]
    [Theory]
    public async Task ReadWriteFile(int fileSize)
    {
        using var client = await _sshServer.CreateClientAsync();
        using var sftpClient = await client.CreateSftpClientAsync();
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
        using var client = await _sshServer.CreateClientAsync();
        using var sftpClient = await client.CreateSftpClientAsync();
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
    public async Task CreateNewDirectoryThrowsIfExists()
    {
        using var client = await _sshServer.CreateClientAsync();
        using var sftpClient = await client.CreateSftpClientAsync();
        string path = $"/tmp/{Path.GetRandomFileName()}";

        await sftpClient.CreateNewDirectoryAsync(path);

        await Assert.ThrowsAsync<SftpException>(async () => await sftpClient.CreateNewDirectoryAsync(path));
    }

    [Fact]
    public async Task CreateDirectoryDoesntThrowIfExists()
    {
        using var client = await _sshServer.CreateClientAsync();
        using var sftpClient = await client.CreateSftpClientAsync();
        string path = $"/tmp/{Path.GetRandomFileName()}";

        await sftpClient.CreateDirectoryAsync(path);

        await sftpClient.CreateDirectoryAsync(path);
    }

    [InlineData(true)]
    [InlineData(false)]
    [Theory]
    public async Task CreateDirectoryCreatesParentDirectories(bool createParents)
    {
        using var client = await _sshServer.CreateClientAsync();
        using var sftpClient = await client.CreateSftpClientAsync();
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
        using var client = await _sshServer.CreateClientAsync();
        using var sftpClient = await client.CreateSftpClientAsync();
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
        using var client = await _sshServer.CreateClientAsync();
        using var sftpClient = await client.CreateSftpClientAsync();
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
        using var client = await _sshServer.CreateClientAsync();
        using var sftpClient = await client.CreateSftpClientAsync();
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
        using var client = await _sshServer.CreateClientAsync();
        using var sftpClient = await client.CreateSftpClientAsync();
        string path = $"/tmp/{Path.GetRandomFileName()}";

        using var file = await sftpClient.OpenFileAsync(path, FileAccess.Write);
        Assert.Null(file);
    }

    [Fact]
    public async Task AttributesNotExistsReturnsNull()
    {
        using var client = await _sshServer.CreateClientAsync();
        using var sftpClient = await client.CreateSftpClientAsync();
        string path = $"/tmp/{Path.GetRandomFileName()}";

        var attributes = await sftpClient.GetAttributesAsync(path);
        Assert.Null(attributes);
    }

    [Fact]
    public async Task FileNotExistsDeleteDoesNotThrow()
    {
        using var client = await _sshServer.CreateClientAsync();
        using var sftpClient = await client.CreateSftpClientAsync();
        string path = $"/tmp/{Path.GetRandomFileName()}";

        await sftpClient.DeleteFileAsync(path);
    }

    [Fact]
    public async Task DirectoryNotExistsDeleteDoesNotThrow()
    {
        using var client = await _sshServer.CreateClientAsync();
        using var sftpClient = await client.CreateSftpClientAsync();
        string path = $"/tmp/{Path.GetRandomFileName()}";

        await sftpClient.DeleteDirectoryAsync(path);
    }

    [Fact]
    public async Task EnumerateDirectory()
    {
        using var client = await _sshServer.CreateClientAsync();
        using var sftpClient = await client.CreateSftpClientAsync();
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
        using var client = await _sshServer.CreateClientAsync();
        using var sftpClient = await client.CreateSftpClientAsync();
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
        using var client = await _sshServer.CreateClientAsync();
        using var sftpClient = await client.CreateSftpClientAsync();
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
        using var client = await _sshServer.CreateClientAsync();
        using var sftpClient = await client.CreateSftpClientAsync();
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
        using var client = await _sshServer.CreateClientAsync();
        using var sftpClient = await client.CreateSftpClientAsync();
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
        using var client = await _sshServer.CreateClientAsync();
        using var sftpClient = await client.CreateSftpClientAsync();
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
        using var client = await _sshServer.CreateClientAsync();
        using var sftpClient = await client.CreateSftpClientAsync();
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
    public void DefaultEnumerationOptions()
    {
        var options = new EnumerationOptions();

        Assert.False(options.RecurseSubdirectories);
    }

    [Fact]
    public async Task UploadDownloadDirectory()
    {
        using var client = await _sshServer.CreateClientAsync();
        using var sftpClient = await client.CreateSftpClientAsync();

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
    [InlineData(2 * PacketSize + 1024)]
    [Theory]
    public async Task UploadDownloadFile(int fileSize)
    {
        using var client = await _sshServer.CreateClientAsync();
        using var sftpClient = await client.CreateSftpClientAsync();

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

    [Fact]
    public async Task ReadCreateLink()
    {
        using var client = await _sshServer.CreateClientAsync();
        using var sftpClient = await client.CreateSftpClientAsync();

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
        using var client = await _sshServer.CreateClientAsync();
        using var sftpClient = await client.CreateSftpClientAsync();

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
    public async Task DownloadFileTypeFilterCreatesParentDirs()
    {
        using var client = await _sshServer.CreateClientAsync();
        using var sftpClient = await client.CreateSftpClientAsync();
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
        using var client = await _sshServer.CreateClientAsync();
        using var sftpClient = await client.CreateSftpClientAsync();

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
        using var client = await _sshServer.CreateClientAsync();
        using var sftpClient = await client.CreateSftpClientAsync();

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

    [Fact]
    public async Task FullPath()
    {
        using var client = await _sshServer.CreateClientAsync();
        using var sftpClient = await client.CreateSftpClientAsync();

        string fullPath = await sftpClient.GetFullPathAsync(".");
        Assert.StartsWith(_sshServer.TestUserHome, fullPath);
    }

    [Fact]
    public async Task SetAttributes()
    {
        const int Length = 1024;
        DateTimeOffset LastAccessTime = new DateTimeOffset(new DateTime(2024, 4, 23, 21, 50, 13, DateTimeKind.Utc));
        DateTimeOffset LastWriteTime = new DateTimeOffset(new DateTime(2024, 4, 26, 20, 11, 20, DateTimeKind.Utc));
        UnixFilePermissions Permissions = UnixFilePermissions.GroupRead;

        using var client = await _sshServer.CreateClientAsync();
        using var sftpClient = await client.CreateSftpClientAsync();

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

        using var client = await _sshServer.CreateClientAsync();
        using var sftpClient = await client.CreateSftpClientAsync();

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

        using var client = await _sshServer.CreateClientAsync();
        using var sftpClient = await client.CreateSftpClientAsync();

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

        using var client = await _sshServer.CreateClientAsync();
        using var sftpClient = await client.CreateSftpClientAsync();

        string filename = $"/tmp/{Path.GetRandomFileName()}";
        using var file = await sftpClient.CreateNewFileAsync(filename, FileAccess.Write);
        await file.WriteAsync(new byte[Length]);
        Assert.Equal(Length, file.Position);

        int truncatedLength = Length / 2;
        await file.SetLengthAsync(truncatedLength);
        Assert.Equal(truncatedLength, file.Position);
        Assert.Equal(truncatedLength, await file.GetLengthAsync());
    }
}

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Xunit;

namespace Tmds.Ssh.Tests
{
    [Collection(nameof(SshServerCollection))]
    public class SftpClientTests
    {
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
        [InlineData(1 * 1024 * 1024)] // 1 MiB
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
        public async Task Directory()
        {
            using var client = await _sshServer.CreateClientAsync();
            using var sftpClient = await client.CreateSftpClientAsync();
            string path = $"/tmp/{Path.GetRandomFileName()}";

            await sftpClient.CreateDirectoryAsync(path);

            var attributes = await sftpClient.GetAttributesAsync(path);
            Assert.NotNull(attributes);
            Assert.True((attributes.FileMode & PosixFileMode.Directory) != 0);

            await sftpClient.DeleteDirectoryAsync(path);
            attributes = await sftpClient.GetAttributesAsync(path);
            Assert.Null(attributes);
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
            Assert.True((attributes.FileMode & PosixFileMode.RegularFile) != 0);

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
            Assert.True((attributes.FileMode & PosixFileMode.RegularFile) != 0);

            string newpath = $"/tmp/{Path.GetRandomFileName()}";
            await sftpClient.RenameAsync(path, newpath);

            attributes = await sftpClient.GetAttributesAsync(path);
            Assert.Null(attributes);

            attributes = await sftpClient.GetAttributesAsync(newpath);
            Assert.NotNull(attributes);
            Assert.True((attributes.FileMode & PosixFileMode.RegularFile) != 0);
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

            void CheckFileAttributes(FileAttributes? attributes)
            {
                Assert.NotNull(attributes);
                Assert.True((attributes.FileMode & PosixFileMode.RegularFile) != 0);
                Assert.Equal(fileLength, attributes.Length);
                Assert.True(attributes.Uid >= 1000);
                Assert.True(attributes.Gid >= 1000);
                Assert.True(attributes.LastAccessTime!.Value >= someTimeAgo);
                Assert.True(attributes.LastWriteTime!.Value >= someTimeAgo);
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

            await sftpClient.CreateDirectoryAsync(directoryPath);

            const int FileCount = 1024;
            const int DirCount = 512;

            for (int i = 0; i < DirCount; i++)
            {
                await sftpClient.CreateDirectoryAsync($"{directoryPath}/dir{i}");
            }

            for (int i = 0; i < FileCount; i++)
            {
                using var file = await sftpClient.CreateNewFileAsync($"{directoryPath}/file{i}", FileAccess.Write);
                await file.CloseAsync();
            }

            var entries = await sftpClient.GetDirectoryEntriesAsync(directoryPath).ToListAsync();
            Assert.Equal(entries.Count, FileCount + DirCount);

            var fileEntries = entries.Where(e => e.Attributes.FileType == PosixFileMode.RegularFile).ToList();
            Assert.Equal(fileEntries.Count, FileCount);
            foreach (var file in fileEntries)
            {
                Assert.StartsWith($"{directoryPath}/file", file.Path);
            }

            var dirEntries = entries.Where(e => e.Attributes.FileType == PosixFileMode.Directory).ToList();
            Assert.Equal(dirEntries.Count, DirCount);
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

            await sftpClient.CreateDirectoryAsync(directoryPath);

            using var file = await sftpClient.CreateNewFileAsync($"{directoryPath}/file", FileAccess.Write);
            await file.CloseAsync();

            await sftpClient.CreateDirectoryAsync($"{directoryPath}/childdir");

            using var file2 = await sftpClient.CreateNewFileAsync($"{directoryPath}/childdir/file2", FileAccess.Write);
            await file2.CloseAsync();

            List<(string Path, FileAttributes Attributes)> entries = await sftpClient.GetDirectoryEntriesAsync(directoryPath, new EnumerationOptions() { RecurseSubdirectories = recurse }).ToListAsync();

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

        [Fact]
        public void DefaultEnumerationOptions()
        {
            var options = new EnumerationOptions();

            Assert.False(options.RecurseSubdirectories);
        }
    }
}

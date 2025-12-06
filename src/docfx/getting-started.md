The following example shows how you can connect to an SSH server and execute a command. The example assumes you have already setup user credentials and trust the server so that `ssh <destination>` works.

Create a new Console application:
```sh
dotnet new console -o example
cd example
dotnet add package Tmds.Ssh
```

Update `Program.cs`:
```cs
using Tmds.Ssh;

using var sshClient = new SshClient("localhost");
using var process = await sshClient.ExecuteAsync("echo 'hello world!'");
(bool isError, string? line) = await process.ReadLineAsync();
Console.WriteLine(line);
```

Now run the application:
```sh
$ dotnet run
hello world!
```

For additional examples, see the documentation of <xref:Tmds.Ssh.SshClient> and <xref:Tmds.Ssh.SftpClient>.
using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Tmds.Ssh.TestApp
{
    class Program
    {
        static async Task<int> Main(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine("Specify a host to connect to, and a command ('http'/'exec')");
                return 1;
            }

            string password = null;
            // password = ReadPassword();

            string command = args[1];

            using var client = new SshClient(args[0],
            settings =>
            {
                if (password == null)
                {
                    settings.Credentials.Add(new IdentityFileCredential(IdentityFileCredential.RsaIdentityFile));
                }
                else
                {
                    settings.Credentials.Add(new PasswordCredential(password));
                }
                settings.Logger = CreateLogger();
                // settings.HostKeyVerification = HostKeyVerification.TrustAll;
            });

            await client.ConnectAsync();

            if (command == "http")
            {
                string url = args.Length > 2 ? args[2] : "www.redhat.com";
                await MakeHttpRequestAsync(client, url);
            }
            else if (command == "exec")
            {
                string commandline = args.Length > 2 ? string.Join(' ', args.Skip(2)) : "echo 'hello world'";
                using var remoteProcess = await client.ExecuteCommandAsync(commandline);
                await remoteProcess.ReadToEndAsync(Console.OpenStandardOutput(), Console.OpenStandardError());

                Console.WriteLine("Process exited with exit code " + remoteProcess.ExitCode);
            }
            else if (command == "sftp")
            {
                using var sftpClient = await client.OpenSftpClientAsync(default);
                var file = await sftpClient.OpenFileAsync("/tmp/test", SftpOpenFlags.CreateNewOrOpen);
            }
            else
            {
                throw new ArgumentException(nameof(command));
            }

            return 0;
        }

        private static async Task MakeHttpRequestAsync(SshClient client, string host)
        {
            // Connect to web server.
            await using var stream = await client.CreateTcpConnectionAsStreamAsync(host, 80);

            // Write an http request.
            using var writer = new StreamWriter(stream, bufferSize: 1, leaveOpen: true) { AutoFlush = true };
            string request = $"GET / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n";
            await writer.WriteAsync(request);

            // Receive the response.
            using var reader = new StreamReader(stream, leaveOpen: true);
            string reply = await reader.ReadToEndAsync();

            // Print it out.
            System.Console.WriteLine(reply);
        }

        private static string ReadPassword()
        {
            System.Console.Write("Password: ");
            Console.Out.Flush();
            var sb = new StringBuilder();
            while (true)
            {
                ConsoleKeyInfo key = Console.ReadKey(intercept: true);
                if (key.Key == ConsoleKey.Enter)
                {
                    System.Console.WriteLine();
                    return sb.ToString();
                }
                else
                {
                    sb.Append(key.KeyChar);
                }
            }
        }

        static ILogger CreateLogger()
        {
            var loggerFactory = LoggerFactory.Create(builder =>
            {
                builder.AddConsole();
                builder.SetMinimumLevel(LogLevel.Trace);
            });
            return loggerFactory.CreateLogger<SshClient>();
        }
    }
}

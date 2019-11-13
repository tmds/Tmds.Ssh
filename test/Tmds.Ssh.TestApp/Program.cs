using System;
using System.IO;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Tmds.Ssh.TestApp
{
    class Program
    {
        static async Task<int> Main(string[] args)
        {
            if (args.Length == 0)
            {
                System.Console.WriteLine("Specify a host to connect to");
                return 1;
            }

            ParseUserHostAndPort(args, out string username, out string host, out int port);
            // string password = ReadPassword();

            var settings = new SshClientSettings(username, host)
            {
                Port = port,
                Credentials = { new IdentityFileCredential() }
                // Credentials = { new PasswordCredential(username, password) }
            };

            using var client = new SshClient(settings, CreateLogger());

            await client.ConnectAsync();

            await MakeHttpRequestAsync(client, "www.redhat.com");

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

        private static void ParseUserHostAndPort(string[] args, out string username, out string host, out int port)
        {
            host = args[0];
            port = 22;
            int colonPos = host.IndexOf(":");
            if (colonPos != -1)
            {
                port = int.Parse(host.Substring(colonPos + 1));
                host = host.Substring(0, colonPos);
            }
            int atPos = host.IndexOf("@");
            if (atPos != -1)
            {
                username = host.Substring(0, atPos);
                host = host.Substring(atPos + 1);
            }
            else
            {
                username = string.Empty;
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

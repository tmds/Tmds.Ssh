using System;
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

            ParseHostAndPort(args, out string host, out int port);

            var settings = new SshClientSettings
            {
                Host = host,
                Port = port
            };

            await using var client = new SshClient(settings, CreateLogger());

            await client.ConnectAsync();

            return 0;
        }

        private static void ParseHostAndPort(string[] args, out string host, out int port)
        {
            host = args[0];
            port = 22;
            int colonPos = host.IndexOf(":");
            if (colonPos != -1)
            {
                port = int.Parse(host.Substring(colonPos + 1));
                host = host.Substring(0, colonPos);
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

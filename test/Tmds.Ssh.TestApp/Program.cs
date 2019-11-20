﻿using System;
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
                System.Console.WriteLine("Specify a host to connect to, and a command ('http'/'exec')");
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
                    settings.Credentials.Add(new IdentityFileCredential());
                }
                else
                {
                    settings.Credentials.Add(new PasswordCredential(password));
                }
                settings.Logger = CreateLogger();
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
                           var remoteProcess = await client.ExecuteCommandAsync(commandline);
                var utf8Decoder = new UTF8Encoding().GetDecoder();
                byte[] buffer = new byte[1024];
                char[] decodedBuffer = new char[Encoding.UTF8.GetMaxCharCount(buffer.Length)];
                do
                {
                    (ProcessReadType readType, int bytesReceived) = await remoteProcess.ReadOutputAsync(buffer);
                    if (readType == ProcessReadType.StandardOutput)
                    {
                            int charsDecoded = utf8Decoder.GetChars(buffer, 0, bytesReceived, decodedBuffer, 0, flush: false);
                            Console.Write(decodedBuffer, 0, charsDecoded);
                            Console.Out.Flush();
                    }
                    else if (readType == ProcessReadType.ProcessExit)
                    {
                        break;
                    }
                } while (true);

                Console.WriteLine("Process exited with exit code " + remoteProcess.ExitCode);
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

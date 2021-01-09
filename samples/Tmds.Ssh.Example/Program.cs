using System;
using System.Linq;
using System.Text;
using Tmds.Ssh;
using System.Threading.Tasks;

namespace Tmds.Ssh
{
    class Program
    {
        static async Task Main(string[] args)
        {
            string destination = args.Length >= 1 ? args[0] : "localhost";
            string command = args.Length >= 2 ? args[1] : "echo 'hello world'";

            using SshClient session = new SshClient(destination);
            await session.ConnectAsync(); 
            using var channel = await session.OpenChannelAsync(new SshChannelOptions() { Command = command });
            Func<Task> channelToConsole = async () =>
            {
                try
                {
                    byte[] buffer = new byte[1024];
                    ChannelReadType readType;
                    do
                    {
                        int bytesRead;
                        (readType, bytesRead) = await channel.ReadAsync(buffer);
                        if (readType == ChannelReadType.StandardOutput)
                        {
                            Console.Write(Encoding.UTF8.GetString(buffer.AsSpan().Slice(0, bytesRead)));
                        }
                    } while (readType != ChannelReadType.Closed);
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex);
                }
            };
            Func<Task> consoleToChannel = async () =>
            {
                try
                {
                    await Task.Yield();
                    while (true)
                    {
                        string line = Console.ReadLine();
                        line += "\n";
                        await channel.WriteAsync(Encoding.UTF8.GetBytes(line));
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex);
                }
            };
            Task[] tasks = new[] { channelToConsole(), consoleToChannel() };
            Task.WaitAny(tasks);
        }
    }
}

using System;
using System.Threading.Tasks;
using System.IO;

namespace Tmds.Ssh;

class Program
{
    static async Task Main(string[] args)
    {
        string destination = args.Length >= 1 ? args[0] : "localhost";
        string command = args.Length >= 2 ? args[1] : "echo 'hello world'";

        using SshClient client = new SshClient(destination, SshConfigOptions.DefaultConfig);
        await client.ConnectAsync();

        using var process = await client.ExecuteAsync(command);
        Task[] tasks = new[]
        {
                PrintToConsole(process),
                ReadInputFromConsole(process)
            };
        Task.WaitAny(tasks);
        PrintExceptions(tasks);

        static async Task PrintToConsole(RemoteProcess process)
        {
            await foreach ((bool isError, string line) in process.ReadAllLinesAsync())
            {
                Console.WriteLine(line);
            }
        }

        static async Task ReadInputFromConsole(RemoteProcess process)
        {
            // note: Console doesn't have an async ReadLine that accepts a CancellationToken...
            await Task.Yield();
            var cancellationToken = process.ExecutionAborted;
            while (!cancellationToken.IsCancellationRequested)
            {
                string? line = Console.ReadLine();
                if (line == null)
                {
                    break;
                }
                await process.WriteLineAsync(line);
            }
        }

        static void PrintExceptions(Task[] tasks)
        {
            foreach (var task in tasks)
            {
                Exception? innerException = task.Exception?.InnerException;
                if (innerException is not null)
                {
                    System.Console.WriteLine("Exception:");
                    Console.WriteLine(innerException);
                }
            }
        }
    }
}

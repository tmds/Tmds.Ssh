using System.Diagnostics;
using Xunit;

namespace Tmds.Ssh.Tests;

// Runs an 'ssh-agent' for the duration of a test.
sealed class LocalSshAgent : IDisposable
{
    private Process? _sshAgentProcess;

    public string Address { get; }

    public LocalSshAgent()
    {
        Address = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
    }

    public void Start()
    {
        var psi = new ProcessStartInfo()
        {
            FileName = "ssh-agent",
            ArgumentList = { "-c", "-D", "-a", Address },
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
        };
        _sshAgentProcess = Process.Start(psi);
    }

    public void Add(string keyFile)
    {
        // If we're adding keys too soon after starting the agent, it may not be ready yet.
        // Retry a few times with a delay.
        const int RetryCount = 10;
        const int RetryDelay = 500;
        int exitCode = -1;
        for (int i = 0; i < RetryCount; i++)
        {
            var psi = new ProcessStartInfo()
            {
                FileName = "ssh-add",
                ArgumentList = { "-q", keyFile },
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                RedirectStandardInput = true,
            };
            psi.EnvironmentVariables["SSH_AUTH_SOCK"] = Address;
            using var addProcess = Process.Start(psi)!;
            addProcess.WaitForExit();
            string stderr = addProcess.StandardError.ReadToEnd().Trim();
            if (stderr.Length != 0)
            {
                Console.WriteLine("ssh-add stderr: " + stderr);
            }
            exitCode = addProcess.ExitCode;
            if (exitCode == 0)
            {
                break;
            }
            Thread.Sleep(RetryDelay);
        }
        Assert.Equal(0, exitCode);
    }

    public void Dispose()
    {
        if (_sshAgentProcess is not null)
        {
            try
            {
                _sshAgentProcess.Kill();
                string stderr = _sshAgentProcess.StandardError.ReadToEnd().Trim();
                if (stderr.Length != 0)
                {
                    Console.WriteLine("ssh-agent stderr: " + stderr);
                }
                _sshAgentProcess.WaitForExit();
            }
            catch
            { }
        }
        try
        {
            File.Delete(Address);
        }
        catch
        { }
    }
}

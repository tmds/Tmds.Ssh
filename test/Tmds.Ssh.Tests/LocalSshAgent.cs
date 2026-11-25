using System.Diagnostics;
using Xunit;

namespace Tmds.Ssh.Tests;

// Runs an 'ssh-agent' for the duration of a test.
// When containerImage is provided, runs ssh-agent from that container
// (needed for ML-DSA key type support on hosts with older OpenSSH).
sealed class LocalSshAgent : IDisposable
{
    private Process? _sshAgentProcess;
    private string? _containerId;
    private readonly string? _containerImage;
    private int _keyIndex;

    public string Address { get; }

    public LocalSshAgent(string? containerImage = null)
    {
        string socketDir = Directory.CreateTempSubdirectory().FullName;
        Address = Path.Combine(socketDir, "agent.sock");
        _containerImage = containerImage;
    }

    public void Start()
    {
        if (_containerImage is not null)
        {
            StartContainer();
        }
        else
        {
            StartProcess();
        }
    }

    private void StartContainer()
    {
        string socketDir = Path.GetDirectoryName(Address)!;
        var psi = new ProcessStartInfo()
        {
            FileName = "podman",
            ArgumentList = { "run", "--rm", "-d",
                "-v", $"{socketDir}:{socketDir}:Z",
                _containerImage!,
                "ssh-agent", "-D", "-a", Address },
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        using var process = Process.Start(psi)!;
        string stdout = process.StandardOutput.ReadToEnd().Trim();
        process.WaitForExit();
        Assert.Equal(0, process.ExitCode);
        _containerId = stdout;
    }

    private void StartProcess()
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
            exitCode = _containerId is not null
                ? AddViaContainer(keyFile)
                : AddViaProcess(keyFile);
            if (exitCode == 0)
            {
                break;
            }
            Thread.Sleep(RetryDelay);
        }
        Assert.Equal(0, exitCode);
    }

    private int AddViaContainer(string keyFile)
    {
        string absKeyFile = Path.GetFullPath(keyFile);
        string containerKeyPath = $"/tmp/agent_key_{_keyIndex++}";

        // Copy key into the running container.
        RunCommand("podman", ["cp", absKeyFile, $"{_containerId}:{containerKeyPath}"]);
        RunCommand("podman", ["exec", _containerId!, "chmod", "600", containerKeyPath]);

        var psi = new ProcessStartInfo()
        {
            FileName = "podman",
            ArgumentList = { "exec",
                "-e", $"SSH_AUTH_SOCK={Address}",
                _containerId!, "ssh-add", "-q", containerKeyPath },
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        using var process = Process.Start(psi)!;
        process.WaitForExit();
        string stderr = process.StandardError.ReadToEnd().Trim();
        if (stderr.Length != 0)
        {
            Console.WriteLine("ssh-add stderr: " + stderr);
        }
        return process.ExitCode;
    }

    private int AddViaProcess(string keyFile)
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
        return addProcess.ExitCode;
    }

    public void Dispose()
    {
        if (_containerId is not null)
        {
            try
            {
                RunCommand("podman", ["kill", _containerId]);
            }
            catch
            { }
        }
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
            Directory.Delete(Path.GetDirectoryName(Address)!, recursive: true);
        }
        catch
        { }
    }

    private static void RunCommand(string fileName, string[] args)
    {
        var psi = new ProcessStartInfo() { FileName = fileName, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var arg in args)
        {
            psi.ArgumentList.Add(arg);
        }
        using var p = Process.Start(psi)!;
        p.WaitForExit();
    }
}

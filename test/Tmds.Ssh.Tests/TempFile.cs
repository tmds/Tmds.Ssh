using System;
using System.IO;

namespace Tmds.Ssh.Tests;

struct TempFile : IDisposable
{
    public string Path { get; }

    public TempFile(string path)
    {
        Path = path;
    }

    public void Dispose()
    {
        try
        {
            File.Delete(Path);
        }
        catch
        { }
    }
}

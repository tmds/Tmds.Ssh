// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Text;

namespace Tmds.Ssh;

// TODO: support envvars.
public sealed class ExecuteOptions
{
    internal static readonly UTF8Encoding DefaultEncoding =
        new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);

    private Encoding _stdinEncoding = DefaultEncoding;
    private Encoding _stdoutEncoding = DefaultEncoding;
    private Encoding _stderrEncoding = DefaultEncoding;
    private string _term = "xterm-256color";
    private int _termWidth = 80;
    private int _termHeight = 24;
    private Dictionary<string, string>? _environmentVariables;

    internal Dictionary<string, string>? EnvironmentVariablesOrDefault
        => _environmentVariables;

    public Encoding StandardInputEncoding
    {
        get => _stdinEncoding;
        set
        {
            ArgumentNullException.ThrowIfNull(value);
            _stdinEncoding = value;
        }
    }

    public Encoding StandardErrorEncoding
    {
        get => _stdoutEncoding;
        set
        {
            ArgumentNullException.ThrowIfNull(value);
            _stdoutEncoding = value;
        }
    }

    public Encoding StandardOutputEncoding
    {
        get => _stderrEncoding;
        set
        {
            ArgumentNullException.ThrowIfNull(value);
            _stderrEncoding = value;
        }
    }

    public bool AllocateTerminal { get; set; } = false;

    public int TerminalWidth
    {
        get => _termWidth;
        set
        {
            ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(value, 0);
            _termWidth = value;
        }
    }

    public int TerminalHeight
    {
        get => _termHeight;
        set
        {
            ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(value, 0);
            _termHeight = value;
        }
    }

    public string TerminalType
    {
        get => _term;
        set
        {
            ArgumentException.ThrowIfNullOrEmpty(value);
            _term = value;
        }
    }

    public TerminalSettings TerminalSettings { get; } = new();

    public Dictionary<string, string> EnvironmentVariables
    {
        get => _environmentVariables ??= new();
        set
        {
            ArgumentNullException.ThrowIfNull(value);
            _environmentVariables = value;
        }
    }

    internal byte[] GetTerminalModeString()
    {
        bool isUtf8Encoding = _stdinEncoding is UTF8Encoding && _stdoutEncoding is UTF8Encoding && _stderrEncoding is UTF8Encoding;
        return TerminalSettings.GetModeString(isUtf8Encoding);
    }
}

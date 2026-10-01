// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Text;

namespace Tmds.Ssh;

/// <summary>
/// Options for executing commands.
/// </summary>
public sealed class ExecuteOptions
{
    internal static readonly UTF8Encoding DefaultEncoding =
        new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);

    private Encoding _stdinEncoding = DefaultEncoding;
    private Encoding _stdoutEncoding = DefaultEncoding;
    private Encoding _stderrEncoding = DefaultEncoding;
    private string _term = "xterm-256color";
    private Dictionary<string, string>? _environmentVariables;
    private int? _windowSize;

    internal Dictionary<string, string>? EnvironmentVariablesOrDefault
        => _environmentVariables;

    /// <summary>
    /// Gets or sets the <see cref="Encoding"/> for standard input.
    /// </summary>
    public Encoding StandardInputEncoding
    {
        get => _stdinEncoding;
        set
        {
            ArgumentNullException.ThrowIfNull(value);
            _stdinEncoding = value;
        }
    }

    /// <summary>
    /// Gets or sets the <see cref="Encoding"/> for standard error.
    /// </summary>
    public Encoding StandardErrorEncoding
    {
        get => _stdoutEncoding;
        set
        {
            ArgumentNullException.ThrowIfNull(value);
            _stdoutEncoding = value;
        }
    }

    /// <summary>
    /// Gets or sets the <see cref="Encoding"/> for standard output.
    /// </summary>
    public Encoding StandardOutputEncoding
    {
        get => _stderrEncoding;
        set
        {
            ArgumentNullException.ThrowIfNull(value);
            _stderrEncoding = value;
        }
    }

    /// <summary>
    /// Gets or sets whether to allocate a pseudo-terminal.
    /// </summary>
    /// <remarks>
    /// Defaults to <see langword="false"/>.
    /// </remarks>
    public bool AllocateTerminal { get; set; } = false;

    /// <summary>
    /// Gets or sets the size of the terminal.
    /// </summary>
    /// <remarks>
    /// Defaults to 80 columns by 24 rows, without a pixel size.
    /// </remarks>
    public TerminalSize TerminalSize { get; set; } = new(columns: 80, rows: 24);

    /// <summary>
    /// Gets or sets the terminal type.
    /// </summary>
    /// <remarks>
    /// Defaults to "xterm-256color".
    /// </remarks>
    public string TerminalType
    {
        get => _term;
        set
        {
            ArgumentException.ThrowIfNullOrEmpty(value);
            _term = value;
        }
    }

    /// <summary>
    /// Configure additional terminal settings.
    /// </summary>
    public TerminalSettings TerminalSettings { get; } = new();

    /// <summary>
    /// Gets or sets environment variables for the remote process.
    /// </summary>
    /// <remarks>
    /// <para>Often SSH servers don't accept environment variables (for security).</para>
    /// <para>When <see cref="AllocateTerminal"/> is set to <see langword="true"/>, 'TERM' is ignored when its value does not match <see cref="TerminalType"/>.</para>
    /// </remarks>
    public Dictionary<string, string> EnvironmentVariables
    {
        get => _environmentVariables ??= new();
        set
        {
            ArgumentNullException.ThrowIfNull(value);
            _environmentVariables = value;
        }
    }

    /// <summary>
    /// Gets or sets whether to request X11 forwarding.
    /// </summary>
    /// <remarks>
    /// <para>When <see langword="null"/> (the default), <see cref="SshClientSettings.ForwardX11"/> is used.</para>
    /// <para>When set to <see cref="ForwardMode.Request"/>, X11 setup failures are logged and the remote process is started without X11 forwarding.
    /// When set to <see cref="ForwardMode.Require"/>, X11 setup failures fail the operation.</para>
    /// <para>The forwarded display and authentication are configured using <see cref="SshClientSettings.X11Display"/>, <see cref="SshClientSettings.ForwardX11Trusted"/>, <see cref="SshClientSettings.ForwardX11Timeout"/>, and <see cref="SshClientSettings.XAuthLocation"/>.</para>
    /// </remarks>
    public ForwardMode? ForwardX11 { get; set; }

    /// <summary>
    /// Gets or sets the SSH channel window size in bytes.
    /// </summary>
    /// <remarks>
    /// <para>When <see langword="null"/> (the default), <see cref="SshClientSettings.DefaultWindowSize"/> is used.</para>
    /// <para>The window size controls the maximum amount of data that can be sent by the remote end before it must wait for acknowledgement.
    /// Larger values can improve throughput on high-latency or high-bandwidth links at the cost of higher memory usage per channel.</para>
    /// </remarks>
    public int? WindowSize
    {
        get => _windowSize;
        set
        {
            if (value.HasValue)
            {
                ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(value.Value, 0);
            }
            _windowSize = value;
        }
    }

    internal byte[] GetTerminalModeString()
    {
        bool isUtf8Encoding = _stdinEncoding is UTF8Encoding && _stdoutEncoding is UTF8Encoding && _stderrEncoding is UTF8Encoding;
        return TerminalSettings.GetModeString(isUtf8Encoding);
    }
}

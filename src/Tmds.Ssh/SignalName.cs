// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

/// <summary>
/// Unix signal names.
/// </summary>
// https://datatracker.ietf.org/doc/html/rfc4254#section-6.10
public static class SignalName
{
    /// <summary>Abort.</summary>
    public const string ABRT = "ABRT";
    /// <summary>Timer.</summary>
    public const string ALRM = "ALRM";
    /// <summary>Erroneous arithmetic operation.</summary>
    public const string FPE = "FPE";
    /// <summary>Hangup.</summary>
    public const string HUP = "HUP";
    /// <summary>Illegal Instruction.</summary>
    public const string ILL = "ILL";
    /// <summary>Interrupt.</summary>
    public const string INT = "INT";
    /// <summary>Kill.</summary>
    public const string KILL = "KILL";
    /// <summary>Broken pipe.</summary>
    public const string PIPE = "PIPE";
    /// <summary>Quit.</summary>
    public const string QUIT = "QUIT";
    /// <summary>Invalid memory reference.</summary>
    public const string SEGV = "SEGV";
    /// <summary>Termination.</summary>
    public const string TERM = "TERM";
    /// <summary>User-defined 1.</summary>
    public const string USR1 = "USR1";
    /// <summary>User-defined 2.</summary>
    public const string USR2 = "USR2";
}
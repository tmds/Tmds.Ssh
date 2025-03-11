// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

// https://datatracker.ietf.org/doc/html/rfc4254#section-6.10
public static class SignalName
{
    public const string ABRT = "ABRT";
    public const string ALRM = "ALRM";
    public const string FPE = "FPE";
    public const string HUP = "HUP";
    public const string ILL = "ILL";
    public const string INT = "INT";
    public const string KILL = "KILL";
    public const string PIPE = "PIPE";
    public const string QUIT = "QUIT";
    public const string SEGV = "SEGV";
    public const string TERM = "TERM";
    public const string USR1 = "USR1";
    public const string USR2 = "USR2";
}
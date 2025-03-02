// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

public sealed class TerminalSettings
{
    // https://datatracker.ietf.org/doc/html/rfc4254#section-8
    private const byte TTY_OP_END = 0;
    private const byte VINTR = 1;
    private const byte VQUIT = 2;
    private const byte VERASE = 3;
    private const byte VKILL = 4;
    private const byte VEOF = 5;
    private const byte VEOL = 6;
    private const byte VEOL2 = 7;
    private const byte VSTART = 8;
    private const byte VSTOP = 9;
    private const byte VSUSP = 10;
    private const byte VDSUSP = 11;
    private const byte VREPRINT = 12;
    private const byte VWERASE = 13;
    private const byte VLNEXT = 14;
    private const byte VFLUSH = 15;
    private const byte VSWTCH = 16;
    private const byte VSTATUS = 17;
    private const byte VDISCARD = 18;
    private const byte IGNPAR = 30;
    private const byte PARMRK = 31;
    private const byte INPCK = 32;
    private const byte ISTRIP = 33;
    private const byte INLCR = 34;
    private const byte IGNCR = 35;
    private const byte ICRNL = 36;
    private const byte IUCLC = 37;
    private const byte IXON = 38;
    private const byte IXANY = 39;
    private const byte IXOFF = 40;
    private const byte IMAXBEL = 41;
    private const byte ISIG = 50;
    private const byte ICANON = 51;
    private const byte XCASE = 52;
    private const byte ECHO = 53;
    private const byte ECHOE = 54;
    private const byte ECHOK = 55;
    private const byte ECHONL = 56;
    private const byte NOFLSH = 57;
    private const byte TOSTOP = 58;
    private const byte IEXTEN = 59;
    private const byte ECHOCTL = 60;
    private const byte ECHOKE = 61;
    private const byte PENDIN = 62;
    private const byte OPOST = 70;
    private const byte OLCUC = 71;
    private const byte ONLCR = 72;
    private const byte OCRNL = 73;
    private const byte ONOCR = 74;
    private const byte ONLRET = 75;
    private const byte CS7 = 90;
    private const byte CS8 = 91;
    private const byte PARENB = 92;
    private const byte PARODD = 93;
    private const byte TTY_OP_ISPEED = 128;
    private const byte TTY_OP_OSPEED = 129;
    // https://datatracker.ietf.org/doc/html/rfc8160
    private const byte IUTF8 = 42;

    public const byte DisableCharacter = 0xff;

    public bool? IsUtf8 { get; set; } = null; // Follow ExecuteOptions.Encoding.

    // VINTR
    public byte InterruptCharacter { get; set; } = (byte)'C' - 0x40;
    // VQUIT
    public byte QuitCharacter { get; set; } = (byte)'\\' - 0x40;
    // VERASE
    public byte EraseCharacter { get; set; } = 0x7F; // DEL
    // VKILL
    public byte EraseToLineStartCharacter { get; set; } = (byte)'U' - 0x40;
    // VEOF
    public byte EndOfFileCharacter { get; set; } = (byte)'D' - 0x40;
    // VSTART
    public byte StartOutputCharacter { get; set; } = (byte)'Q' - 0x40;
    // VSTOP
    public byte StopOutputCharacter { get; set; } = (byte)'S' - 0x40;
    // VSUSP
    public byte SuspendCharacter { get; set; } = (byte)'Z' - 0x40;
    // VDSUSP
    public byte DelayedSuspendCharacter { get; set; } = (byte)'Y' - 0x40;
    // VREPRINT
    public byte ReprintLineCharacter { get; set; } = (byte)'R' - 0x40;
    // VWERASE
    public byte EraseWordCharacter { get; set; } = (byte)'W' - 0x40;
    // VLNEXT
    public byte LiteralNextCharacter { get; set; } = (byte)'V' & 0x1f;
    // VDISCARD
    public byte ToggleOutputDiscardCharacter { get; set; } = (byte)'O' & 0x1f;
    // VEOL
    public byte AdditionalEndOfLineCharacter { get; set; } = DisableCharacter;
    // VEOL2
    public byte AdditionalEndOfLineCharacter2 { get; set; } = DisableCharacter;

    // NOFLSH
    public bool DisableFlushOnInterrupt { get; set; } = false;
    // TOSTOP
    public bool StopBackgroundProcessesOnOutput { get; set; } = false;
    // IXON
    public bool EnableOutputControlFlow { get; set; } = true;
    // ISIG
    public bool EnableInputSignals { get; set; } = true;

    // ECHO
    public bool Echo { get; set; } = true;
    // ECHOE
    public bool EchoErase { get; set; } = true;
    // ECHOK
    public bool EchoEraseLine { get; set; } = true;
    // ECHOKE
    public bool EchoVisualEraseLine { get; set; } = true;
    // ECHOCTL
    public bool EchoControlCharacters { get; set; } = true;
    // ECHONL
    public bool EchoNl { get; set; } = false;

     // ICANON
    public bool InputLineByLine { get; set; } = true;
    // IEXTEN
    public bool InputEnableExtensions { get; set; } = true;
    // ICRNL
    public bool InputMapCrToNl { get; set; } = true;
    // IXANY
    public bool InputRestartOnAnyChar { get; set; } = false;
    // INLCR
    public bool InputMapNlToCr { get; set; } = false;
    // IGNCR
    public bool InputIgnoreCr { get; set; } = false;

    // OPOST
    public bool OutputEnableProcessing { get; set; } = true;
    // ONLCR
    public bool OutputMapNlToCrNl { get; set; } = true;
    // OCRNL
    public bool OutputMapCrToNl { get; set; } = false;

    /* These are private because considered of no/limited use for pseudo ttys over SSH . */
    // IMAXBEL
    private bool OutputBellWhenInputFull { get; set; } = true;
    // IUCLC
    private bool InputMapLowerToUpper { get; set; } = false;
    // OLCUC
    private bool OutputMapLowerToUpper { get; set; } = false;
    // XCASE
    private bool EnableInputCasing { get; set; } = false;
    // PENDIN
    private bool ReprintPendingInput { get; set; } = false;
    // ONLRET
    private bool OutputCrOnNl { get; set; } = false;
    // ONOCR
    private bool OutputIgnoreCrAtStart { get; set; } = false;
    // IXOFF
    private bool EnableInputFlowControl { get; set; } = false;
    // VFLUSH
    private byte FlushCharacter { get; set; } = DisableCharacter;
    // VSWTCH
    private byte SwitchShellCharacter { get; set; } = DisableCharacter;
    // VSTATUS
    private byte PrintStatusCharacter { get; set; } = DisableCharacter;
    // IGNPAR
    private bool IgnoreParityErrors { get; set; } = false;
    // PARMRK
    private bool MarkParityErrors { get; set; } = false;
    // INPCK
    private bool EnableInputParityChecking { get; set; } = false;
    // ISTRIP
    private bool InputStrip8thBit { get; set; } = false;
    // PARENB
    private bool EnableParityBitGeneration { get; set; } = false;
    // PARODD
    private bool UseOddParity { get; set; } = false;
    // CS7 / CS8
    private bool Use7Bit { get; set; } = false;
    // TTY_OP_ISPEED
    private int InputBaudRate { get; set; } = 38400;
    // TTY_OP_OSPEED
    private int OutputBaudRate { get; set; } = 38400;

    internal byte[] GetModeString(bool isUtf8)
    {
        using var writer = new ArrayWriter();
        writer.WriteByte(VINTR); writer.WriteUInt32(InterruptCharacter);
        writer.WriteByte(VQUIT); writer.WriteUInt32(QuitCharacter);
        writer.WriteByte(VERASE); writer.WriteUInt32(EraseCharacter);
        writer.WriteByte(VKILL); writer.WriteUInt32(EraseToLineStartCharacter);
        writer.WriteByte(VEOF); writer.WriteUInt32(EndOfFileCharacter);
        writer.WriteByte(VSTART); writer.WriteUInt32(StartOutputCharacter);
        writer.WriteByte(VSTOP); writer.WriteUInt32(StopOutputCharacter);
        writer.WriteByte(VSUSP); writer.WriteUInt32(SuspendCharacter);
        writer.WriteByte(VDSUSP); writer.WriteUInt32(DelayedSuspendCharacter);
        writer.WriteByte(VREPRINT); writer.WriteUInt32(ReprintLineCharacter);
        writer.WriteByte(VWERASE); writer.WriteUInt32(EraseWordCharacter);
        writer.WriteByte(VLNEXT); writer.WriteUInt32(LiteralNextCharacter);
        writer.WriteByte(VDISCARD); writer.WriteUInt32(ToggleOutputDiscardCharacter);
        writer.WriteByte(VEOL); writer.WriteUInt32(AdditionalEndOfLineCharacter);
        writer.WriteByte(VEOL2); writer.WriteUInt32(AdditionalEndOfLineCharacter2);
        writer.WriteByte(VFLUSH); writer.WriteUInt32(FlushCharacter);
        writer.WriteByte(VSWTCH); writer.WriteUInt32(SwitchShellCharacter);
        writer.WriteByte(VSTATUS); writer.WriteUInt32(PrintStatusCharacter);

        writer.WriteByte(IGNPAR); writer.WriteUInt32(IgnoreParityErrors ? 1 : 0);
        writer.WriteByte(PARMRK); writer.WriteUInt32(MarkParityErrors ? 1 : 0);
        writer.WriteByte(INPCK); writer.WriteUInt32(EnableInputParityChecking ? 1 : 0);
        writer.WriteByte(ISTRIP); writer.WriteUInt32(InputStrip8thBit ? 1 : 0);
        writer.WriteByte(INLCR); writer.WriteUInt32(InputMapNlToCr ? 1 : 0);
        writer.WriteByte(IGNCR); writer.WriteUInt32(InputIgnoreCr ? 1 : 0);
        writer.WriteByte(ICRNL); writer.WriteUInt32(InputMapCrToNl ? 1 : 0);
        writer.WriteByte(IUCLC); writer.WriteUInt32(InputMapLowerToUpper ? 1 : 0);
        writer.WriteByte(IXON); writer.WriteUInt32(EnableOutputControlFlow ? 1 : 0);
        writer.WriteByte(IXANY); writer.WriteUInt32(InputRestartOnAnyChar ? 1 : 0);
        writer.WriteByte(IXOFF); writer.WriteUInt32(EnableInputFlowControl ? 1 : 0);
        writer.WriteByte(IMAXBEL); writer.WriteUInt32(OutputBellWhenInputFull ? 1 : 0);
        writer.WriteByte(ISIG); writer.WriteUInt32(EnableInputSignals ? 1 : 0);
        writer.WriteByte(ICANON); writer.WriteUInt32(InputLineByLine ? 1 : 0);
        writer.WriteByte(XCASE); writer.WriteUInt32(EnableInputCasing ? 1 : 0);
        writer.WriteByte(ECHO); writer.WriteUInt32(Echo ? 1 : 0);
        writer.WriteByte(ECHONL); writer.WriteUInt32(EchoNl ? 1 : 0);
        writer.WriteByte(ECHOE); writer.WriteUInt32(EchoErase ? 1 : 0);
        writer.WriteByte(ECHOK); writer.WriteUInt32(EchoEraseLine ? 1 : 0);
        writer.WriteByte(ECHOKE); writer.WriteUInt32(EchoVisualEraseLine ? 1 : 0);
        writer.WriteByte(NOFLSH); writer.WriteUInt32(DisableFlushOnInterrupt ? 1 : 0);
        writer.WriteByte(TOSTOP); writer.WriteUInt32(StopBackgroundProcessesOnOutput ? 1 : 0);
        writer.WriteByte(IEXTEN); writer.WriteUInt32(InputEnableExtensions ? 1 : 0);
        writer.WriteByte(ECHOCTL); writer.WriteUInt32(EchoControlCharacters ? 1 : 0);
        writer.WriteByte(PENDIN); writer.WriteUInt32(ReprintPendingInput ? 1 : 0);
        writer.WriteByte(OPOST); writer.WriteUInt32(OutputEnableProcessing ? 1 : 0);
        writer.WriteByte(OLCUC); writer.WriteUInt32(OutputMapLowerToUpper ? 1 : 0);
        writer.WriteByte(ONLCR); writer.WriteUInt32(OutputMapNlToCrNl ? 1 : 0);
        writer.WriteByte(OCRNL); writer.WriteUInt32(OutputMapCrToNl ? 1 : 0);
        writer.WriteByte(ONOCR); writer.WriteUInt32(OutputIgnoreCrAtStart ? 1 : 0);
        writer.WriteByte(ONLRET); writer.WriteUInt32(OutputCrOnNl ? 1 : 0);
        writer.WriteByte(PARENB); writer.WriteUInt32(EnableParityBitGeneration ? 1 : 0);
        writer.WriteByte(PARODD); writer.WriteUInt32(UseOddParity ? 1 : 0);

        if (Use7Bit)
        {
            writer.WriteByte(CS7); writer.WriteUInt32(1);
        }
        else
        {
            writer.WriteByte(CS8); writer.WriteUInt32(1);
        }

        bool setUtf8 = IsUtf8 == true || (!IsUtf8.HasValue && isUtf8);
        if (setUtf8)
        {
            writer.WriteByte(IUTF8); writer.WriteUInt32(1);
        }

        writer.WriteByte(TTY_OP_ISPEED); writer.WriteUInt32(InputBaudRate);
        writer.WriteByte(TTY_OP_OSPEED); writer.WriteUInt32(OutputBaudRate);

        writer.WriteByte(TTY_OP_END);

        return writer.ToArray();
    }
}

// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Text;

namespace Tmds.Ssh;

// TODO: support envvars.
public sealed class ExecuteOptions
{
    internal static readonly UTF8Encoding DefaultEncoding =
        new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);

    public Encoding StandardInputEncoding { get; set; } = DefaultEncoding;
    public Encoding StandardErrorEncoding { get; set; } = DefaultEncoding;
    public Encoding StandardOutputEncoding { get; set; } = DefaultEncoding;
}

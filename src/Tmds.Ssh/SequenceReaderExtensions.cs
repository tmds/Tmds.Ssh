// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Buffers;
using System.Collections.Generic;
using System.Numerics;
using System.Text;

namespace Tmds.Ssh
{
    // https://tools.ietf.org/html/rfc4251#section-5
    static class SequenceReaderExtensions
    {
        private static readonly UTF8Encoding s_utf8Encoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    }
}

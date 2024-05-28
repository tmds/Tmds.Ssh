// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Security.Cryptography;

namespace Tmds.Ssh;

public sealed class HostKey
{
    private string? _sha256FingerPrint;

    internal HostKey(string sha256FingerPrint)
    {
        _sha256FingerPrint = sha256FingerPrint;
        Type = "";
        RawKey = Array.Empty<byte>();
    }

    public string SHA256FingerPrint
    {
        get
        {
            if (_sha256FingerPrint == null)
            {
                Span<byte> hash = stackalloc byte[32];
                SHA256.HashData(RawKey, hash);
                _sha256FingerPrint = Convert.ToBase64String(hash).TrimEnd('=');
            }
            return _sha256FingerPrint;
        }
    }

    // Managed
    internal HostKey(string type, byte[] key)
    {
        Type = type ?? throw new ArgumentNullException(nameof(type));
        RawKey = key ?? throw new ArgumentNullException(nameof(key));
    }
    internal string Type { get; } // TODO: type as 'Name'?
    internal byte[] RawKey { get; }
}

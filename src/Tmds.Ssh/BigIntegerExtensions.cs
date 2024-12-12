using System.Numerics;
using System.Diagnostics;

namespace Tmds.Ssh;

static class BigIntegerExtensions
{
    public static byte[] ToBEByteArray(this BigInteger integer, bool isUnsigned, int minLength)
    {
        int bytesNeeded = integer.GetByteCount(isUnsigned);
        int length = Math.Max(bytesNeeded, minLength);
        byte[] array = new byte[length];
        int prefixLength = length - bytesNeeded;
        bool success = integer.TryWriteBytes(array.AsSpan(prefixLength), out _, isUnsigned, isBigEndian: true);
        Debug.Assert(success); // Can't fail since the array is large enough.
        if (prefixLength != 0 && integer.Sign < 0)
        {
            array.AsSpan(0, prefixLength).Fill(0xff);
        }
        return array;
    }
}
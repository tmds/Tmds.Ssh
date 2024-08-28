using Tmds.Ssh;

namespace System.Text;

ref partial struct ValueStringBuilder
{
    public void AppendLocalPathToRemotePath(ReadOnlySpan<char> value)
    {
        if (Path.DirectorySeparatorChar == Path.AltDirectorySeparatorChar)
        {
            Append(value);
        }
        else
        {
            AppendPathAndConvertSeparators(value);
        }
    }

    private void AppendPathAndConvertSeparators(ReadOnlySpan<char> value)
    {
        Span<char> span = AppendSpan(value.Length);
        value.CopyTo(span);
        for (int i = 0; i < span.Length; i++)
        {
            if (span[i] == Path.DirectorySeparatorChar)
            {
                span[i] = RemotePath.DirectorySeparatorChar;
            }
        }
    }
}
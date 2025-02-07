// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Text;
using System.Diagnostics;

namespace Tmds.Ssh;

// Represents a fixed name used to identify an algorithm, key type, ...
// The type is optimized to work with the identifiers that are known to the library.
readonly struct Name : IEquatable<Name>, ISpanFormattable
{
    // Disallow control characters, space, non ASCII.
    private const byte LowInclusive = 33;
    private const byte HighInclusive = 126;

    private readonly string _name;
    private readonly bool _isKnown;

    private Name(string name, bool isKnown)
    {
        _name = name;
        _isKnown = isKnown;
    }

    internal Name(string name)
    {
        string? knownNameString = KnownNameStrings.FindKnownName(name);
        if (knownNameString is not null)
        {
            _name = knownNameString;
            _isKnown = true;
        }
        else
        {
            if (name.AsSpan().ContainsAnyExceptInRange((char)LowInclusive, (char)HighInclusive))
            {
                throw new ArgumentException($"Name '{name}' contains invalid characters.", nameof(name));
            }
            _name = name;
        }
    }

    internal Name(ReadOnlySpan<char> name)
    {
        string? knownNameString = KnownNameStrings.FindKnownName(name);
        if (knownNameString is not null)
        {
            _name = knownNameString;
            _isKnown = true;
        }
        else
        {
            if (name.ContainsAnyExceptInRange((char)LowInclusive, (char)HighInclusive))
            {
                ThrowHelper.ThrowDataInvalidName();
            }
            _name = name.ToString();
        }
    }

    internal static Name FromKnownNameString(string name)
    {
        // Ensure MaxNameLength is large enough to fit any known name.
        Debug.Assert(name.Length <= Constants.MaxParseNameLength);
        Debug.Assert(KnownNameStrings.FindKnownName(name) is not null);
        return new Name(name, isKnown: true);
    }

    internal bool IsKnown => _isKnown;

    internal bool EndsWith(string suffix)
        => ToString().EndsWith(suffix, StringComparison.Ordinal);

    internal static Name Parse(ReadOnlySpan<byte> name)
    {
        // Refuse to parse names that are very long.
        if (name.Length > Constants.MaxParseNameLength)
        {
            ThrowHelper.ThrowDataNameTooLong();
        }

        if (name.ContainsAnyExceptInRange(LowInclusive, HighInclusive))
        {
            ThrowHelper.ThrowDataInvalidName();
        }

        Debug.Assert(Constants.MaxParseNameLength <= Constants.StackallocThreshold);
        Span<char> charSpan = stackalloc char[name.Length];
        Encoding.ASCII.GetChars(name, charSpan);

        string? knownNameString = KnownNameStrings.FindKnownName(charSpan);
        if (knownNameString is not null)
        {
            return FromKnownNameString(knownNameString);
        }

        return new Name(charSpan.ToString(), isKnown: false);
    }

    public override string ToString()
    {
        return _name  ?? "";
    }

    public override int GetHashCode()
        => ToString().GetHashCode();

    public bool Equals(Name other)
    {
        if (ReferenceEquals(_name, other._name))
        {
            return true;
        }
        if (IsKnown || other.IsKnown)
        {
            return false;
        }
        return ToString() == other.ToString();
    }

    public override bool Equals(object? obj)
    {
        return obj is Name name && Equals(name);
    }

    bool ISpanFormattable.TryFormat(Span<char> destination, out int charsWritten, ReadOnlySpan<char> format, IFormatProvider? provider)
    {
        string s = ToString();
        if (destination.Length < s.Length)
        {
            charsWritten = 0;
            return false;
        }
        s.AsSpan().CopyTo(destination);
        charsWritten = s.Length;
        return true;
    }

    string IFormattable.ToString(string? format, IFormatProvider? formatProvider)
        => ToString();

    public static bool operator ==(Name left, Name right)
    {
        return left.Equals(right);
    }

    public static bool operator !=(Name left, Name right)
    {
        return !(left == right);
    }

    public static implicit operator string(Name name)
        => name.ToString();

    public bool IsEmpty => ToString().Length == 0;
}

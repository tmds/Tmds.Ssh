// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

/// <summary>
/// Represents the size of a terminal.
/// </summary>
/// <remarks>
/// The size is expressed in characters (<see cref="Columns"/> and <see cref="Rows"/>)
/// and, optionally, in pixels (<see cref="WidthPixels"/> and <see cref="HeightPixels"/>).
/// Pixel dimensions can be 0 when unspecified.
/// </remarks>
public readonly struct TerminalSize : IEquatable<TerminalSize>
{
    /// <summary>
    /// Initializes a new <see cref="TerminalSize"/>.
    /// </summary>
    /// <param name="columns">The terminal width in characters. Must be greater than 0.</param>
    /// <param name="rows">The terminal height in characters. Must be greater than 0.</param>
    /// <param name="widthPixels">The terminal width in pixels. Use 0 when unspecified. Must not be negative.</param>
    /// <param name="heightPixels">The terminal height in pixels. Use 0 when unspecified. Must not be negative.</param>
    public TerminalSize(int columns, int rows, int widthPixels = 0, int heightPixels = 0)
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(columns, 0);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(rows, 0);
        ArgumentOutOfRangeException.ThrowIfNegative(widthPixels);
        ArgumentOutOfRangeException.ThrowIfNegative(heightPixels);

        Columns = columns;
        Rows = rows;
        WidthPixels = widthPixels;
        HeightPixels = heightPixels;
    }

    /// <summary>
    /// Gets the terminal width in characters.
    /// </summary>
    public int Columns { get; }

    /// <summary>
    /// Gets the terminal height in characters.
    /// </summary>
    public int Rows { get; }

    /// <summary>
    /// Gets the terminal width in pixels.
    /// </summary>
    /// <remarks>
    /// A value of 0 means the pixel width is unspecified.
    /// </remarks>
    public int WidthPixels { get; }

    /// <summary>
    /// Gets the terminal height in pixels.
    /// </summary>
    /// <remarks>
    /// A value of 0 means the pixel height is unspecified.
    /// </remarks>
    public int HeightPixels { get; }

    /// <summary>
    /// Determines whether this terminal size equals another.
    /// </summary>
    /// <param name="other">The terminal size to compare.</param>
    /// <returns><see langword="true"/> if terminal sizes are equal.</returns>
    public bool Equals(TerminalSize other)
    {
        return Columns == other.Columns &&
            Rows == other.Rows &&
            WidthPixels == other.WidthPixels &&
            HeightPixels == other.HeightPixels;
    }

    /// <summary>
    /// Determines whether this terminal size equals another object.
    /// </summary>
    /// <param name="obj">The object to compare.</param>
    /// <returns><see langword="true"/> if the objects are equal.</returns>
    public override bool Equals(object? obj)
    {
        return obj is TerminalSize other && Equals(other);
    }

    /// <summary>
    /// Returns the hash code for this terminal size.
    /// </summary>
    /// <returns>Hash code.</returns>
    public override int GetHashCode()
    {
        return HashCode.Combine(Columns, Rows, WidthPixels, HeightPixels);
    }

    /// <summary>
    /// Returns a string representation of the terminal size.
    /// </summary>
    /// <returns>String representation of the terminal size.</returns>
    public override string ToString()
        => WidthPixels == 0 && HeightPixels == 0
            ? $"{Columns}x{Rows}"
            : $"{Columns}x{Rows} ({WidthPixels}x{HeightPixels})";
}


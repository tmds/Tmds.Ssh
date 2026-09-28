// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

/// <summary>
/// Represents the size of a terminal.
/// </summary>
/// <remarks>
/// The size is expressed in characters (<see cref="Columns"/> and <see cref="Rows"/>)
/// and, optionally, in pixels (<see cref="WidthPixels"/> and <see cref="HeightPixels"/>).
/// A value of 0 means the dimension is unspecified.
/// </remarks>
public readonly struct TerminalSize
{
    /// <summary>
    /// Initializes a new <see cref="TerminalSize"/>.
    /// </summary>
    /// <param name="columns">The terminal width in characters. Use 0 when unspecified. Must not be negative.</param>
    /// <param name="rows">The terminal height in characters. Use 0 when unspecified. Must not be negative.</param>
    /// <param name="widthPixels">The terminal width in pixels. Use 0 when unspecified. Must not be negative.</param>
    /// <param name="heightPixels">The terminal height in pixels. Use 0 when unspecified. Must not be negative.</param>
    public TerminalSize(int columns, int rows, int widthPixels = 0, int heightPixels = 0)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(columns);
        ArgumentOutOfRangeException.ThrowIfNegative(rows);
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
    /// <remarks>
    /// Defaults to 0, which means the width is unspecified.
    /// </remarks>
    public int Columns { get; }

    /// <summary>
    /// Gets the terminal height in characters.
    /// </summary>
    /// <remarks>
    /// Defaults to 0, which means the height is unspecified.
    /// </remarks>
    public int Rows { get; }

    /// <summary>
    /// Gets the terminal width in pixels.
    /// </summary>
    /// <remarks>
    /// Defaults to 0, which means the pixel size is unspecified.
    /// Tmds.Ssh does not compute a pixel size; the caller supplies it.
    /// </remarks>
    public int WidthPixels { get; }

    /// <summary>
    /// Gets the terminal height in pixels.
    /// </summary>
    /// <remarks>
    /// Defaults to 0, which means the pixel size is unspecified.
    /// Tmds.Ssh does not compute a pixel size; the caller supplies it.
    /// </remarks>
    public int HeightPixels { get; }
}

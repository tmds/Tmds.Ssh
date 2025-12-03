// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

/// <summary>
/// Value for an SshConfigOption
/// </summary>
public readonly struct SshConfigOptionValue
{
    private readonly object? _value;

    /// <summary>
    /// Creates a value from a single string.
    /// </summary>
    /// <param name="value">The value.</param>
    public SshConfigOptionValue(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        _value = value;
    }

    /// <summary>
    /// Creates a value from multiple strings.
    /// </summary>
    /// <param name="values">The values.</param>
    public SshConfigOptionValue(IEnumerable<string> values)
    {
        ArgumentNullException.ThrowIfNull(values);
        string[] valueArray = values.ToArray();
        foreach (string value in valueArray)
        {
            ArgumentNullException.ThrowIfNull(value);
        }
        _value = valueArray;
    }

    /// <summary>
    /// Implicitly converts a string to an SshConfigOptionValue.
    /// </summary>
    /// <param name="value">The value.</param>
    public static implicit operator SshConfigOptionValue(string value)
        => new SshConfigOptionValue(value);

    /// <summary>
    /// Gets whether the value is empty.
    /// </summary>
    public bool IsEmpty => FirstValue is null;

    /// <summary>
    /// Gets whether the value contains a single string.
    /// </summary>
    public bool IsSingleValue =>
        _value is string || (_value is string[] values && values.Length == 1);

    /// <summary>
    /// Gets the first value.
    /// </summary>
    public string? FirstValue =>
        _value switch
        {
            string s => s,
            string[] values => values[0],
            _ => null
        };

    /// <summary>
    /// Gets all values.
    /// </summary>
    public IEnumerable<string> Values =>
        _value switch
        {
            string s => [ s ],
            string[] values => values,
            _ => []
        };
}
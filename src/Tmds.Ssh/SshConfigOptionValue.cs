// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

namespace Tmds.Ssh;

public readonly struct SshConfigOptionValue
{
    private readonly object? _value;

    public SshConfigOptionValue(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        _value = value;
    }

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

    public static implicit operator SshConfigOptionValue(string value)
        => new SshConfigOptionValue(value);

    public bool IsEmpty => FirstValue is null;

    public bool IsSingleValue =>
        _value is string || (_value is string[] values && values.Length == 1);

    public string? FirstValue =>
        _value switch
        {
            string s => s,
            string[] values => values[0],
            _ => null
        };

    public IEnumerable<string> Values =>
        _value switch
        {
            string s => [ s ],
            string[] values => values,
            _ => []
        };
}
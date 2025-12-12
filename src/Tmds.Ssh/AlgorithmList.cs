// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System.Collections;

namespace Tmds.Ssh;

/// <summary>
/// Represents an ordered set of algorithm names.
/// </summary>
public sealed class AlgorithmList : IList<string>
{
    private readonly List<Name> _algorithms;

    /// <summary>
    /// Initializes a new instance of the <see cref="AlgorithmList"/> class.
    /// </summary>
    public AlgorithmList()
    {
        _algorithms = new List<Name>();
    }

    internal AlgorithmList(List<Name> algorithms)
    {
        _algorithms = algorithms;
    }

    internal List<Name> AsNameList() => _algorithms;

    internal List<Name> AsNameList(List<Name> supportedAlgorithms)
    {
        List<Name>? result = null;

        for (int i = 0; i < _algorithms.Count; i++)
        {
            if (supportedAlgorithms.Contains(_algorithms[i]))
            {
                if (result is not null)
                {
                    result.Add(_algorithms[i]);
                }
            }
            else
            {
                if (result is null)
                {
                    result = new List<Name>(_algorithms.Count);
                    for (int j = 0; j < i; j++)
                    {
                        result.Add(_algorithms[j]);
                    }
                }
            }
        }

        return result ?? _algorithms;
    }

    private void ThrowIfContains(Name name)
    {
        if (_algorithms.Contains(name))
        {
            throw new ArgumentException($"Algorithm '{name}' is already in the list.");
        }
    }

    private void ThrowIfContains(Name name, int skipIndex)
    {
        for (int i = 0; i < _algorithms.Count; i++)
        {
            if (i != skipIndex && _algorithms[i] == name)
            {
                throw new ArgumentException($"Algorithm '{name}' is already in the list.");
            }
        }
    }

    /// <inheritdoc />
    public string this[int index]
    {
        get => _algorithms[index];
        set
        {
            ArgumentException.ThrowIfNullOrEmpty(value, nameof(value));

            Name newName = new Name(value);

            ThrowIfContains(newName, skipIndex: index);

            _algorithms[index] = newName;
        }
    }

    /// <inheritdoc />
    public int Count => _algorithms.Count;

    /// <inheritdoc />
    public bool IsReadOnly => false;

    /// <inheritdoc />
    public void Add(string item)
    {
        ArgumentException.ThrowIfNullOrEmpty(item, nameof(item));

        Name newName = new Name(item);

        ThrowIfContains(newName);

        _algorithms.Add(newName);
    }

    /// <inheritdoc />
    public void Clear()
    {
        _algorithms.Clear();
    }

    /// <inheritdoc />
    public bool Contains(string item)
    {
        ArgumentNullException.ThrowIfNull(item);
        return _algorithms.Contains(new Name(item));
    }

    /// <inheritdoc />
    public void CopyTo(string[] array, int arrayIndex)
    {
        ArgumentNullException.ThrowIfNull(array);
        if (arrayIndex < 0 || arrayIndex > array.Length)
        {
            throw new ArgumentOutOfRangeException(nameof(arrayIndex));
        }
        if (array.Length - arrayIndex < _algorithms.Count)
        {
            throw new ArgumentException("Destination array is not long enough.");
        }

        for (int i = 0; i < _algorithms.Count; i++)
        {
            array[arrayIndex + i] = _algorithms[i];
        }
    }

    /// <inheritdoc />
    public IEnumerator<string> GetEnumerator()
    {
        foreach (Name name in _algorithms)
        {
            yield return name;
        }
    }

    /// <inheritdoc />
    public int IndexOf(string item)
    {
        ArgumentNullException.ThrowIfNull(item);
        return _algorithms.IndexOf(new Name(item));
    }

    /// <inheritdoc />
    public void Insert(int index, string item)
    {
        ArgumentException.ThrowIfNullOrEmpty(item, nameof(item));

        Name newName = new Name(item);

        ThrowIfContains(newName);

        _algorithms.Insert(index, newName);
    }

    /// <inheritdoc />
    public bool Remove(string item)
    {
        ArgumentNullException.ThrowIfNull(item);
        return _algorithms.Remove(new Name(item));
    }

    /// <inheritdoc />
    public void RemoveAt(int index)
    {
        _algorithms.RemoveAt(index);
    }

    IEnumerator IEnumerable.GetEnumerator()
    {
        return GetEnumerator();
    }
}

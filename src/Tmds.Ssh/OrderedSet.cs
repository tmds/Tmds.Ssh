// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace Tmds.Ssh;

sealed class OrderedSet<T>
{
    private readonly HashSet<T> _set;
    private readonly List<T> _ordered;

    public OrderedSet(int capacity)
    {
        _set = new HashSet<T>(capacity);
        _ordered = new List<T>(capacity);
    }

    public OrderedSet()
    {
        _set = new HashSet<T>();
        _ordered = new List<T>();
    }

    public void Add(T item)
    {
        if (_set.Add(item))
        {
            _ordered.Add(item);
        }
    }

    public ReadOnlySpan<T> OrderedItems
    {
        get
        {
            return CollectionsMarshal.AsSpan(_ordered);
        }
    }
}
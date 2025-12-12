using Xunit;

namespace Tmds.Ssh.Tests;

public class AlgorithmListTests
{
    [Fact]
    public void CanAddItems()
    {
        var list = new AlgorithmList();
        list.Add("algorithm1");
        list.Add("algorithm2");

        Assert.Equal(2, list.Count);
        Assert.Equal("algorithm1", list[0]);
        Assert.Equal("algorithm2", list[1]);
    }

    [Fact]
    public void CanInitializeWithCollectionExpression()
    {
        AlgorithmList list = [ "algorithm1", "algorithm2", "algorithm3" ];

        Assert.Equal(3, list.Count);
        Assert.Equal("algorithm1", list[0]);
        Assert.Equal("algorithm2", list[1]);
        Assert.Equal("algorithm3", list[2]);
    }

    [Fact]
    public void AddThrowsOnDuplicate()
    {
        var list = new AlgorithmList();
        list.Add("algorithm1");

        Assert.Throws<ArgumentException>(() => list.Add("algorithm1"));
    }

    [Fact]
    public void AddThrowsOnNull()
    {
        var list = new AlgorithmList();

        Assert.Throws<ArgumentNullException>(() => list.Add(null!));
    }

    [Fact]
    public void AddThrowsOnEmpty()
    {
        var list = new AlgorithmList();

        Assert.Throws<ArgumentException>(() => list.Add(string.Empty));
    }

    [Fact]
    public void CanRemoveItems()
    {
        AlgorithmList list = [ "algorithm1", "algorithm2", "algorithm3" ];

        bool removed = list.Remove("algorithm2");

        Assert.True(removed);
        Assert.Equal(2, list.Count);
        Assert.Equal("algorithm1", list[0]);
        Assert.Equal("algorithm3", list[1]);
    }

    [Fact]
    public void RemoveReturnsFalseForNonExistent()
    {
        AlgorithmList list = [ "algorithm1" ];

        bool removed = list.Remove("algorithm2");

        Assert.False(removed);
        Assert.Single(list);
    }

    [Fact]
    public void RemoveThrowsOnNull()
    {
        var list = new AlgorithmList();

        Assert.Throws<ArgumentNullException>(() => list.Remove(null!));
    }

    [Fact]
    public void CanRemoveAt()
    {
        AlgorithmList list = [ "algorithm1", "algorithm2", "algorithm3" ];

        list.RemoveAt(1);

        Assert.Equal(2, list.Count);
        Assert.Equal("algorithm1", list[0]);
        Assert.Equal("algorithm3", list[1]);
    }

    [Fact]
    public void ContainsReturnsTrueForExistingItem()
    {
        AlgorithmList list = [ "algorithm1", "algorithm2" ];

        Assert.Contains("algorithm1", list);
        Assert.Contains("algorithm2", list);
    }

    [Fact]
    public void ContainsReturnsFalseForNonExistingItem()
    {
        AlgorithmList list = [ "algorithm1" ];

        Assert.DoesNotContain("algorithm2", list);
    }

    [Fact]
    public void ContainsThrowsOnNull()
    {
        var list = new AlgorithmList();

        Assert.Throws<ArgumentNullException>(() => list.Contains(null!));
    }

    [Fact]
    public void IndexOfReturnsCorrectIndex()
    {
        AlgorithmList list = [ "algorithm1", "algorithm2", "algorithm3" ];

        Assert.Equal(0, list.IndexOf("algorithm1"));
        Assert.Equal(1, list.IndexOf("algorithm2"));
        Assert.Equal(2, list.IndexOf("algorithm3"));
    }

    [Fact]
    public void IndexOfReturnsMinusOneForNonExistent()
    {
        AlgorithmList list = [ "algorithm1" ];

        Assert.Equal(-1, list.IndexOf("algorithm2"));
    }

    [Fact]
    public void IndexOfThrowsOnNull()
    {
        var list = new AlgorithmList();

        Assert.Throws<ArgumentNullException>(() => list.IndexOf(null!));
    }

    [Fact]
    public void CanSetItemByIndex()
    {
        AlgorithmList list = [ "algorithm1", "algorithm2" ];

        list[0] = "algorithm3";

        Assert.Equal("algorithm3", list[0]);
        Assert.Equal("algorithm2", list[1]);
    }

    [Fact]
    public void SetItemThrowsOnDuplicate()
    {
        AlgorithmList list = [ "algorithm1", "algorithm2" ];

        Assert.Throws<ArgumentException>(() => list[0] = "algorithm2");
    }

    [Fact]
    public void SetItemThrowsOnNull()
    {
        AlgorithmList list = [ "algorithm1" ];

        Assert.Throws<ArgumentNullException>(() => list[0] = null!);
    }

    [Fact]
    public void SetItemThrowsOnEmpty()
    {
        AlgorithmList list = [ "algorithm1" ];

        Assert.Throws<ArgumentException>(() => list[0] = string.Empty);
    }

    [Fact]
    public void CanInsertItems()
    {
        AlgorithmList list = [ "algorithm1", "algorithm3" ];

        list.Insert(1, "algorithm2");

        Assert.Equal(3, list.Count);
        Assert.Equal("algorithm1", list[0]);
        Assert.Equal("algorithm2", list[1]);
        Assert.Equal("algorithm3", list[2]);
    }

    [Fact]
    public void InsertThrowsOnDuplicate()
    {
        AlgorithmList list = [ "algorithm1", "algorithm2" ];

        Assert.Throws<ArgumentException>(() => list.Insert(1, "algorithm1"));
    }

    [Fact]
    public void InsertThrowsOnNull()
    {
        var list = new AlgorithmList();

        Assert.Throws<ArgumentNullException>(() => list.Insert(0, null!));
    }

    [Fact]
    public void InsertThrowsOnEmpty()
    {
        var list = new AlgorithmList();

        Assert.Throws<ArgumentException>(() => list.Insert(0, string.Empty));
    }

    [Fact]
    public void CanClear()
    {
        AlgorithmList list = [ "algorithm1", "algorithm2" ];

        list.Clear();

        Assert.Empty(list);
    }

    [Fact]
    public void CanEnumerate()
    {
        AlgorithmList list = [ "algorithm1", "algorithm2", "algorithm3" ];

        var items = new List<string>();
        foreach (var item in list)
        {
            items.Add(item);
        }

        Assert.Equal(new[] { "algorithm1", "algorithm2", "algorithm3" }, items);
    }

    [Fact]
    public void CanCopyTo()
    {
        AlgorithmList list = [ "algorithm1", "algorithm2" ];
        var array = new string[3];

        list.CopyTo(array, 1);

        Assert.Null(array[0]);
        Assert.Equal("algorithm1", array[1]);
        Assert.Equal("algorithm2", array[2]);
    }

    [Fact]
    public void CopyToThrowsOnNullArray()
    {
        var list = new AlgorithmList();

        Assert.Throws<ArgumentNullException>(() => list.CopyTo(null!, 0));
    }

    [Fact]
    public void CopyToThrowsOnInvalidArrayIndex()
    {
        AlgorithmList list = [ "algorithm1" ];
        var array = new string[1];

        Assert.Throws<ArgumentOutOfRangeException>(() => list.CopyTo(array, -1));
        Assert.Throws<ArgumentOutOfRangeException>(() => list.CopyTo(array, 2));
    }

    [Fact]
    public void CopyToThrowsWhenArrayTooSmall()
    {
        AlgorithmList list = [ "algorithm1", "algorithm2" ];
        var array = new string[2];

        Assert.Throws<ArgumentException>(() => list.CopyTo(array, 1));
    }

    [Fact]
    public void IsReadOnlyReturnsFalse()
    {
        var list = new AlgorithmList();

        Assert.False(list.IsReadOnly);
    }
}

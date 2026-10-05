using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace Tmds.Ssh.Tests;

public class ConnectCancellationTests
{
    [Fact]
    public void TokenCancelsAfterTimeout()
    {
        var timeProvider = new FakeTimeProvider();
        using var cc = new ConnectCancellation(TimeSpan.FromSeconds(10), CancellationToken.None, CancellationToken.None, timeProvider);

        Assert.False(cc.Token.IsCancellationRequested);

        timeProvider.Advance(TimeSpan.FromSeconds(10));

        Assert.True(cc.Token.IsCancellationRequested);
    }

    [Fact]
    public void TokenDoesNotCancelBeforeTimeout()
    {
        var timeProvider = new FakeTimeProvider();
        using var cc = new ConnectCancellation(TimeSpan.FromSeconds(10), CancellationToken.None, CancellationToken.None, timeProvider);

        timeProvider.Advance(TimeSpan.FromSeconds(9));

        Assert.False(cc.Token.IsCancellationRequested);
    }

    [Fact]
    public void SuspendPreventsTimeout()
    {
        var timeProvider = new FakeTimeProvider();
        using var cc = new ConnectCancellation(TimeSpan.FromSeconds(10), CancellationToken.None, CancellationToken.None, timeProvider);

        timeProvider.Advance(TimeSpan.FromSeconds(5));
        cc.SuspendTimeout();

        timeProvider.Advance(TimeSpan.FromSeconds(100));

        Assert.False(cc.Token.IsCancellationRequested);
    }

    [Fact]
    public void ResumeAfterSuspendContinuesTimeout()
    {
        var timeProvider = new FakeTimeProvider();
        using var cc = new ConnectCancellation(TimeSpan.FromSeconds(10), CancellationToken.None, CancellationToken.None, timeProvider);

        timeProvider.Advance(TimeSpan.FromSeconds(3));
        cc.SuspendTimeout();

        timeProvider.Advance(TimeSpan.FromSeconds(100));
        Assert.False(cc.Token.IsCancellationRequested);

        cc.ResumeTimeout();

        // 7 seconds remaining.
        timeProvider.Advance(TimeSpan.FromSeconds(6));
        Assert.False(cc.Token.IsCancellationRequested);

        timeProvider.Advance(TimeSpan.FromSeconds(1));
        Assert.True(cc.Token.IsCancellationRequested);
    }

    [Fact]
    public void SuspendResumePreservesRemainingTime()
    {
        var timeProvider = new FakeTimeProvider();
        using var cc = new ConnectCancellation(TimeSpan.FromSeconds(10), CancellationToken.None, CancellationToken.None, timeProvider);

        // Consume 2s, suspend, wait a long time, resume.
        timeProvider.Advance(TimeSpan.FromSeconds(2));
        cc.SuspendTimeout();
        timeProvider.Advance(TimeSpan.FromSeconds(1000));
        cc.ResumeTimeout();

        // 8s remaining — should not have cancelled.
        Assert.False(cc.Token.IsCancellationRequested);

        timeProvider.Advance(TimeSpan.FromSeconds(8));
        Assert.True(cc.Token.IsCancellationRequested);
    }

    [Fact]
    public void MultipleSuspendResumeCycles()
    {
        var timeProvider = new FakeTimeProvider();
        using var cc = new ConnectCancellation(TimeSpan.FromSeconds(10), CancellationToken.None, CancellationToken.None, timeProvider);

        // Consume 3s.
        timeProvider.Advance(TimeSpan.FromSeconds(3));
        cc.SuspendTimeout();
        timeProvider.Advance(TimeSpan.FromSeconds(100));

        // Consume 2s more.
        cc.ResumeTimeout();
        timeProvider.Advance(TimeSpan.FromSeconds(2));
        cc.SuspendTimeout();
        timeProvider.Advance(TimeSpan.FromSeconds(100));

        // 5s remaining.
        Assert.False(cc.Token.IsCancellationRequested);

        cc.ResumeTimeout();
        timeProvider.Advance(TimeSpan.FromSeconds(4));
        Assert.False(cc.Token.IsCancellationRequested);

        timeProvider.Advance(TimeSpan.FromSeconds(1));
        Assert.True(cc.Token.IsCancellationRequested);
    }

    [Fact]
    public void SuspendWhenAlreadySuspendedIsNoOp()
    {
        var timeProvider = new FakeTimeProvider();
        using var cc = new ConnectCancellation(TimeSpan.FromSeconds(10), CancellationToken.None, CancellationToken.None, timeProvider);

        cc.SuspendTimeout();
        cc.SuspendTimeout();

        Assert.False(cc.Token.IsCancellationRequested);
    }

    [Fact]
    public void ResumeWhenNotSuspendedIsNoOp()
    {
        var timeProvider = new FakeTimeProvider();
        using var cc = new ConnectCancellation(TimeSpan.FromSeconds(10), CancellationToken.None, CancellationToken.None, timeProvider);

        cc.ResumeTimeout();

        Assert.False(cc.Token.IsCancellationRequested);
    }

    [Fact]
    public void SuspendAfterTimeoutThrows()
    {
        var timeProvider = new FakeTimeProvider();
        using var cc = new ConnectCancellation(TimeSpan.FromSeconds(10), CancellationToken.None, CancellationToken.None, timeProvider);

        timeProvider.Advance(TimeSpan.FromSeconds(10));
        Assert.True(cc.Token.IsCancellationRequested);

        Assert.Throws<OperationCanceledException>(() => cc.SuspendTimeout());
    }

    [Fact]
    public void ResumeAfterTimeoutIsNoOp()
    {
        var timeProvider = new FakeTimeProvider();
        using var cc = new ConnectCancellation(TimeSpan.FromSeconds(10), CancellationToken.None, CancellationToken.None, timeProvider);

        timeProvider.Advance(TimeSpan.FromSeconds(10));
        Assert.True(cc.Token.IsCancellationRequested);

        cc.ResumeTimeout();
    }

    [Fact]
    public void UpdateTimeoutExtendsDeadline()
    {
        var timeProvider = new FakeTimeProvider();
        using var cc = new ConnectCancellation(TimeSpan.FromSeconds(10), CancellationToken.None, CancellationToken.None, timeProvider);

        timeProvider.Advance(TimeSpan.FromSeconds(5));
        cc.UpdateTimeout(TimeSpan.FromSeconds(20));

        // 15s remaining after update. Original 10s timeout would have fired at +10s.
        timeProvider.Advance(TimeSpan.FromSeconds(10));
        Assert.False(cc.Token.IsCancellationRequested);

        timeProvider.Advance(TimeSpan.FromSeconds(5));
        Assert.True(cc.Token.IsCancellationRequested);
    }

    [Fact]
    public void UpdateTimeoutShortensDeadline()
    {
        var timeProvider = new FakeTimeProvider();
        using var cc = new ConnectCancellation(TimeSpan.FromSeconds(60), CancellationToken.None, CancellationToken.None, timeProvider);

        timeProvider.Advance(TimeSpan.FromSeconds(5));
        cc.UpdateTimeout(TimeSpan.FromSeconds(10));

        // 5s remaining.
        timeProvider.Advance(TimeSpan.FromSeconds(4));
        Assert.False(cc.Token.IsCancellationRequested);

        timeProvider.Advance(TimeSpan.FromSeconds(1));
        Assert.True(cc.Token.IsCancellationRequested);
    }

    [Fact]
    public void UpdateTimeoutCancelsWhenAlreadyExpired()
    {
        var timeProvider = new FakeTimeProvider();
        using var cc = new ConnectCancellation(TimeSpan.FromSeconds(60), CancellationToken.None, CancellationToken.None, timeProvider);

        timeProvider.Advance(TimeSpan.FromSeconds(10));
        cc.UpdateTimeout(TimeSpan.FromSeconds(5));

        Assert.True(cc.Token.IsCancellationRequested);
    }

    [Fact]
    public void DisposeDoesNotThrow()
    {
        var timeProvider = new FakeTimeProvider();
        var cc = new ConnectCancellation(TimeSpan.FromSeconds(10), CancellationToken.None, CancellationToken.None, timeProvider);
        cc.Dispose();
    }

    [Fact]
    public void ConnectTokenCancellationPropagates()
    {
        var timeProvider = new FakeTimeProvider();
        using var userCts = new CancellationTokenSource();
        using var cc = new ConnectCancellation(TimeSpan.FromSeconds(10), userCts.Token, CancellationToken.None, timeProvider);

        userCts.Cancel();

        Assert.True(cc.Token.IsCancellationRequested);
    }

    [Fact]
    public void AbortTokenCancellationPropagates()
    {
        var timeProvider = new FakeTimeProvider();
        using var abortCts = new CancellationTokenSource();
        using var cc = new ConnectCancellation(TimeSpan.FromSeconds(10), CancellationToken.None, abortCts.Token, timeProvider);

        abortCts.Cancel();

        Assert.True(cc.Token.IsCancellationRequested);
    }

    [Fact]
    public void TimeoutCancelsToken()
    {
        var timeProvider = new FakeTimeProvider();
        using var userCts = new CancellationTokenSource();
        using var cc = new ConnectCancellation(TimeSpan.FromSeconds(10), userCts.Token, CancellationToken.None, timeProvider);

        timeProvider.Advance(TimeSpan.FromSeconds(10));

        Assert.True(cc.Token.IsCancellationRequested);
        Assert.False(userCts.Token.IsCancellationRequested);
    }

    [Fact]
    public void SuspendThrowsWhenConnectTokenCancelled()
    {
        var timeProvider = new FakeTimeProvider();
        using var userCts = new CancellationTokenSource();
        using var cc = new ConnectCancellation(TimeSpan.FromSeconds(10), userCts.Token, CancellationToken.None, timeProvider);

        userCts.Cancel();

        Assert.Throws<OperationCanceledException>(() => cc.SuspendTimeout());
    }

    [Fact]
    public void ResumeIsNoOpWhenConnectTokenCancelled()
    {
        var timeProvider = new FakeTimeProvider();
        using var userCts = new CancellationTokenSource();
        using var cc = new ConnectCancellation(TimeSpan.FromSeconds(10), userCts.Token, CancellationToken.None, timeProvider);

        cc.SuspendTimeout();
        userCts.Cancel();

        cc.ResumeTimeout();
    }

    [Fact]
    public void SuspendInnerSuspendsOuter()
    {
        var timeProvider = new FakeTimeProvider();
        using var outer = new ConnectCancellation(TimeSpan.FromSeconds(30), CancellationToken.None, CancellationToken.None, timeProvider);
        using var inner = new ConnectCancellation(TimeSpan.FromSeconds(10), CancellationToken.None, CancellationToken.None, timeProvider, outer: outer);

        timeProvider.Advance(TimeSpan.FromSeconds(5));
        inner.SuspendTimeout();

        // Both should be suspended — outer should not fire even past its timeout.
        timeProvider.Advance(TimeSpan.FromSeconds(100));
        Assert.False(outer.Token.IsCancellationRequested);
        Assert.False(inner.Token.IsCancellationRequested);
    }

    [Fact]
    public void ResumeInnerResumesOuter()
    {
        var timeProvider = new FakeTimeProvider();
        using var outer = new ConnectCancellation(TimeSpan.FromSeconds(30), CancellationToken.None, CancellationToken.None, timeProvider);
        using var inner = new ConnectCancellation(TimeSpan.FromSeconds(10), CancellationToken.None, CancellationToken.None, timeProvider, outer: outer);

        timeProvider.Advance(TimeSpan.FromSeconds(2));
        inner.SuspendTimeout();
        timeProvider.Advance(TimeSpan.FromSeconds(100));
        inner.ResumeTimeout();

        // Inner: 8s remaining, outer: 28s remaining.
        timeProvider.Advance(TimeSpan.FromSeconds(7));
        Assert.False(inner.Token.IsCancellationRequested);
        Assert.False(outer.Token.IsCancellationRequested);

        // Inner times out at 8s.
        timeProvider.Advance(TimeSpan.FromSeconds(1));
        Assert.True(inner.Token.IsCancellationRequested);
        Assert.False(outer.Token.IsCancellationRequested);
    }

    [Fact]
    public void OuterTimesOutIndependentlyAfterResume()
    {
        var timeProvider = new FakeTimeProvider();
        using var outer = new ConnectCancellation(TimeSpan.FromSeconds(15), CancellationToken.None, CancellationToken.None, timeProvider);
        using var inner = new ConnectCancellation(TimeSpan.FromSeconds(60), CancellationToken.None, CancellationToken.None, timeProvider, outer: outer);

        timeProvider.Advance(TimeSpan.FromSeconds(5));
        inner.SuspendTimeout();
        timeProvider.Advance(TimeSpan.FromSeconds(100));
        inner.ResumeTimeout();

        // Outer: 10s remaining, inner: 55s remaining.
        timeProvider.Advance(TimeSpan.FromSeconds(10));
        Assert.True(outer.Token.IsCancellationRequested);
        Assert.False(inner.Token.IsCancellationRequested);
    }

    [Fact]
    public void SuspendResumeChainPreservesRemainingTimeForBoth()
    {
        var timeProvider = new FakeTimeProvider();
        using var outer = new ConnectCancellation(TimeSpan.FromSeconds(20), CancellationToken.None, CancellationToken.None, timeProvider);
        using var inner = new ConnectCancellation(TimeSpan.FromSeconds(10), CancellationToken.None, CancellationToken.None, timeProvider, outer: outer);

        // Consume 3s, suspend, wait, resume.
        timeProvider.Advance(TimeSpan.FromSeconds(3));
        inner.SuspendTimeout();
        timeProvider.Advance(TimeSpan.FromSeconds(500));
        inner.ResumeTimeout();

        // Inner: 7s remaining, outer: 17s remaining.
        // Consume 4s more, suspend again, wait, resume.
        timeProvider.Advance(TimeSpan.FromSeconds(4));
        inner.SuspendTimeout();
        timeProvider.Advance(TimeSpan.FromSeconds(500));
        inner.ResumeTimeout();

        // Inner: 3s remaining, outer: 13s remaining.
        timeProvider.Advance(TimeSpan.FromSeconds(2));
        Assert.False(inner.Token.IsCancellationRequested);
        Assert.False(outer.Token.IsCancellationRequested);

        timeProvider.Advance(TimeSpan.FromSeconds(1));
        Assert.True(inner.Token.IsCancellationRequested);
        Assert.False(outer.Token.IsCancellationRequested);
    }

    [Fact]
    public void SuspendInnerThrowsWhenOuterAlreadyCancelled()
    {
        var timeProvider = new FakeTimeProvider();
        using var outer = new ConnectCancellation(TimeSpan.FromSeconds(5), CancellationToken.None, CancellationToken.None, timeProvider);
        using var inner = new ConnectCancellation(TimeSpan.FromSeconds(10), CancellationToken.None, CancellationToken.None, timeProvider, outer: outer);

        // Let outer time out.
        timeProvider.Advance(TimeSpan.FromSeconds(5));
        Assert.True(outer.Token.IsCancellationRequested);

        Assert.Throws<OperationCanceledException>(() => inner.SuspendTimeout());
    }
}

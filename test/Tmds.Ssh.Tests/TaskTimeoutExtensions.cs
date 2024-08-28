namespace Tmds.Ssh.Tests;

static class TaskTimeoutExtensions
{
    private const int DefaultTimeout = 30_000;

    public static Task WithTimeout(this Task task)
        => task.TimeoutAfter(DefaultTimeout);

    public static Task TimeoutAfter(this Task task, int millisecondsTimeout)
        => task.TimeoutAfter(TimeSpan.FromMilliseconds(millisecondsTimeout));

    public static async Task TimeoutAfter(this Task task, TimeSpan timeout)
    {
        var cts = new CancellationTokenSource();

        if (task == await Task.WhenAny(task, Task.Delay(timeout, cts.Token)).ConfigureAwait(false))
        {
            cts.Cancel();
            await task.ConfigureAwait(false);
        }
        else
        {
            throw new TimeoutException($"Task timed out after {timeout}");
        }
    }

    public static Task TimeoutAfter(this ValueTask task, int millisecondsTimeout)
        => task.AsTask().TimeoutAfter(TimeSpan.FromMilliseconds(millisecondsTimeout));

    public static Task TimeoutAfter(this ValueTask task, TimeSpan timeout)
        => task.AsTask().TimeoutAfter(timeout);
}

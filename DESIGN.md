SSH is a multiplexed, packet-oriented protocol.

This is different from SSL which is stream-oriented.
And HTTP which is also stream-oriented.
HTTP/2 is a stream-oriented, multiplexed protocol: it multiplexes/demultiplexes a number of streams into one.

Because SSH is a packet-oriented, we can't use the [Pipe](https://docs.microsoft.com/en-us/dotnet/api/system.io.pipelines.pipe?view=dotnet-plat-ext-2.1) class after we've decrypted the packets.
The `Pipe` class represents a stream buffer, and storing the packets into it would make us lose the packet boundaries.

for buffering packets, we can make use of the [Channel](https://docs.microsoft.com/en-us/dotnet/api/system.threading.channels.channel?view=dotnet-plat-ext-2.1) class.

As a type to represent packets, we want something that works wel together with the `Pipe` related types, like [Memory](https://docs.microsoft.com/en-us/dotnet/api/system.memory-1?view=netstandard-2.1), [ReadOnlySequence<T>](https://docs.microsoft.com/en-us/dotnet/api/system.buffers.readonlysequence-1?view=netstandard-2.1), and [SequenceReader<T>](https://docs.microsoft.com/en-us/dotnet/api/system.buffers.sequencereader-1?view=netcore-3.0).

We want to pool the packet type so it can be re-used by the `SshClient`.
Also, if an instance was parsed, we may want to trim it and allow passing it to the user.

So our packet should be some type of _mutable_ counterpart of `ReadOnlySequence`.
```cs
class Sequence
{
    // Writer API
    Memory<byte> AllocMemory(int sizeHint); // PipeWriter.GetMemory
    Span<byte> AllocSpan(int sizeHint);     // PipeWriter.GetSpan
    void Append(int);                       // PipeWriter.Advance (Adds data put into the Allocated Span/Memory)
    void Append(Sequence);                  // Extracts data from other sequence and adds it to this sequence.
    // Reader API
    void Remove(int);                       // PipeReader.AdvanceTo (Removes data from the front of the Sequence)
    ReadOnlySequence<byte> AsReadOnlySequence();      // Allows the Sequence to be read, e.g. by SequenceReader
    ReadOnlySequence<byte> ExtractReadOnlySequence(); // Extracts data from the Sequence
    // Pooling
    Dispose(); // return to pool
}
class SequencePool
{
    Sequence Rent(); // alloc from pool
}
```

The following picture shows the data flow on an SSH connection which has two channels (e.g. a shell, and a port forward).
```
+---------------------------------------------------------------------------------------------+
|                                                                                             |
|  SshClient                             +--------------------------------------------------+ |
|                                        |                                                  | |
|                                  +----^+                 SSH Channel                      | |
|                                  | +---+                                                  | |
|                                  | |   +--------------------------------------------------+ |
|                                  | |                                                        |
| +--------------+                 | |   +--------------------------------------------------+ |
| |              |                 | |   |                 SSH Channel                      | |
| |  Socket      +---------------->+ |   |                                                  | |
| |              |                 | |   |                                                  | |
| +--------------+<---------+      | |   |  +-------------------+                           | |
|                           |      | |   |  |                   |     +-------------------+ | |
|                           |      +------->+ Channel<Sequence> +---->+                   | | |
|                           |        |   |  |                   |     |                   | | |
|                           |        v   |  +-------------------+     |                   | | |
|                +----------+--------++  |                            |  Channel Handler  | | |
|                |                    |  |                            |                   | | |
|                |  Channel<Sequence> +<------------------------------+                   | | |
|                |                    |  |                            |                   | | |
|                +--------------------+  |                            +-------------------+ | |
|                                        +--------------------------------------------------+ |
|  +--------------+                                                                           |
|  |              |                                                                           |
|  | SequencePool |                                                                           |
|  |              |                                                                           |
|  +--------------+                                                                           |
+---------------------------------------------------------------------------------------------+
```

All `Sequences` on this diagram are decrypted packets. Decryption happens when packets are read from the socket. Encryption when they are sent to the socket.

The basis for supporting different type of channels will be the capability to add a channel handler into the `SshClient`.

The API will be something like:
```cs
delegate Task ChannelHandler(ChannelContext);

class SshClient
{
    Task HandleChannelAsync(ChannelHandler, CancellationToken);
}

class ChannelContext
{
    int ChannelNumber; // Channel number of the local end, chosen by SshClient.
    CancellationToken ChannelStopped; // triggered when a channel should stop
    ValueTask<Sequence> ReadPacketAsync();
    ValueTask SendPacketAsync(Sequence);  // Sends can't be canceled because they may have partially occured
    ValueTask SendPacketAsync(Span<byte>);
    Sequence RentSequence(); // rent a Sequence from the SshClient.SequencePool
}
```

Thanks to the inversion of control pattern, a channel type can be implemented (and tested) independent of `SshClient`.

`SshClient` will cancel the `CannelStopped` cancellation token when the connection is closed, and wait for `ChannelHandlers` to complete. So when we're done disposing the `SshClient`, all `Sequences` that were allocated from the `SequencePool` should be returned. A `ChannelHandler` may keep the data past this, by using the `ExtractReadOnlySequence` method.

using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Tmds.Ssh.Tests;

public class ProxyTests
{
    [Fact]
    public void ChainNone()
    {
        Assert.Null(Proxy.Chain(Array.Empty<Proxy>()));
    }

    [Fact]
    public void ChainSingle()
    {
        SshProxy proxy = new SshProxy("localhost", SshConfigSettings.DefaultConfig);
        Assert.Equal(proxy, Proxy.Chain([ proxy ]));
    }

    [Fact]
    public async Task ChainMultiple()
    {
        TestProxy proxy1 = new TestProxy();
        TestProxy proxy2 = new TestProxy();

        Proxy? chain = Proxy.Chain(proxy1, proxy2);
        Assert.NotNull(chain);

        var destinationContext = new DestinationConnectContext();

        Stream stream = await chain.ConnectToProxyAndForward((ConnectContext ctx, CancellationToken ct) => new ValueTask<Stream>(new TcpStream(ctx)), destinationContext, default);

        ProxyStream proxy2Stream = Assert.IsType<ProxyStream>(stream);
        ProxyStream proxy1Stream = Assert.IsType<ProxyStream>(proxy2Stream.InnerStream);
        TcpStream tcpStream = Assert.IsType<TcpStream>(proxy1Stream.InnerStream);

        TestProxyConnectContext proxy1Context = Assert.IsType<TestProxyConnectContext>(proxy1Stream.ProxyContext);
        TestProxyConnectContext proxy2Context = Assert.IsType<TestProxyConnectContext>(proxy2Stream.ProxyContext);

        Assert.Equal(destinationContext, proxy2Stream.ForwardsTo);
        Assert.Equal(proxy2Context, proxy1Stream.ForwardsTo);
        Assert.Equal(proxy1Context, tcpStream.ConnectsTo);
    }

    sealed class TestProxyConnectContext : ConnectContext
    {
        public TestProxy Proxy { get; }

        public TestProxyConnectContext(TestProxy proxy, ConnectContext parent) : base(new ConnectEndPoint("proxy", 1), parent)
        {
            Proxy = proxy;
        }
    }

    sealed class ProxyStream : FakeStream
    {
        public Stream InnerStream { get; }
        public ConnectContext ProxyContext { get; }
        public ConnectContext ForwardsTo { get; }
        public ProxyStream(Stream innerStream, ConnectContext proxyContext, ConnectContext destinationContext)
        {
            InnerStream = innerStream;
            ProxyContext = proxyContext;
            ForwardsTo = destinationContext;
        }
    }

    sealed class DestinationConnectContext : ConnectContext
    {
        public DestinationConnectContext()
            : base(new ConnectEndPoint("destination", 1), NullLoggerFactory.Instance)
        {

        }
    }

    sealed class TcpStream : FakeStream
    {
        public ConnectContext ConnectsTo { get; }
        public TcpStream(ConnectContext context)
        {
            ConnectsTo = context;
        }
    }

    sealed class TestProxy : Proxy
    {
        internal override async ValueTask<Stream> ConnectToProxyAndForward(ConnectCallback connect, ConnectContext context, CancellationToken ct)
        {
            ConnectContext proxyContext = new TestProxyConnectContext(this, context);
            Stream stream = await connect(proxyContext, ct);
            return new ProxyStream(stream, proxyContext, context);
        }
    }

    class FakeStream : Stream
    {
        public override bool CanRead => throw new NotImplementedException();

        public override bool CanSeek => throw new NotImplementedException();

        public override bool CanWrite => throw new NotImplementedException();

        public override long Length => throw new NotImplementedException();

        public override long Position { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }

        public override void Flush()
        {
            throw new NotImplementedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            throw new NotImplementedException();
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotImplementedException();
        }

        public override void SetLength(long value)
        {
            throw new NotImplementedException();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            throw new NotImplementedException();
        }
    }
}

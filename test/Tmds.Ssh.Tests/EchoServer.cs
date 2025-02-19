using System.Net;
using System.Net.Sockets;

namespace Tmds.Ssh.Tests;

sealed class EchoServer : IDisposable
{
    private readonly Socket _serverSocket;

    public EndPoint EndPoint => _serverSocket.LocalEndPoint!;

    public EchoServer(AddressFamily addressFamily = AddressFamily.InterNetwork)
    {
        if (addressFamily == AddressFamily.InterNetwork)
        {
            _serverSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.IP);
            _serverSocket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        }
        else if (addressFamily == AddressFamily.Unix)
        {
            _serverSocket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
            string unixSocketPath = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
            _serverSocket.Bind(new UnixDomainSocketEndPoint(unixSocketPath));
        }
        else
        {
            throw new IndexOutOfRangeException(addressFamily.ToString());
        }
        _serverSocket.Listen(1);
        _ = AcceptLoop();
    }

    private async Task AcceptLoop()
    {
        try
        {
            while (true)
            {
                var clientSocket = await _serverSocket.AcceptAsync().ConfigureAwait(false);
                if (clientSocket.ProtocolType == ProtocolType.Tcp)
                {
                    clientSocket.NoDelay = true;
                }
                _ = HandleClient(clientSocket);
            }
        }
        catch
        { }
    }

    private async Task HandleClient(Socket clientSocket)
    {
        using var _ = clientSocket;
        try
        {
            byte[] buffer = new byte[1024];
            while (true)
            {
                int bytesRead = await clientSocket.ReceiveAsync(buffer);
                if (bytesRead == 0)
                {
                    clientSocket.Shutdown(SocketShutdown.Both);
                    break;
                }
                await clientSocket.SendAsync(buffer.AsMemory(0, bytesRead));
            }
        }
        catch
        { }
    }


    public void Dispose()
    {
        _serverSocket.Dispose();
    }
}

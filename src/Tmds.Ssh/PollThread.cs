// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using static Tmds.Ssh.Interop;

namespace Tmds.Ssh
{
    class PollThread
    {
        // TODO: weak reference SshClient, and finalizers.
        // TODO: stop thread when there are no more SshClients.
        private readonly ConcurrentDictionary<Socket, SshClient> Sessions = new();
        private Socket _interruptSocket;
        private Socket _readSocket;
        private int _blocked;
        private static PollThread? s_instance;

        private PollThread()
        {
            (_interruptSocket, _readSocket) = CreateSocketPair();
        }

        private void Cleanup()
        {
            _interruptSocket.Dispose();
            _readSocket.Dispose();
        }

        private void Start()
        {
            var thread = new Thread(o => ((PollThread)o!).ThreadFunction());
            thread.Name = "SSH Poll";
            thread.IsBackground = true;
            thread.Start(this);
        }

        private void ThreadFunction()
        {
            SshClient.EnableDebugLogging();

            using EventHandle ev = ssh_event_new();
            List<Socket> readList = new List<Socket>();
            List<Socket> writeList = new List<Socket>();
            List<Socket> errorList = new List<Socket>();
            HashSet<Socket> socketsWithEvent = new HashSet<Socket>();

            Span<byte> buffer = stackalloc byte[1];
            while (true)
            {
                socketsWithEvent.Clear();
                try
                {
                    Interlocked.Exchange(ref _blocked, 1);

                    readList.Add(_readSocket);
                    foreach (var kv in Sessions)
                    {
                        SshClient session = kv.Value;
                        PollFlags pollFlags;
                        lock (session.Gate)
                        {
                            pollFlags = session.SessionPollFlags;
                            session.PollThreadPollFlags = pollFlags;
                        }
                        if (pollFlags != 0)
                        {
                            Socket socket = kv.Key;
                            errorList.Add(socket);
                            if ((pollFlags & PollFlags.ReadPending) != 0)
                            {
                                readList.Add(socket);
                            }
                            if ((pollFlags & PollFlags.WritePending) != 0)
                            {
                                writeList.Add(socket);
                            }
                        }
                    }
                    Socket.Select(readList, writeList, errorList, -1);

                    Interlocked.Exchange(ref _blocked, 0);

                    foreach (Socket s in readList)
                    {
                        socketsWithEvent.Add(s);
                    }
                    foreach (Socket s in writeList)
                    {
                        socketsWithEvent.Add(s);
                    }
                    foreach (Socket s in errorList)
                    {
                        socketsWithEvent.Add(s);
                    }
                }
                catch (ObjectDisposedException)
                {
                    continue;
                }
                finally
                {
                    readList.Clear();
                    writeList.Clear();
                    errorList.Clear();
                }

                foreach (var socket in socketsWithEvent)
                {
                    if (Sessions.TryGetValue(socket, out SshClient? session))
                    {
                        lock (session.Gate)
                        {
                            if (session.SshHandle.IsClosed)
                            {
                                continue;
                            }

                            // TODO (libssh): not require additional poll.
                            ssh_event_add_session(ev, session.SshHandle); // TODO: rv
                            ssh_event_dopoll(ev, timeout: 0);
                            ssh_event_remove_session(ev, session.SshHandle); // TODO: rv
                            session.HandleEvents();
                        }
                    }
                    else if (socket == _readSocket)
                    {
                        // TODO: read into a larger buffer once.
                        while (_readSocket.Receive(buffer, SocketFlags.None, out SocketError error) > 0)
                        { }
                    }
                }
                socketsWithEvent.Clear();
            }
        }

        private static (Socket socket1, Socket socket2) CreateSocketPair()
        {
            using Socket s = Platform.IsWindows ? new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) :
                                                  new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
            EndPoint ep = Platform.IsWindows ? new IPEndPoint(IPAddress.Any, 0) :
                                               new UnixDomainSocketEndPoint("\0" + Guid.NewGuid().ToString());
            s.Bind(ep);
            s.Listen(1);
            Socket socket1 = new Socket(s.AddressFamily, s.SocketType, s.ProtocolType);
            socket1.Connect(s.LocalEndPoint!);
            Socket socket2 = s.Accept();
            socket1.Blocking = false;
            socket2.Blocking = false;
            return (socket1, socket2);
        }

        private void Interrupt()
        {
            int blocking = Interlocked.CompareExchange(ref _blocked, 0, 1);
            if (blocking == 1)
            {
                Span<byte> b = stackalloc byte[1];
                _interruptSocket.Send(b);
            }
        }

        internal static void InterruptPollThread()
        {
            s_instance!.Interrupt();
        }

        internal static void AddSession(Socket pollSocket, SshClient session)
        {
            PollThread? pollThread = s_instance;
            bool isNewThread = false;
            if (pollThread == null)
            {
                PollThread newThread = new PollThread();
                pollThread = Interlocked.CompareExchange(ref s_instance, newThread, null) ?? newThread;
                isNewThread = pollThread == newThread;
                if (!isNewThread)
                {
                    newThread.Cleanup();
                }
            }
            pollThread.Sessions[pollSocket] = session;
            if (isNewThread)
            {
                pollThread.Start();
            }
            else
            {
                pollThread.Interrupt();
            }
        }

        internal static void RemoveSession(Socket pollSocket)
        {
            PollThread pollThread = s_instance!;
            if (pollThread != null)
            {
                bool removed = pollThread.Sessions.TryRemove(pollSocket, out _);
                Debug.Assert(removed);
                pollThread.Interrupt();
            }
        }
    }
}
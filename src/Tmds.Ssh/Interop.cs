// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Runtime.InteropServices;
using System.Text;

namespace Tmds.Ssh
{
    static class Interop
    {
        const string Library = "libssh";

        public const int SSH_OK = 0;
        public const int SSH_ERROR = -1;
        public const int SSH_AGAIN = -2;
        public const int SSH_EOF = -127;

        public const int SSH_NO_ERROR = 0;
        public const int SSH_REQUEST_DENIED = 1;
        public const int SSH_FATAL = 2;
        public const int SSH_EINTR = 3;

        [DllImport(Library)]
        public static extern SessionHandle ssh_new();

        [DllImport(Library)]
        public static extern void ssh_free(IntPtr session);

        [DllImport(Library)]
        public static extern int ssh_options_set(SessionHandle session, SshOption option, IntPtr value);

        public unsafe static bool ssh_options_set(SessionHandle session, SshOption option, string value)
        {
            // TODO: stackalloc
            fixed (byte* p = Encoding.UTF8.GetBytes(value))
            {
                return ssh_options_set(session, option, new IntPtr(p)) == 0;
            }
        }

        public unsafe static bool ssh_options_set(SessionHandle session, SshOption option, uint value)
        {
            return ssh_options_set(session, option, new IntPtr(&value)) == 0;
        }

        [DllImport(Library)]
        public static extern int ssh_connect(SessionHandle session);

        [DllImport(Library)]
        public static extern int ssh_disconnect(SessionHandle session);

        [DllImport(Library)]
        public static extern AuthResult ssh_userauth_password(SessionHandle session, string username, string password);

        [DllImport(Library, EntryPoint = "ssh_get_error")]
        public static extern IntPtr ssh_get_error_(SessionHandle session);

        public static string ssh_get_error(SessionHandle session)
        {
            return Marshal.PtrToStringAnsi(ssh_get_error_(session)) ?? "Uknown error.";
        }

        [DllImport(Library)]
        public static extern int ssh_get_error_code(SessionHandle session);

        public static bool ssh_get_error_is_fatal(SessionHandle session)
            => ssh_get_error_code(session) == SSH_FATAL;

        [DllImport(Library)]
        public static extern int ssh_channel_open_session(ChannelHandle channel);

        [DllImport(Library)]
        public static extern ChannelHandle ssh_channel_new(SessionHandle session);

        [DllImport(Library)]
        public static extern void ssh_channel_free(IntPtr channel);

        [DllImport(Library)]
        public static extern int ssh_channel_request_exec(ChannelHandle channel, string cmd);

        [DllImport(Library)]
        public static extern int ssh_channel_read(ChannelHandle channel, IntPtr dest, uint count, int is_stderr);

        public static unsafe int ssh_channel_read(ChannelHandle channel, Span<byte> dest, int is_stderr)
        {
            fixed (byte* ptr = dest)
            {
                return ssh_channel_read(channel, new IntPtr(ptr), (uint)dest.Length, is_stderr);
            }
        }

        [DllImport(Library)]
        public static extern void ssh_set_blocking(SessionHandle session, int blocking);

        [DllImport(Library)]
        public static extern PollFlags ssh_get_poll_flags(SessionHandle session);

        [DllImport(Library)]
        public static extern int ssh_get_fd(SessionHandle session); // TODO: Windows: return IntPtr

        [DllImport(Library)]
        public static extern int ssh_channel_poll(ChannelHandle channel, int is_stderr);

        [DllImport(Library)]
        public static extern int ssh_blocking_flush(SessionHandle session, int timeout);

        [DllImport(Library)]
        public static extern int ssh_set_log_level(int level);

        [DllImport(Library)]
        public static extern EventHandle ssh_event_new();

        [DllImport(Library)]
        public static extern void ssh_event_free(IntPtr handle);

        [DllImport(Library)]
        public static extern int ssh_event_add_session(EventHandle @event, SessionHandle session);

        [DllImport(Library)]
        public static extern int ssh_event_remove_session(EventHandle @event, SessionHandle session);

        [DllImport(Library)]
        public static extern int ssh_event_dopoll(EventHandle @event, int timeout);

        [DllImport(Library)]
        public static extern int ssh_channel_write(ChannelHandle channel, IntPtr data, uint len);

        public static unsafe int ssh_channel_write(ChannelHandle channel, ReadOnlySpan<byte> buffer)
        {
            fixed(byte* ptr = buffer)
            {
                return ssh_channel_write(channel, new IntPtr(ptr), (uint)buffer.Length);
            }
        }

        [DllImport(Library)]
        public static extern int ssh_channel_write_stderr(ChannelHandle channel, IntPtr data, uint len);

        public static unsafe int ssh_channel_write_stderr(ChannelHandle channel, ReadOnlySpan<byte> buffer)
        {
            fixed(byte* ptr = buffer)
            {
                return ssh_channel_write_stderr(channel, new IntPtr(ptr), (uint)buffer.Length);
            }
        }

        [DllImport(Library)]
        public static extern AuthResult ssh_userauth_publickey_auto(SessionHandle session, string? username, string? passphrase);

        [DllImport(Library)]
        public static extern KnownHostResult ssh_session_is_known_server(SessionHandle session);

        [DllImport(Library, EntryPoint="ssh_is_connected")]
        private static extern int ssh_is_connected_(SessionHandle session);

        public static bool ssh_is_connected(SessionHandle session)
        {
            return ssh_is_connected_(session) == 1;
        }

        [DllImport(Library, EntryPoint="ssh_channel_is_eof")]
        private static extern int ssh_channel_is_eof_(ChannelHandle channel);

        public static bool ssh_channel_is_eof(ChannelHandle channel)
        {
            return ssh_channel_is_eof_(channel) != 0;
        }

        [DllImport(Library, EntryPoint="ssh_channel_is_closed")]
        private static extern int ssh_channel_is_closed_(ChannelHandle channel);

        public static bool ssh_channel_is_closed(ChannelHandle channel)
        {
            return ssh_channel_is_closed_(channel) != 0;
        }

        [DllImport(Library)]
        public static extern uint ssh_channel_window_size(ChannelHandle channel);
    }
}
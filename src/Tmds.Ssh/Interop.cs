// This file is part of Tmds.Ssh which is released under MIT.
// See file LICENSE for full license details.

using System;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;

namespace Tmds.Ssh
{
    static class Interop
    {
        const string Library = "libssh";

        static Interop()
        {
            NativeLibrary.SetDllImportResolver(typeof(Interop).Assembly, ImportResolver);
        }

        private static IntPtr ImportResolver(string libraryName, Assembly assembly, DllImportSearchPath? searchPath)
        {
            IntPtr libHandle = IntPtr.Zero;
            if (libraryName == Library)
            {
                string? libraryPath = Environment.GetEnvironmentVariable("LIBSSH_PATH");
                if (!string.IsNullOrEmpty(libraryPath))
                {
                    libraryName = libraryPath;
                }
                else
                {
                    libraryName = Platform.IsWindows ? "libssh.dll" : "libssh.so.4";
                }
                NativeLibrary.TryLoad(libraryName, assembly, null, out libHandle);
            }
            return libHandle;
        }

        public const int SSH_OK = 0;
        public const int SSH_ERROR = -1;
        public const int SSH_AGAIN = -2;
        public const int SSH_EOF = -127;

        public const int SSH_NO_ERROR = 0;
        public const int SSH_REQUEST_DENIED = 1;
        public const int SSH_FATAL = 2;
        public const int SSH_EINTR = 3;

        public enum PublicKeyHashType : uint
        {
            SSH_PUBLICKEY_HASH_SHA1,
            SSH_PUBLICKEY_HASH_MD5,
            SSH_PUBLICKEY_HASH_SHA256,
        }

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
        private static extern AuthResult ssh_userauth_password(SessionHandle session, string? username, IntPtr password);

        public unsafe static AuthResult ssh_userauth_password(SessionHandle session, string? username, string password)
        {
            fixed (byte* p = Encoding.UTF8.GetBytes(password))
            {
                return ssh_userauth_password(session, username, new IntPtr(p));
            }
        }

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
        public static extern int ssh_channel_request_subsystem(ChannelHandle channel, string subsys);

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
        public static extern StatusFlags ssh_get_status(SessionHandle session);

        [DllImport(Library, EntryPoint="ssh_get_fd")]
        private static extern IntPtr ssh_get_fd_windows(SessionHandle session);

        [DllImport(Library, EntryPoint="ssh_get_fd")]
        private static extern int ssh_get_fd_unix(SessionHandle session);

        public static IntPtr ssh_get_fd(SessionHandle session)
        {
            if (Platform.IsWindows)
            {
                return ssh_get_fd_windows(session);
            }
            else
            {
                return new IntPtr(ssh_get_fd_unix(session));
            }
        }

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

        [DllImport(Library)]
        public static extern int ssh_session_update_known_hosts(SessionHandle session);

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

        public unsafe static bool ssh_channel_is_closed(ChannelHandle channel)
        {
            return ssh_channel_is_closed_(channel) != 0;
        }

        [DllImport(Library)]
        public static extern uint ssh_channel_window_size(ChannelHandle channel);

        [DllImport(Library)]
        public static extern void ssh_key_free(IntPtr key);

        [DllImport(Library, EntryPoint="ssh_pki_import_pubkey_file")]
        private static unsafe extern int ssh_pki_import_pubkey_file_(string filename, IntPtr* pkey);

        public unsafe static int ssh_pki_import_pubkey_file(string filename, out SshKeyHandle? keyHandle)
        {
            IntPtr pkey;
            int rv = ssh_pki_import_pubkey_file_(filename, &pkey);
            keyHandle = rv == SSH_OK ? new SshKeyHandle(pkey, ownsHandle: true) : null;
            return rv;
        }

        [DllImport(Library)]
        private static unsafe extern int ssh_get_server_publickey(SessionHandle session, IntPtr* pkey);

        public unsafe static SshKeyHandle? ssh_get_server_publickey(SessionHandle session)
        {
            IntPtr pkey;
            int rv = ssh_get_server_publickey(session, &pkey);
            return rv == SSH_OK ? new SshKeyHandle(pkey, ownsHandle: true) : null;
        }

        [DllImport(Library)]
        private static unsafe extern int ssh_get_publickey_hash(SshKeyHandle key, PublicKeyHashType type, IntPtr* hash, nuint* hlen);

        [DllImport(Library)]
        private static unsafe extern void ssh_clean_pubkey_hash(IntPtr* hash);

        public static unsafe int ssh_get_publickey_hash(SshKeyHandle key, PublicKeyHashType type, out byte[] hash)
        {
            IntPtr pHash;
            nuint length;
            int rv = ssh_get_publickey_hash(key, type, &pHash, &length);
            if (rv == SSH_OK)
            {
                hash = new byte[length];
                new Span<byte>((void*)pHash, (int)length).CopyTo(hash);
                ssh_clean_pubkey_hash(&pHash);
            }
            else
            {
                hash = Array.Empty<byte>();
            }
            return rv;
        }

        [DllImport(Library)]
        public static extern AuthResult ssh_userauth_try_publickey(SessionHandle session, string? username, SshKeyHandle pubkey);

        [DllImport(Library, EntryPoint="ssh_pki_import_privkey_file")]
        public static unsafe extern int ssh_pki_import_privkey_file_(string filename, string? passphrase, IntPtr auth_fn, IntPtr auth_data, IntPtr*  pkey);

        public static unsafe int ssh_pki_import_privkey_file(string filename, string? passphrase, out SshKeyHandle? keyHandle)
        {
            IntPtr pkey;
            int rv = ssh_pki_import_privkey_file_(filename, passphrase, IntPtr.Zero, IntPtr.Zero, &pkey);
            keyHandle = rv == SSH_OK ? new SshKeyHandle(pkey, ownsHandle: true) : null;
            return rv;
        }

        [DllImport(Library)]
        public static extern AuthResult ssh_userauth_publickey(SessionHandle session, string? username, SshKeyHandle privkey);

        [DllImport(Library)]
        public static extern int ssh_channel_get_exit_status(ChannelHandle channel);

        [DllImport(Library)]
        public unsafe static extern int ssh_set_channel_callbacks(ChannelHandle channel, ssh_channel_callbacks_struct* cb);

        [DllImport(Library)]
        public unsafe static extern int ssh_remove_channel_callbacks(ChannelHandle channel, ssh_channel_callbacks_struct* cb);

        [DllImport(Library)]
        public static extern int ssh_channel_open_forward(ChannelHandle channel, string remotehost, int remoteport, string sourcehost, int localport);

        [DllImport(Library)]
        public static extern int ssh_channel_open_forward_unix(ChannelHandle channel, string remotepath, string sourcehost, int localport);

        [StructLayout(LayoutKind.Sequential)]
        public unsafe struct ssh_channel_callbacks_struct
        {
            public nint size;
            public IntPtr userdata;
            public delegate* unmanaged<IntPtr, IntPtr, IntPtr, int, int, IntPtr, int> channel_data_function;
            public delegate* unmanaged<IntPtr, IntPtr, IntPtr, void> channel_eof_function;
            public delegate* unmanaged<IntPtr, IntPtr, IntPtr, void> channel_close_function;
            public IntPtr channel_signal_function;
            public IntPtr channel_exit_status_function;
            public IntPtr channel_exit_signal_function;
            public IntPtr channel_pty_request_function;
            public IntPtr channel_shell_request_function;
            public IntPtr channel_auth_agent_req_function;
            public IntPtr channel_x11_req_function;
            public IntPtr channel_pty_window_change_function;
            public IntPtr channel_exec_request_function;
            public IntPtr channel_env_request_function;
            public IntPtr channel_subsystem_request_function;
            public delegate* unmanaged<IntPtr, IntPtr, uint, IntPtr, void> channel_write_wontblock_function;
            public delegate* unmanaged<IntPtr, IntPtr, int, IntPtr, void> channel_open_response_function;
            public delegate* unmanaged<IntPtr, IntPtr, IntPtr, void> channel_request_response_function;
        }
    }
}
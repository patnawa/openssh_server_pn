using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32;

namespace OpenSSHServerPNManager
{
    /// <summary>
    /// Launch without administrator rights, as the desktop user with that user's environment. An elevated process borrows the
    /// desktop shell's token (UAC Admin Approval Mode); when the desktop itself has the full administrator token of the same
    /// account (the built-in Administrator, or UAC off), it starts the program with a SAFER normal-user token of its own.
    /// UAC elevation with another account's credentials is not supported: Windows gives that account no use of the shell's token.
    /// </summary>
    internal static class UserProcessLauncher
    {
        // The parent-process attribute inherits the shell's token. Explicit environment creation avoids keeping
        // the administrator's USERPROFILE. See Microsoft's 2019-04-25 Old New Thing unelevated process example.
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] private struct StartupInfo
        {
            public int Size; public string Reserved, Desktop, Title;
            public int X, Y, XSize, YSize, XChars, YChars, Fill, Flags;
            public short Show, ReservedSize; public IntPtr ReservedData, Input, Output, Error;
        }
        [StructLayout(LayoutKind.Sequential)] private struct StartupInfoEx { public StartupInfo Startup; public IntPtr Attributes; }
        [StructLayout(LayoutKind.Sequential)] private struct ProcessInfo { public IntPtr Process, Thread; public int ProcessId, ThreadId; }
        [StructLayout(LayoutKind.Sequential)] private struct TokenMandatoryLabel { public IntPtr Sid; public uint Attributes; }
        [DllImport("user32.dll")] private static extern IntPtr GetShellWindow();
        [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr window, out int processId);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern IntPtr OpenProcess(uint rights, bool inherit, int pid);
        [DllImport("advapi32.dll", SetLastError = true)] private static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
        [DllImport("advapi32.dll", SetLastError = true)] private static extern bool SaferCreateLevel(int scope, int level, int flags, out IntPtr handle, IntPtr reserved);
        [DllImport("advapi32.dll", SetLastError = true)] private static extern bool SaferComputeTokenFromLevel(IntPtr level, IntPtr token, out IntPtr result, int flags, IntPtr reserved);
        [DllImport("advapi32.dll", SetLastError = true)] private static extern bool SaferCloseLevel(IntPtr level);
        [DllImport("advapi32.dll", SetLastError = true)] private static extern bool SetTokenInformation(IntPtr token, int infoClass, ref TokenMandatoryLabel info, int length);
        [DllImport("advapi32.dll", SetLastError = true)] private static extern bool GetTokenInformation(IntPtr token, int infoClass, IntPtr info, int length, out int returned);
        [DllImport("userenv.dll", SetLastError = true)] private static extern bool CreateEnvironmentBlock(out IntPtr environment, IntPtr token, bool inherit);
        [DllImport("userenv.dll")] private static extern bool DestroyEnvironmentBlock(IntPtr environment);
        [DllImport("userenv.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool GetUserProfileDirectory(IntPtr token, StringBuilder path, ref int size);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool InitializeProcThreadAttributeList(IntPtr list, int count, int flags, ref IntPtr size);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool UpdateProcThreadAttribute(IntPtr list, uint flags, IntPtr attribute, IntPtr value, IntPtr size, IntPtr previous, IntPtr returned);
        [DllImport("kernel32.dll")] private static extern void DeleteProcThreadAttributeList(IntPtr list);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool CreateProcess(string application, StringBuilder command, IntPtr processSecurity, IntPtr threadSecurity, bool inheritHandles, uint flags, IntPtr environment, string directory, ref StartupInfoEx startup, out ProcessInfo process);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool CreateProcessAsUser(IntPtr token, string application, StringBuilder command, IntPtr processSecurity, IntPtr threadSecurity, bool inheritHandles, uint flags, IntPtr environment, string directory, ref StartupInfo startup, out ProcessInfo process);
        [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr handle);

        internal enum LaunchPlan { Direct, ShellParent, RestrictedSelf, Refuse }

        /// <summary>
        /// How a program starts without administrator rights. A full administrator token of the shell is never borrowed: the
        /// child would be an administrator again, and --client would restart itself without end.
        /// </summary>
        internal static LaunchPlan Plan(bool selfAdmin, bool shellAdmin, bool shellIsSameUser)
        {
            if (!selfAdmin) return LaunchPlan.Direct;
            if (!shellAdmin) return LaunchPlan.ShellParent;
            return shellIsSameUser ? LaunchPlan.RestrictedSelf : LaunchPlan.Refuse;
        }

        /// <summary>
        /// Starts a program as the desktop user. A connection (ssh, sftp) starts in the user's profile folder, where sftp's get
        /// saves files, and its console stays open when it fails, so the error can be read.
        /// </summary>
        public static void Open(string executable, string arguments, bool connection = false)
        {
            // cmd.exe keeps the console open; where policy blocks it, the program starts directly, as before.
            var console = connection && !CommandPromptDisabled() ? ConsoleCommandLine(executable, arguments) : null;
            if (console != null)
            {
                try { Start(Path.Combine(Environment.SystemDirectory, "cmd.exe"), console, true, executable); return; }
                catch (Win32Exception ex) { Log.Info("cmd.exe could not start (" + ex.Message + "); starting " + executable + " directly"); }
            }
            Start(executable, arguments, connection, executable);
        }

        /// <summary>The "Prevent access to the command prompt" policy (DisableCMD): cmd.exe would only say so and close.</summary>
        private static bool CommandPromptDisabled()
        {
            foreach (var hive in new[] { Registry.CurrentUser, Registry.LocalMachine })
            {
                try
                {
                    using (var k = hive.OpenSubKey(@"Software\Policies\Microsoft\Windows\System"))
                    {
                        var v = k == null ? null : k.GetValue("DisableCMD");
                        if (v is int && (int)v != 0) return true;
                    }
                }
                catch (Exception) { }
            }
            return false;
        }

        private static void Start(string executable, string arguments, bool connection, string program)
        {
            if (!Elevation.IsAdministrator())
            {
                var start = new ProcessStartInfo(executable, arguments ?? "") { UseShellExecute = true };
                if (connection) start.WorkingDirectory = StartDirectory(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), program, Directory.Exists);
                Process.Start(start);
                return;
            }
            int pid; var window = GetShellWindow();
            if (window == IntPtr.Zero || GetWindowThreadProcessId(window, out pid) == 0)
                throw new InvalidOperationException("No interactive Windows desktop was found. Open the Client workspace from your normal user session.");
            IntPtr parent = IntPtr.Zero, token = IntPtr.Zero, environment = IntPtr.Zero, attributes = IntPtr.Zero, parentValue = IntPtr.Zero;
            bool initialized = false;
            try
            {
                parent = OpenProcess(0x0080 | 0x1000, false, pid); // CREATE_PROCESS | QUERY_LIMITED_INFORMATION
                if (parent == IntPtr.Zero || !OpenProcessToken(parent, 0x0008 | 0x0002, out token)) throw ShellAccessError(Marshal.GetLastWin32Error());
                bool shellAdmin, sameUser;
                using (var identity = new WindowsIdentity(token))
                using (var self = WindowsIdentity.GetCurrent())
                {
                    shellAdmin = new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
                    sameUser = identity.User != null && identity.User == self.User;
                }
                var plan = Plan(true, shellAdmin, sameUser);
                if (plan == LaunchPlan.Refuse)
                    throw new InvalidOperationException("The Windows desktop runs as another administrator account with full rights. Open 'OpenSSH Client PN' from the Start menu in that account's own session.");
                if (plan == LaunchPlan.RestrictedSelf) { StartRestricted(executable, arguments, connection ? program : null); return; }
                if (!CreateEnvironmentBlock(out environment, token, false)) throw new Win32Exception(Marshal.GetLastWin32Error());
                IntPtr size = IntPtr.Zero; InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref size);
                attributes = Marshal.AllocHGlobal(size);
                if (!InitializeProcThreadAttributeList(attributes, 1, 0, ref size)) throw new Win32Exception(Marshal.GetLastWin32Error());
                initialized = true; parentValue = Marshal.AllocHGlobal(IntPtr.Size); Marshal.WriteIntPtr(parentValue, parent);
                if (!UpdateProcThreadAttribute(attributes, 0, new IntPtr(0x00020000), parentValue, new IntPtr(IntPtr.Size), IntPtr.Zero, IntPtr.Zero)) throw new Win32Exception(Marshal.GetLastWin32Error());
                var startup = new StartupInfoEx { Startup = new StartupInfo { Size = Marshal.SizeOf(typeof(StartupInfoEx)) }, Attributes = attributes };
                ProcessInfo child;
                var directory = connection ? StartDirectory(ProfileOf(token), program, Directory.Exists) : Path.GetDirectoryName(executable);
                if (!CreateProcess(executable, CommandLine(executable, arguments),
                    IntPtr.Zero, IntPtr.Zero, false, 0x00080000 | 0x00000400 | 0x00000010, environment, directory, ref startup, out child))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                CloseHandle(child.Thread); CloseHandle(child.Process);
            }
            finally
            {
                if (initialized) DeleteProcThreadAttributeList(attributes);
                if (attributes != IntPtr.Zero) Marshal.FreeHGlobal(attributes);
                if (parentValue != IntPtr.Zero) Marshal.FreeHGlobal(parentValue);
                if (environment != IntPtr.Zero) DestroyEnvironmentBlock(environment);
                if (token != IntPtr.Zero) CloseHandle(token);
                if (parent != IntPtr.Zero) CloseHandle(parent);
            }
        }

        /// <summary>Access to the shell is denied when another account elevated this process (over-the-shoulder UAC).</summary>
        internal static Exception ShellAccessError(int error)
        {
            if (error == 5)
                return new InvalidOperationException("The Windows desktop belongs to another user: this program was elevated with another administrator's credentials, and Windows does not let it start programs as the desktop user. Open 'OpenSSH Client PN' from the Start menu in the desktop user's session.");
            return new Win32Exception(error);
        }

        /// <summary>The user's profile folder when it exists, else the program's own folder.</summary>
        internal static string StartDirectory(string profile, string program, Func<string, bool> exists)
        {
            return !string.IsNullOrEmpty(profile) && exists(profile) ? profile : Path.GetDirectoryName(program);
        }

        /// <summary>
        /// The cmd.exe arguments that run a client program and wait for a key when it fails (a console closes with its last
        /// program). Null when the program or its arguments hold characters cmd would interpret: those start directly.
        /// </summary>
        internal static string ConsoleCommandLine(string executable, string arguments)
        {
            arguments = arguments ?? "";
            if (executable.IndexOfAny(new[] { '%', '!', '"' }) >= 0 || arguments.IndexOfAny("%!^&|<>()\"".ToCharArray()) >= 0) return null;
            return "/d /s /c \"\"" + executable + "\"" + (arguments.Length > 0 ? " " + arguments : "") + " || pause\"";
        }

        private static StringBuilder CommandLine(string executable, string arguments)
        {
            return new StringBuilder(Proc.Quote(executable) + (string.IsNullOrEmpty(arguments) ? "" : " " + arguments));
        }

        /// <summary>
        /// This process's token at the SAFER normal-user level (Administrators deny-only, no administrator privileges) and at
        /// medium integrity, so it cannot open this account's elevated processes. The caller closes it with Release.
        /// </summary>
        internal static IntPtr ReducedToken()
        {
            IntPtr level, token = IntPtr.Zero, sid = IntPtr.Zero;
            if (!SaferCreateLevel(2 /*SAFER_SCOPEID_USER*/, 0x20000 /*SAFER_LEVELID_NORMALUSER*/, 1 /*SAFER_LEVEL_OPEN*/, out level, IntPtr.Zero)) throw new Win32Exception(Marshal.GetLastWin32Error());
            try { if (!SaferComputeTokenFromLevel(level, IntPtr.Zero, out token, 0, IntPtr.Zero)) throw new Win32Exception(Marshal.GetLastWin32Error()); }
            finally { SaferCloseLevel(level); }
            try
            {
                var medium = new SecurityIdentifier("S-1-16-8192"); var bytes = new byte[medium.BinaryLength]; medium.GetBinaryForm(bytes, 0);
                sid = Marshal.AllocHGlobal(bytes.Length); Marshal.Copy(bytes, 0, sid, bytes.Length);
                var label = new TokenMandatoryLabel { Sid = sid, Attributes = 0x20 /*SE_GROUP_INTEGRITY*/ };
                if (!SetTokenInformation(token, 25 /*TokenIntegrityLevel*/, ref label, Marshal.SizeOf(typeof(TokenMandatoryLabel)) + bytes.Length)) throw new Win32Exception(Marshal.GetLastWin32Error());
                var result = token; token = IntPtr.Zero;
                return result;
            }
            finally
            {
                if (sid != IntPtr.Zero) Marshal.FreeHGlobal(sid);
                if (token != IntPtr.Zero) CloseHandle(token);
            }
        }

        internal static void Release(IntPtr handle) { if (handle != IntPtr.Zero) CloseHandle(handle); }

        /// <summary>The integrity level SID of a token (S-1-16-8192 is medium).</summary>
        internal static string IntegrityLevel(IntPtr token)
        {
            int size; GetTokenInformation(token, 25, IntPtr.Zero, 0, out size);
            var buffer = Marshal.AllocHGlobal(Math.Max(size, IntPtr.Size));
            try
            {
                if (!GetTokenInformation(token, 25, buffer, size, out size)) throw new Win32Exception(Marshal.GetLastWin32Error());
                return new SecurityIdentifier(Marshal.ReadIntPtr(buffer)).Value;
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }

        private static string ProfileOf(IntPtr token)
        {
            int size = 260; var path = new StringBuilder(size);
            return GetUserProfileDirectory(token, path, ref size) ? path.ToString() : null;
        }

        private static void StartRestricted(string executable, string arguments, string connectionProgram)
        {
            IntPtr token = ReducedToken(), environment = IntPtr.Zero;
            try
            {
                if (!CreateEnvironmentBlock(out environment, token, false)) throw new Win32Exception(Marshal.GetLastWin32Error());
                var startup = new StartupInfo { Size = Marshal.SizeOf(typeof(StartupInfo)) };
                ProcessInfo child;
                var directory = connectionProgram != null ? StartDirectory(ProfileOf(token), connectionProgram, Directory.Exists) : Path.GetDirectoryName(executable);
                if (!CreateProcessAsUser(token, executable, CommandLine(executable, arguments), IntPtr.Zero, IntPtr.Zero, false, 0x00000400 | 0x00000010, environment, directory, ref startup, out child))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                CloseHandle(child.Thread); CloseHandle(child.Process);
            }
            finally
            {
                if (environment != IntPtr.Zero) DestroyEnvironmentBlock(environment);
                CloseHandle(token);
            }
        }
    }
}

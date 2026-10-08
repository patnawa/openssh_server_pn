using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace OpenSSHServerPNManager
{
    /// <summary>Launch with the desktop user's token and environment, including over-the-shoulder UAC elevation.</summary>
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
        [DllImport("user32.dll")] private static extern IntPtr GetShellWindow();
        [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr window, out int processId);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern IntPtr OpenProcess(uint rights, bool inherit, int pid);
        [DllImport("advapi32.dll", SetLastError = true)] private static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
        [DllImport("userenv.dll", SetLastError = true)] private static extern bool CreateEnvironmentBlock(out IntPtr environment, IntPtr token, bool inherit);
        [DllImport("userenv.dll")] private static extern bool DestroyEnvironmentBlock(IntPtr environment);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool InitializeProcThreadAttributeList(IntPtr list, int count, int flags, ref IntPtr size);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool UpdateProcThreadAttribute(IntPtr list, uint flags, IntPtr attribute, IntPtr value, IntPtr size, IntPtr previous, IntPtr returned);
        [DllImport("kernel32.dll")] private static extern void DeleteProcThreadAttributeList(IntPtr list);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool CreateProcess(string application, StringBuilder command, IntPtr processSecurity, IntPtr threadSecurity, bool inheritHandles, uint flags, IntPtr environment, string directory, ref StartupInfoEx startup, out ProcessInfo process);
        [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr handle);

        public static void Open(string executable, string arguments)
        {
            if (!Elevation.IsAdministrator())
            {
                Process.Start(new ProcessStartInfo(executable, arguments ?? "") { UseShellExecute = true });
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
                if (parent == IntPtr.Zero || !OpenProcessToken(parent, 0x0008 | 0x0002, out token)) throw new Win32Exception(Marshal.GetLastWin32Error());
                using (var identity = new WindowsIdentity(token))
                    if (new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
                        throw new InvalidOperationException("The Windows desktop is elevated. Sign in with a standard desktop session to use the Client workspace safely.");
                if (!CreateEnvironmentBlock(out environment, token, false)) throw new Win32Exception(Marshal.GetLastWin32Error());
                IntPtr size = IntPtr.Zero; InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref size);
                attributes = Marshal.AllocHGlobal(size);
                if (!InitializeProcThreadAttributeList(attributes, 1, 0, ref size)) throw new Win32Exception(Marshal.GetLastWin32Error());
                initialized = true; parentValue = Marshal.AllocHGlobal(IntPtr.Size); Marshal.WriteIntPtr(parentValue, parent);
                if (!UpdateProcThreadAttribute(attributes, 0, new IntPtr(0x00020000), parentValue, new IntPtr(IntPtr.Size), IntPtr.Zero, IntPtr.Zero)) throw new Win32Exception(Marshal.GetLastWin32Error());
                var startup = new StartupInfoEx { Startup = new StartupInfo { Size = Marshal.SizeOf(typeof(StartupInfoEx)) }, Attributes = attributes };
                ProcessInfo child;
                if (!CreateProcess(executable, new StringBuilder(Proc.Quote(executable) + (string.IsNullOrEmpty(arguments) ? "" : " " + arguments)),
                    IntPtr.Zero, IntPtr.Zero, false, 0x00080000 | 0x00000400 | 0x00000010, environment, Path.GetDirectoryName(executable), ref startup, out child))
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
    }
}

// OpenSSH Server Manager for Windows: Sessions

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Windows.Forms;
using Microsoft.Win32;

namespace OpenSSHServerManager
{
    // ------------------------------------------------------------------------------------------
    // Live sessions (sshd-session.exe processes, owners and TCP peers)
    // ------------------------------------------------------------------------------------------
    internal sealed class SessionInfo { public int Pid; public string User = ""; public DateTime Start; public string Peer = ""; }

    internal static class Sessions
    {
        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_TCPROW_OWNER_PID { public uint state; public uint localAddr; public uint localPort; public uint remoteAddr; public uint remotePort; public uint owningPid; }
        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_TCP6ROW_OWNER_PID
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] localAddr; public uint localScopeId; public uint localPort;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] remoteAddr; public uint remoteScopeId; public uint remotePort;
            public uint state; public uint owningPid;
        }
        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(IntPtr table, ref int size, bool sort, int family, int tableClass, uint reserved);

        private static int NetPort(uint p) { return (int)(((p & 0xff) << 8) | ((p >> 8) & 0xff)); }

        /// <summary>Maps process id to "remote:port" for established IPv4 and IPv6 connections on the given local port.</summary>
        private static Dictionary<int, string> PeersByPid(int port)
        {
            var d = new Dictionary<int, string>();
            Action<int, string> add = (pid, peer) => { d[pid] = d.ContainsKey(pid) ? d[pid] + ", " + peer : peer; };
            foreach (int family in new[] { 2 /*AF_INET*/, 23 /*AF_INET6*/ })
            {
                try
                {
                    int size = 0;
                    GetExtendedTcpTable(IntPtr.Zero, ref size, false, family, 5 /*TCP_TABLE_OWNER_PID_ALL*/, 0);
                    if (size <= 0) continue;
                    var buf = Marshal.AllocHGlobal(size);
                    try
                    {
                        if (GetExtendedTcpTable(buf, ref size, false, family, 5, 0) != 0) continue;
                        int n = Marshal.ReadInt32(buf);
                        var p = new IntPtr(buf.ToInt64() + 4);
                        if (family == 2)
                        {
                            int rowSize = Marshal.SizeOf(typeof(MIB_TCPROW_OWNER_PID));
                            for (int i = 0; i < n; i++)
                            {
                                var row = (MIB_TCPROW_OWNER_PID)Marshal.PtrToStructure(new IntPtr(p.ToInt64() + i * rowSize), typeof(MIB_TCPROW_OWNER_PID));
                                if (row.state != 5 /*ESTABLISHED*/ || NetPort(row.localPort) != port) continue;
                                add((int)row.owningPid, new IPAddress(row.remoteAddr) + ":" + NetPort(row.remotePort));
                            }
                        }
                        else
                        {
                            int rowSize = Marshal.SizeOf(typeof(MIB_TCP6ROW_OWNER_PID));
                            for (int i = 0; i < n; i++)
                            {
                                var row = (MIB_TCP6ROW_OWNER_PID)Marshal.PtrToStructure(new IntPtr(p.ToInt64() + i * rowSize), typeof(MIB_TCP6ROW_OWNER_PID));
                                if (row.state != 5 || NetPort(row.localPort) != port) continue;
                                var addr = new IPAddress(row.remoteAddr, row.remoteScopeId);
                                add((int)row.owningPid, (addr.IsIPv4MappedToIPv6 ? addr.MapToIPv4().ToString() : "[" + addr + "]") + ":" + NetPort(row.remotePort));
                            }
                        }
                    }
                    finally { Marshal.FreeHGlobal(buf); }
                }
                catch { }
            }
            return d;
        }

        [DllImport("kernel32.dll", SetLastError = true)] private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool CloseHandle(IntPtr h);
        [DllImport("advapi32.dll", SetLastError = true)] private static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);

        /// <summary>Account that owns a process, from its primary token (works for SYSTEM and user processes when elevated).</summary>
        public static string OwnerOf(int pid)
        {
            IntPtr h = IntPtr.Zero, tok = IntPtr.Zero;
            try
            {
                h = OpenProcess(0x1000 /*PROCESS_QUERY_LIMITED_INFORMATION*/, false, pid);
                if (h == IntPtr.Zero) h = OpenProcess(0x0400 /*PROCESS_QUERY_INFORMATION*/, false, pid);
                if (h == IntPtr.Zero) return "?";
                if (!OpenProcessToken(h, 0x0008 /*TOKEN_QUERY*/, out tok)) return "?";
                using (var id = new WindowsIdentity(tok)) return id.Name;
            }
            catch { return "?"; }
            finally { if (tok != IntPtr.Zero) CloseHandle(tok); if (h != IntPtr.Zero) CloseHandle(h); }
        }

        /// <summary>Established connections on the server port: "remote -> owning process".</summary>
        public static List<string[]> Connections(int port)
        {
            var l = new List<string[]>();
            foreach (var kv in PeersByPid(port))
            {
                string name = "?"; try { using (var p = Process.GetProcessById(kv.Key)) name = p.ProcessName; } catch { }
                foreach (var peer in kv.Value.Split(new[] { ", " }, StringSplitOptions.RemoveEmptyEntries)) l.Add(new[] { peer, name + " (PID " + kv.Key + ")" });
            }
            return l;
        }

        public static List<SessionInfo> List(int port)
        {
            var l = new List<SessionInfo>();
            try
            {
                foreach (var p in Process.GetProcessesByName("sshd-session"))
                {
                    using (p)
                    {
                        var si = new SessionInfo { Pid = p.Id, User = OwnerOf(p.Id) };
                        try { si.Start = p.StartTime; } catch { }
                        l.Add(si);
                    }
                }
            }
            catch (Exception ex) { l.Add(new SessionInfo { Pid = 0, User = "error: " + ex.Message }); }
            return l.OrderBy(s => s.Start).ThenBy(s => s.Pid).ToList();
        }

        public static void Disconnect(int pid)
        {
            using (var p = Process.GetProcessById(pid))
            {
                if (!p.ProcessName.Equals("sshd-session", StringComparison.OrdinalIgnoreCase)) throw new Exception("Process " + pid + " is not an sshd session.");
                p.Kill(); p.WaitForExit(5000);
            }
        }
    }
}

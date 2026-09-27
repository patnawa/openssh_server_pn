// OpenSSH Server PN Manager: Sessions

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

namespace OpenSSHServerPNManager
{
    // ------------------------------------------------------------------------------------------
    // Live sessions (sshd-session.exe processes, owners and TCP peers)
    // ------------------------------------------------------------------------------------------
    internal sealed class SessionInfo { public int Pid; public string User = ""; public DateTime Start; public string Peer = ""; public string Activity = ""; }

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

        /// <summary>
        /// The client addresses of logged-in sessions: the sshd-session.exe that holds the connection (SYSTEM) has a child
        /// sshd-session.exe that runs as the account. Connections still at the login prompt are not counted.
        /// </summary>
        public static HashSet<string> LoggedInAddresses(int port)
        {
            var set = new HashSet<string>();
            var all = Snapshot();
            foreach (var kv in PeersByPid(port))
            {
                bool loggedIn = all.Any(p => p.ParentPid == kv.Key && p.Name.Equals("sshd-session.exe", StringComparison.OrdinalIgnoreCase) && OwnerOf(p.Pid).IndexOf("SYSTEM", StringComparison.OrdinalIgnoreCase) < 0);
                if (!loggedIn) continue;
                foreach (var peer in kv.Value.Split(new[] { ", " }, StringSplitOptions.RemoveEmptyEntries)) set.Add(AddressOf(peer));
            }
            return set;
        }

        /// <summary>The address of "1.2.3.4:5678" or "[2001:db8::1]:5678".</summary>
        public static string AddressOf(string peer)
        {
            peer = (peer ?? "").Trim();
            if (peer.StartsWith("[")) { int end = peer.IndexOf(']'); return end > 0 ? peer.Substring(1, end - 1) : peer.Trim('[', ']'); }
            int colon = peer.LastIndexOf(':');
            return colon > 0 && peer.IndexOf(':') == colon ? peer.Substring(0, colon) : peer;
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

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct PROCESSENTRY32W
        {
            public int dwSize; public int cntUsage; public int th32ProcessID; public IntPtr th32DefaultHeapID; public int th32ModuleID;
            public int cntThreads; public int th32ParentProcessID; public int pcPriClassBase; public int dwFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szExeFile;
        }
        [DllImport("kernel32.dll", SetLastError = true)] private static extern IntPtr CreateToolhelp32Snapshot(uint flags, int pid);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool Process32FirstW(IntPtr snapshot, ref PROCESSENTRY32W entry);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool Process32NextW(IntPtr snapshot, ref PROCESSENTRY32W entry);

        /// <summary>One process of a snapshot of the process list.</summary>
        internal struct ProcessEntry { public int Pid, ParentPid; public string Name; }

        /// <summary>Every process, with its parent and program name, from one snapshot.</summary>
        private static List<ProcessEntry> Snapshot()
        {
            var l = new List<ProcessEntry>();
            var snap = CreateToolhelp32Snapshot(0x2 /*TH32CS_SNAPPROCESS*/, 0);
            if (snap == IntPtr.Zero || snap == new IntPtr(-1)) return l;
            try
            {
                var e = new PROCESSENTRY32W { dwSize = Marshal.SizeOf(typeof(PROCESSENTRY32W)) };
                for (bool more = Process32FirstW(snap, ref e); more; more = Process32NextW(snap, ref e))
                    l.Add(new ProcessEntry { Pid = e.th32ProcessID, ParentPid = e.th32ParentProcessID, Name = e.szExeFile });
            }
            finally { CloseHandle(snap); }
            return l;
        }

        /// <summary>
        /// The programs a process started, its children first, then theirs, down to three levels: sshd for Windows starts
        /// a subsystem such as sftp-server.exe through the account's shell (cmd.exe /c ...), so the program that matters is
        /// often a grandchild.
        /// </summary>
        internal static List<string> Descendants(int pid, IEnumerable<ProcessEntry> all)
        {
            var byParent = all.Where(p => p.Pid != p.ParentPid).ToLookup(p => p.ParentPid);
            var names = new List<string>(); var level = new List<int> { pid }; var seen = new HashSet<int> { pid };
            for (int depth = 0; depth < 3 && level.Count > 0; depth++)
            {
                var next = new List<int>();
                foreach (var parent in level)
                    foreach (var c in byParent[parent])
                        if (seen.Add(c.Pid)) { names.Add(c.Name); next.Add(c.Pid); }
                level = next;
            }
            return names;
        }

        /// <summary>
        /// What a user's session does, from the programs its sshd-session.exe started (Descendants): "SFTP"
        /// (sftp-server.exe, which internal-sftp runs too), "scp", or the shell or command; empty for a session that only
        /// forwards ports or has nothing running. The console host of a terminal (conhost.exe) is left out.
        /// </summary>
        internal static string Activity(IEnumerable<string> descendants)
        {
            var names = (descendants ?? Enumerable.Empty<string>()).Where(n => !n.Equals("conhost.exe", StringComparison.OrdinalIgnoreCase)).ToList();
            if (names.Any(n => n.Equals("sftp-server.exe", StringComparison.OrdinalIgnoreCase))) return "SFTP";
            if (names.Any(n => n.Equals("scp.exe", StringComparison.OrdinalIgnoreCase))) return "scp";
            return string.Join(", ", names.Distinct(StringComparer.OrdinalIgnoreCase));
        }

        /// <summary>SFTP sessions open now: sftp-server.exe processes below an sshd-session.exe (one process snapshot).</summary>
        public static int SftpSessionCount() { return SftpSessionCount(Snapshot()); }

        internal static int SftpSessionCount(List<ProcessEntry> all)
        {
            var byPid = new Dictionary<int, ProcessEntry>();
            foreach (var p in all) byPid[p.Pid] = p;
            return all.Count(p =>
            {
                if (!p.Name.Equals("sftp-server.exe", StringComparison.OrdinalIgnoreCase)) return false;
                ProcessEntry up = p;
                for (int depth = 0; depth < 3; depth++)
                {
                    if (!byPid.TryGetValue(up.ParentPid, out up) || up.Pid == up.ParentPid) return false;
                    if (up.Name.Equals("sshd-session.exe", StringComparison.OrdinalIgnoreCase)) return true;
                }
                return false;
            });
        }

        public static List<SessionInfo> List(int port)
        {
            var l = new List<SessionInfo>();
            try
            {
                var all = Snapshot();
                foreach (var p in Process.GetProcessesByName("sshd-session"))
                {
                    using (p)
                    {
                        var si = new SessionInfo { Pid = p.Id, User = OwnerOf(p.Id) };
                        try { si.Start = p.StartTime; } catch { }
                        if (si.User.IndexOf("SYSTEM", StringComparison.OrdinalIgnoreCase) < 0) si.Activity = Activity(Descendants(p.Id, all));
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

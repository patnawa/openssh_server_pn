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
        /// <summary>Established peers on every requested listener, from a complete Windows TCP snapshot.</summary>
        private static Dictionary<int, string> PeersByPid(int port) { return PeersByPid(new[] { port }); }
        private static Dictionary<int, string> PeersByPid(IEnumerable<int> ports)
        {
            List<TcpConnection> rows; string error;
            if (!WindowsTcp.TryRead(out rows, out error)) throw new InvalidOperationException("Cannot inspect TCP peers: " + error);
            var wanted = new HashSet<int>(ports);
            return rows.Where(r => r.State == 5 && wanted.Contains(r.LocalPort)).GroupBy(r => r.Pid)
                .ToDictionary(g => g.Key, g => string.Join(", ", g.Select(r => r.Peer)));
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

        /// <summary>The client addresses of logged-in sessions (TryLoggedInAddresses). Connections still at the login prompt are not counted.</summary>
        public static HashSet<string> LoggedInAddresses(int port)
        {
            HashSet<string> addresses; string error;
            if (!TryLoggedInAddresses(new[] { port }, out addresses, out error)) throw new InvalidOperationException(error);
            return addresses;
        }

        /// <summary>A login as sshd records it: "Accepted method for user from address port N ...", logged by the session's monitor.</summary>
        internal sealed class SessionLogin { public int Pid; public DateTime TimeUtc; public string Address = ""; public int Port; }

        private static readonly Regex AcceptedLine = new Regex(@"^Accepted \S+ for .+ from (\S+) port (\d{1,5})(?:\s|$)", RegexOptions.CultureInvariant);

        internal static SessionLogin ParseAccepted(int pid, DateTime timeUtc, string message)
        {
            var m = AcceptedLine.Match((message ?? "").Trim()); int port;
            if (!m.Success || !int.TryParse(m.Groups[2].Value, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out port) || port < 1 || port > 65535) return null;
            return new SessionLogin { Pid = pid, TimeUtc = timeUtc, Address = m.Groups[1].Value, Port = port };
        }

        /// <summary>An address as the TCP table writes it: IPv4-mapped IPv6 as IPv4, canonical text.</summary>
        internal static string CanonicalAddress(string address)
        {
            IPAddress ip;
            if (!IPAddress.TryParse(address ?? "", out ip)) return (address ?? "").ToLowerInvariant();
            if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
            return ip.ToString().ToLowerInvariant();
        }

        /// <summary>
        /// Which established peers belong to logged-in sessions. The TCP table cannot tell: the listening sshd.exe accepted
        /// every connection and still owns it there, while the session runs in a SYSTEM sshd-session.exe (the monitor) whose
        /// child sshd-session.exe is the account's. The monitor logs the login with the client's address and port, so a
        /// session's peer is that login's connection while it is still established. Logins found are kept in known (by process
        /// id and start time): the circular OpenSSH log overwrites them during a long session. A session whose login is unknown
        /// (log overwritten, sshd logging to a file, a session older than this version) could be any established peer that no
        /// known login explains, so all of those count as logged in; the result says so. Returns that note, or null.
        /// </summary>
        internal static string MatchLoggedIn(IList<TcpConnection> established, IEnumerable<ProcessEntry> userSessions, Func<int, DateTime?> startUtc,
                                             IList<SessionLogin> logins, IDictionary<string, SessionLogin> known, HashSet<string> addresses)
        {
            var unknown = new List<int>(); var explained = new HashSet<TcpConnection>();
            foreach (var u in userSessions)
            {
                SessionLogin login = null;
                foreach (var pid in new[] { u.ParentPid, u.Pid })
                {
                    var start = startUtc(pid);
                    if (start == null) continue;
                    var key = pid + "@" + start.Value.Ticks;
                    if (known.TryGetValue(key, out login)) break;
                    // A process that had the same id earlier logged its logins before this one started.
                    login = logins.Where(l => l.Pid == pid && l.TimeUtc >= start.Value.AddSeconds(-2)).OrderByDescending(l => l.TimeUtc).FirstOrDefault();
                    if (login != null) { known[key] = login; break; }
                }
                if (login == null) { unknown.Add(u.Pid); continue; }
                foreach (var r in established.Where(r => r.RemotePort == login.Port && CanonicalAddress(r.RemoteAddress) == CanonicalAddress(login.Address)))
                { addresses.Add(AddressOf(r.Peer)); explained.Add(r); }
            }
            if (unknown.Count == 0) return null;
            foreach (var r in established.Where(r => !explained.Contains(r))) addresses.Add(AddressOf(r.Peer));
            return "the client address of SSH session" + (unknown.Count == 1 ? " " : "s ") + string.Join(", ", unknown) + " is not known (its login is not in the OpenSSH event log), so every connected address counts as logged in";
        }

        /// <summary>
        /// The client addresses of logged-in sessions of the installed sshd (MatchLoggedIn). False, with the error, only when the
        /// connections or processes cannot be inspected; true with a note in error when some sessions' addresses are unknown and
        /// every connected address was counted instead.
        /// </summary>
        public static bool TryLoggedInAddresses(IEnumerable<int> ports, out HashSet<string> addresses, out string error)
        {
            addresses = new HashSet<string>(StringComparer.OrdinalIgnoreCase); error = null;
            try
            {
                List<TcpConnection> rows; string tcpError;
                if (!WindowsTcp.TryRead(out rows, out tcpError)) throw new InvalidOperationException("Cannot inspect TCP peers: " + tcpError);
                var wanted = new HashSet<int>(ports);
                var established = rows.Where(r => r.State == 5 && wanted.Contains(r.LocalPort)).ToList();
                var users = new List<ProcessEntry>();
                var all = Snapshot(true);
                var byPid = new Dictionary<int, ProcessEntry>(); foreach (var p in all) byPid[p.Pid] = p;
                // Sessions of the installed service only: the monitor of each is a child of the sshd service process. Another
                // OpenSSH server (a test sshd, MSYS2, Cygwin) has sessions that never log to this event log.
                int service = Services.PidOf("sshd");
                foreach (var p in all.Where(p => p.Name.Equals("sshd-session.exe", StringComparison.OrdinalIgnoreCase)))
                {
                    ProcessEntry monitor;
                    if (service > 0 && !(byPid.TryGetValue(p.ParentPid, out monitor) && monitor.ParentPid == service) && p.ParentPid != service) continue;
                    bool system;
                    if (TrySystemOwner(p.Pid, out system)) { if (!system) users.Add(p); continue; }
                    if (!Ended(p.Pid)) throw new InvalidOperationException("Cannot verify the owner of SSH session " + p.Pid + ".");
                }
                if (users.Count == 0 || established.Count == 0) return true;
                var starts = new Dictionary<int, DateTime?>();
                Func<int, DateTime?> startUtc = pid => { DateTime? s; if (!starts.TryGetValue(pid, out s)) starts[pid] = s = StartUtc(pid); return s; };
                var found = addresses;
                var problem = ConfigurationTransaction.Locked(KnownLoginsPath, () =>
                {
                    var known = LoadKnownLogins();
                    var before = new HashSet<string>(known.Keys);
                    var pids = users.SelectMany(u => new[] { u.ParentPid, u.Pid }).Distinct().ToList();
                    bool complete = users.All(u => new[] { u.ParentPid, u.Pid }.Any(pid => { var s = startUtc(pid); return s != null && known.ContainsKey(pid + "@" + s.Value.Ticks); }));
                    var result = MatchLoggedIn(established, users, startUtc, complete ? new List<SessionLogin>() : LoginEvents(pids), known, found);
                    var live = new HashSet<string>(pids.Select(pid => { var s = startUtc(pid); return s == null ? null : pid + "@" + s.Value.Ticks; }).Where(k => k != null));
                    foreach (var k in known.Keys.Where(k => !live.Contains(k)).ToList()) known.Remove(k);
                    if (!before.SetEquals(known.Keys))
                        try { Ini.Write(KnownLoginsPath, known.Select(kv => new KeyValuePair<string, string>("login." + kv.Key, kv.Value.Address + "|" + kv.Value.Port + "|" + kv.Value.Pid + "|" + kv.Value.TimeUtc.Ticks))); }
                        catch (Exception ex) { Log.Error("Keeping the client addresses of SSH sessions", ex, false); }
                    return result;
                });
                error = problem;
                return true;
            }
            catch (Exception ex) { addresses.Clear(); error = "Active SSH sessions could not be verified: " + ex.Message; return false; }
        }

        private static string KnownLoginsPath { get { return Path.Combine(AlertSettings.Dir, "session-logins.ini"); } }

        private static Dictionary<string, SessionLogin> LoadKnownLogins()
        {
            var d = new Dictionary<string, SessionLogin>(StringComparer.Ordinal);
            foreach (var kv in Ini.Read(KnownLoginsPath).Where(kv => kv.Key.StartsWith("login.", StringComparison.Ordinal)))
            {
                var f = kv.Value.Split('|'); int port, pid; long ticks;
                if (f.Length == 4 && int.TryParse(f[1], out port) && int.TryParse(f[2], out pid) && long.TryParse(f[3], out ticks))
                    d[kv.Key.Substring(6)] = new SessionLogin { Address = f[0], Port = port, Pid = pid, TimeUtc = new DateTime(ticks, DateTimeKind.Utc) };
            }
            return d;
        }

        /// <summary>The logins recorded by these processes, newest first, from OpenSSH/Operational.</summary>
        private static List<SessionLogin> LoginEvents(IList<int> pids)
        {
            var l = new List<SessionLogin>();
            // The event log's XPath subset limits the length of an expression: a few processes per query.
            for (int i = 0; i < pids.Count; i += 8)
            {
                var xpath = "*[System[Execution[" + string.Join(" or ", pids.Skip(i).Take(8).Select(p => "@ProcessID=" + p.ToString(System.Globalization.CultureInfo.InvariantCulture))) + "]]]";
                using (var reader = new EventLogReader(new EventLogQuery("OpenSSH/Operational", PathType.LogName, xpath) { ReverseDirection = true }))
                    for (EventRecord r = reader.ReadEvent(); r != null; r = reader.ReadEvent())
                        using (r)
                        {
                            if (r.Properties.Count < 2) continue;
                            var login = ParseAccepted(r.ProcessId ?? 0, (r.TimeCreated ?? DateTime.MinValue).ToUniversalTime(), Convert.ToString(r.Properties[1].Value));
                            if (login != null) l.Add(login);
                        }
            }
            return l;
        }

        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GetProcessTimes(IntPtr process, out long creation, out long exit, out long kernel, out long user);

        /// <summary>Whether a process ended since a snapshot listed it (ERROR_INVALID_PARAMETER: no such process), as opposed to access being refused.</summary>
        private static bool Ended(int pid)
        {
            var h = OpenProcess(0x1000, false, pid);
            if (h != IntPtr.Zero) { CloseHandle(h); return false; }
            return Marshal.GetLastWin32Error() == 87;
        }

        /// <summary>When a running process started, or null when it does not exist (any more).</summary>
        private static DateTime? StartUtc(int pid)
        {
            var h = OpenProcess(0x1000 /*PROCESS_QUERY_LIMITED_INFORMATION*/, false, pid);
            if (h == IntPtr.Zero) return null;
            try { long created, exited, kernel, user; return GetProcessTimes(h, out created, out exited, out kernel, out user) ? DateTime.FromFileTimeUtc(created) : (DateTime?)null; }
            finally { CloseHandle(h); }
        }

        private static bool TrySystemOwner(int pid, out bool system)
        {
            system = false; IntPtr process = IntPtr.Zero, token = IntPtr.Zero;
            try
            {
                process = OpenProcess(0x1000, false, pid);
                if (process == IntPtr.Zero || !OpenProcessToken(process, 8, out token)) return false;
                using (var identity = new WindowsIdentity(token)) system = identity.User.IsWellKnown(WellKnownSidType.LocalSystemSid);
                return true;
            }
            catch { return false; }
            finally { if (token != IntPtr.Zero) CloseHandle(token); if (process != IntPtr.Zero) CloseHandle(process); }
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
        { return Connections(new[] { port }); }

        public static List<string[]> Connections(IEnumerable<int> ports)
        {
            var l = new List<string[]>();
            foreach (var kv in PeersByPid(ports))
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
        private static List<ProcessEntry> Snapshot(bool requireComplete = false)
        {
            var l = new List<ProcessEntry>();
            var snap = CreateToolhelp32Snapshot(0x2 /*TH32CS_SNAPPROCESS*/, 0);
            if (snap == IntPtr.Zero || snap == new IntPtr(-1))
            {
                if (requireComplete) throw new Win32Exception(Marshal.GetLastWin32Error());
                return l;
            }
            try
            {
                var e = new PROCESSENTRY32W { dwSize = Marshal.SizeOf(typeof(PROCESSENTRY32W)) };
                for (bool more = Process32FirstW(snap, ref e); more; more = Process32NextW(snap, ref e))
                    l.Add(new ProcessEntry { Pid = e.th32ProcessID, ParentPid = e.th32ParentProcessID, Name = e.szExeFile });
                if (requireComplete && Marshal.GetLastWin32Error() != 18) throw new Win32Exception(Marshal.GetLastWin32Error());
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

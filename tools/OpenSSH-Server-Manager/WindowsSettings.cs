// OpenSSH Server Manager for Windows: WindowsSettings

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
    // Default shell (registry) and firewall (COM, language independent)
    // ------------------------------------------------------------------------------------------
    internal static class DefaultShell
    {
        private static RegistryKey Open(bool writable)
        {
            var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, Environment.Is64BitOperatingSystem ? RegistryView.Registry64 : RegistryView.Default);
            return writable ? baseKey.CreateSubKey(@"SOFTWARE\OpenSSH") : baseKey.OpenSubKey(@"SOFTWARE\OpenSSH");
        }
        public static string Get() { try { using (var k = Open(false)) return k == null ? null : k.GetValue("DefaultShell") as string; } catch { return null; } }
        public static string GetOption() { try { using (var k = Open(false)) return k == null ? null : k.GetValue("DefaultShellCommandOption") as string; } catch { return null; } }
        public static void Set(string shell, string option)
        {
            using (var k = Open(true))
            {
                if (string.IsNullOrWhiteSpace(shell)) { k.DeleteValue("DefaultShell", false); k.DeleteValue("DefaultShellCommandOption", false); return; }
                k.SetValue("DefaultShell", shell.Trim(), RegistryValueKind.String);
                if (string.IsNullOrWhiteSpace(option)) k.DeleteValue("DefaultShellCommandOption", false);
                else k.SetValue("DefaultShellCommandOption", option.Trim(), RegistryValueKind.String);
            }
        }
        public static List<string> Candidates()
        {
            var l = new List<string>();
            var pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            foreach (var p in new[] {
                Path.Combine(Environment.SystemDirectory, "cmd.exe"),
                Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe"),
                Path.Combine(pf, @"PowerShell\7\pwsh.exe"),
                Path.Combine(pf, @"Git\bin\bash.exe"),
                Path.Combine(Environment.SystemDirectory, "bash.exe") })
                if (File.Exists(p)) l.Add(p);
            return l;
        }
    }

    internal sealed class FirewallRule { public string Name; public bool Enabled; public int Profiles; public string Ports; public string Program; public string ProfilesText { get { return ProfileText(Profiles); } }
        public static string ProfileText(int p) { if ((p & 0x7fffffff) == 0x7fffffff || (p & 7) == 7) return "Domain, Private, Public"; var l = new List<string>(); if ((p & 1) != 0) l.Add("Domain"); if ((p & 2) != 0) l.Add("Private"); if ((p & 4) != 0) l.Add("Public"); return l.Count == 0 ? "none" : string.Join(", ", l); } }

    internal static class Firewall
    {
        public const string RuleName = "OpenSSH SSH Server Preview (sshd)";
        public const string ManagedRuleName = "OpenSSH SSH Server (sshd)";

        private static dynamic Policy() { return Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2")); }

        /// <summary>
        /// The inbound rule for sshd, or null. Looked up by name (Rules.Item): walking all rules costs one COM call per rule,
        /// which is quick on the window's thread but took about 150 ms per rule on the background refresh thread (more
        /// than a minute for the 1,100 rules of a test machine). All rules are walked only when the rule found by name is
        /// not the inbound one (an outbound rule of the same name).
        /// </summary>
        public static FirewallRule Get() { return Get(RuleName, ManagedRuleName); }

        /// <summary>The first inbound rule with one of these names, or null (the names are tried in order).</summary>
        public static FirewallRule Get(params string[] names)
        {
            try
            {
                dynamic policy = Policy();
                foreach (var name in names)
                {
                    dynamic byName = null;
                    try { byName = policy.Rules.Item(name); } catch (COMException) { continue; } // no rule of that name
                    if ((int)byName.Direction == 1) return FromRule(name, byName);
                    foreach (dynamic r in policy.Rules)
                    {
                        try { if ((string)r.Name == name && (int)r.Direction == 1) return FromRule(name, r); }
                        catch { }
                    }
                }
            }
            catch (Exception ex) { Log.Error("Firewall query failed", ex, false); }
            return null;
        }

        private static FirewallRule FromRule(string name, dynamic r)
        {
            return new FirewallRule { Name = name, Enabled = (bool)r.Enabled, Profiles = (int)r.Profiles, Ports = (string)r.LocalPorts, Program = (string)r.ApplicationName };
        }

        /// <summary>True when a rule's LocalPorts value ("22", "22,2222", "2000-3000", "*") admits the port.</summary>
        public static bool Covers(string ports, int port)
        {
            if (string.IsNullOrWhiteSpace(ports)) return false;
            foreach (var raw in ports.Split(','))
            {
                var t = raw.Trim();
                if (t == "*" || t.Equals("Any", StringComparison.OrdinalIgnoreCase)) return true;
                int a, b; int dash = t.IndexOf('-');
                if (dash > 0 && int.TryParse(t.Substring(0, dash), out a) && int.TryParse(t.Substring(dash + 1), out b)) { if (port >= a && port <= b) return true; }
                else if (int.TryParse(t, out a) && a == port) return true;
            }
            return false;
        }

        /// <summary>True when LocalPorts holds exactly one port number (the form the Firewall tab edits directly).</summary>
        public static bool IsSinglePort(string ports) { int p; return int.TryParse((ports ?? "").Trim(), out p) && p >= 1 && p <= 65535; }

        public static void Apply(bool enabled, int profiles, int port) { Apply(enabled, profiles, port.ToString()); }

        /// <summary>Creates or updates the inbound sshd rule; ports is a LocalPorts value such as "22" or "22,2222".</summary>
        public static void Apply(bool enabled, int profiles, string ports)
        {
            dynamic policy = Policy();
            dynamic rule = null;
            foreach (dynamic r in policy.Rules)
            {
                try { if (((string)r.Name == RuleName || (string)r.Name == ManagedRuleName) && (int)r.Direction == 1) { rule = r; break; } } catch { }
            }
            if (rule == null)
            {
                rule = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule"));
                rule.Name = ManagedRuleName;
                rule.Description = "Inbound rule for OpenSSH SSH Server (sshd), managed by OpenSSH Server Manager";
                rule.Protocol = 6; // TCP
                rule.Direction = 1; // in
                rule.Action = 1; // allow
                rule.ApplicationName = Ssh.Exe("sshd.exe");
                rule.LocalPorts = ports;
                rule.Profiles = profiles == 0 ? 0x7fffffff : profiles;
                rule.Enabled = enabled;
                policy.Rules.Add(rule);
                return;
            }
            rule.LocalPorts = ports;
            rule.Profiles = profiles == 0 ? 0x7fffffff : profiles;
            rule.Enabled = enabled;
        }

        public static void Remove()
        {
            dynamic policy = Policy();
            foreach (var name in new[] { RuleName, ManagedRuleName }) { try { policy.Rules.Remove(name); } catch { } }
        }

        /// <summary>The inbound block rule this program keeps for addresses blocked from SSH (block rules win over allow rules).</summary>
        public const string BlockRuleName = "OpenSSH Server Manager: blocked addresses";

        /// <summary>The addresses in the block rule (empty when there is none).</summary>
        public static List<string> BlockedAddresses()
        {
            try
            {
                dynamic policy = Policy();
                dynamic r = policy.Rules.Item(BlockRuleName);
                var v = (string)r.RemoteAddresses;
                if (string.IsNullOrEmpty(v) || v == "*") return new List<string>();
                return v.Split(',').Select(a => NormaliseAddress(a.Trim())).Where(a => a.Length > 0).Distinct().ToList();
            }
            catch (COMException) { return new List<string>(); } // no such rule
        }

        /// <summary>"1.2.3.4/255.255.255.255" (how Windows stores a single address) as "1.2.3.4"; ranges and subnets stay as they are.</summary>
        public static string NormaliseAddress(string a)
        {
            if (a.EndsWith("/255.255.255.255")) return a.Substring(0, a.Length - 16);
            if (a.EndsWith("/128") && a.Contains(":")) return a.Substring(0, a.Length - 4);
            return a;
        }

        /// <summary>
        /// Writes the block rule: TCP to the given local ports from these addresses is blocked on every profile. An empty
        /// list removes the rule.
        /// </summary>
        public static void SetBlockedAddresses(IList<string> addresses, string ports)
        {
            dynamic policy = Policy();
            try { policy.Rules.Remove(BlockRuleName); } catch { }
            if (addresses == null || addresses.Count == 0) return;
            dynamic rule = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule"));
            rule.Name = BlockRuleName;
            rule.Description = "Addresses blocked from SSH by OpenSSH Server Manager (Logs tab, Failed logins by address).";
            rule.Protocol = 6; rule.Direction = 1; rule.Action = 0; // TCP, inbound, block
            rule.LocalPorts = ports;
            rule.RemoteAddresses = string.Join(",", addresses);
            rule.Profiles = 0x7fffffff;
            rule.Enabled = true;
            policy.Rules.Add(rule);
        }

        /// <summary>Why an address should not be blocked (this computer, loopback, an address it cannot parse), or null.</summary>
        public static string NotBlockable(string address)
        {
            IPAddress ip;
            if (!IPAddress.TryParse(address, out ip)) return address + " is not an IP address";
            if (IPAddress.IsLoopback(ip)) return address + " is this computer (loopback)";
            try
            {
                foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
                    foreach (var ua in ni.GetIPProperties().UnicastAddresses)
                        if (ua.Address.Equals(ip)) return address + " is an address of this computer";
            }
            catch { }
            return null;
        }
    }

    // ------------------------------------------------------------------------------------------
    // Event log
    // ------------------------------------------------------------------------------------------
    internal sealed class LogEvent { public DateTime Time; public int Id; public string Level; public string Message; }

    internal static class EventLogs
    {
        public const string LogName = "OpenSSH/Operational";

        public static List<LogEvent> Read(int max, string filter) { return Read(max, filter, null, CancellationToken.None); }

        /// <summary>The newest events first, at most max, whose message contains filter; only those of the last period when given.</summary>
        public static List<LogEvent> Read(int max, string filter, TimeSpan? period, CancellationToken cancel)
        {
            var l = new List<LogEvent>();
            try
            {
                var xpath = period.HasValue ? "*[System[TimeCreated[timediff(@SystemTime) <= " + (long)period.Value.TotalMilliseconds + "]]]" : "*";
                var q = new EventLogQuery(LogName, PathType.LogName, xpath) { ReverseDirection = true };
                using (var reader = new EventLogReader(q))
                {
                    EventRecord rec;
                    while (l.Count < max && !cancel.IsCancellationRequested && (rec = reader.ReadEvent()) != null)
                    {
                        using (rec)
                        {
                            string msg;
                            try { msg = rec.FormatDescription(); } catch { msg = null; }
                            if (string.IsNullOrEmpty(msg)) { try { msg = string.Join(" ", rec.Properties.Select(p => Convert.ToString(p.Value))); } catch { msg = "(no message)"; } }
                            msg = msg.Replace("\r", " ").Replace("\n", " ").Trim();
                            if (!string.IsNullOrEmpty(filter) && msg.IndexOf(filter, StringComparison.OrdinalIgnoreCase) < 0) continue;
                            string level; try { level = rec.LevelDisplayName; } catch { level = rec.Level.ToString(); }
                            l.Add(new LogEvent { Time = rec.TimeCreated ?? DateTime.MinValue, Id = rec.Id, Level = level, Message = msg });
                        }
                    }
                }
            }
            catch (EventLogNotFoundException) { l.Add(new LogEvent { Time = DateTime.Now, Id = 0, Level = "Info", Message = "The " + LogName + " event log does not exist on this system. Install the server feature or enable file logging (SyslogFacility LOCAL0)." }); }
            catch (Exception ex) { l.Add(new LogEvent { Time = DateTime.Now, Id = 0, Level = "Error", Message = "Cannot read event log: " + ex.Message }); }
            return l;
        }

        private static readonly Regex FailurePattern = new Regex(
            @"(?:^|: )(?:Failed \S+ for (?:invalid user )?(?<user>.*?)|Invalid user (?<user>.*?)|(?:Connection closed by|Disconnected from) (?:authenticating|invalid) user (?<user>.*?)|Timeout before authentication for|maximum authentication attempts exceeded for (?:invalid user )?(?<user>.*?)) (?:from )?(?<addr>[0-9A-Fa-f.:]+) port \d+",
            RegexOptions.IgnoreCase);

        /// <summary>
        /// The client address (and the account name tried, if any) of an sshd message about a failed or abandoned login
        /// ("Failed password for x from 10.0.0.5 port 50123 ssh2", "Invalid user x from ..."), or null for other messages.
        /// </summary>
        public static string FailedLoginAddress(string message, out string user)
        {
            user = null;
            var m = FailurePattern.Match((message ?? "").Replace("sshd: ", "").Trim());
            if (!m.Success) return null;
            IPAddress ip;
            if (!IPAddress.TryParse(m.Groups["addr"].Value, out ip)) return null;
            user = m.Groups["user"].Success ? m.Groups["user"].Value : null;
            return (ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip).ToString();
        }

        /// <summary>Failed logins grouped by client address, the most first.</summary>
        public sealed class FailedSource { public string Address; public int Count; public DateTime First, Last; public SortedSet<string> Users = new SortedSet<string>(StringComparer.OrdinalIgnoreCase); }

        public static List<FailedSource> FailedByAddress(IEnumerable<LogEvent> events)
        {
            var d = new Dictionary<string, FailedSource>();
            foreach (var e in events)
            {
                string user; var a = FailedLoginAddress(e.Message, out user);
                if (a == null) continue;
                FailedSource s;
                if (!d.TryGetValue(a, out s)) d[a] = s = new FailedSource { Address = a, First = e.Time, Last = e.Time };
                s.Count++;
                if (e.Time < s.First) s.First = e.Time;
                if (e.Time > s.Last) s.Last = e.Time;
                if (!string.IsNullOrEmpty(user)) s.Users.Add(user);
            }
            return d.Values.OrderByDescending(x => x.Count).ThenByDescending(x => x.Last).ToList();
        }

        public static string FileLogPath()
        {
            try
            {
                if (!Directory.Exists(Ssh.LogDir)) return null;
                return Directory.GetFiles(Ssh.LogDir, "sshd*.log").OrderByDescending(f => File.GetLastWriteTime(f)).FirstOrDefault();
            }
            catch { return null; }
        }

        public static string TailFile(string path, int lines)
        {
            try
            {
                const int window = 512 * 1024; // sshd.log can grow to hundreds of MB; read only the end
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                {
                    bool partial = fs.Length > window;
                    if (partial) fs.Seek(-window, SeekOrigin.End);
                    using (var sr = new StreamReader(fs, Encoding.UTF8))
                    {
                        var all = sr.ReadToEnd().Split('\n');
                        if (partial && all.Length > 1) all = all.Skip(1).ToArray(); // first line is cut
                        return string.Join("\n", all.Skip(Math.Max(0, all.Length - lines)));
                    }
                }
            }
            catch (Exception ex) { return "Cannot read " + path + ": " + ex.Message; }
        }
    }
}

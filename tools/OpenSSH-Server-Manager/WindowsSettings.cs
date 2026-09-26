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
    }

    // ------------------------------------------------------------------------------------------
    // Event log
    // ------------------------------------------------------------------------------------------
    internal sealed class LogEvent { public DateTime Time; public int Id; public string Level; public string Message; }

    internal static class EventLogs
    {
        public const string LogName = "OpenSSH/Operational";

        public static List<LogEvent> Read(int max, string filter)
        {
            var l = new List<LogEvent>();
            try
            {
                var q = new EventLogQuery(LogName, PathType.LogName) { ReverseDirection = true };
                using (var reader = new EventLogReader(q))
                {
                    EventRecord rec;
                    while (l.Count < max && (rec = reader.ReadEvent()) != null)
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

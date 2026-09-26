// OpenSSH Server Manager for Windows: Ssh

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
    // Paths, versions, config test
    // ------------------------------------------------------------------------------------------
    internal static class Ssh
    {
        private static string _installDir;
        public static string InstallDir
        {
            get
            {
                if (_installDir != null) return _installDir;
                string dir = null;
                try
                {
                    using (var k = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default).OpenSubKey(@"SYSTEM\CurrentControlSet\Services\sshd"))
                    {
                        var img = k == null ? null : k.GetValue("ImagePath") as string;
                        if (!string.IsNullOrEmpty(img))
                        {
                            img = Environment.ExpandEnvironmentVariables(img.Trim());
                            if (img.StartsWith("\"")) img = img.Substring(1, Math.Max(0, img.IndexOf('"', 1) - 1));
                            else if (img.IndexOf(" -", StringComparison.Ordinal) > 0) img = img.Substring(0, img.IndexOf(" -", StringComparison.Ordinal));
                            if (File.Exists(img)) dir = Path.GetDirectoryName(img);
                        }
                    }
                }
                catch { }
                if (dir == null)
                {
                    var pf = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "OpenSSH");
                    var sys = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), @"System32\OpenSSH");
                    dir = File.Exists(Path.Combine(pf, "sshd.exe")) ? pf : (File.Exists(Path.Combine(sys, "sshd.exe")) ? sys : pf);
                }
                _installDir = dir;
                return dir;
            }
        }
        /// <summary>--selftest only: a scratch folder in place of %ProgramData%\ssh, so window tests never touch the live files.</summary>
        internal static string ConfigDirOverride;
        public static string ConfigDir { get { return ConfigDirOverride ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "ssh"); } }
        public static string ConfigPath { get { return Path.Combine(ConfigDir, "sshd_config"); } }
        public static string DefaultConfigPath { get { return Path.Combine(InstallDir, "sshd_config_default"); } }
        public static string AdminKeysPath { get { return Path.Combine(ConfigDir, "administrators_authorized_keys"); } }
        public static string LogDir { get { return Path.Combine(ConfigDir, "logs"); } }
        public static string Exe(string name) { return Path.Combine(InstallDir, name); }

        public static string ServerVersion()
        {
            try { var p = Exe("sshd.exe"); return File.Exists(p) ? FileVersionInfo.GetVersionInfo(p).FileVersion + " (" + FileVersionInfo.GetVersionInfo(p).ProductVersion + ")" : "not installed"; }
            catch (Exception ex) { return "unknown (" + ex.Message + ")"; }
        }
        public static string ClientBanner()
        {
            var r = Proc.Run(Exe("ssh.exe"), "-V", 10000);
            return r.Output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() ?? "unknown";
        }

        /// <summary>Runs sshd -t against the live configuration, or against a candidate file.</summary>
        public static RunResult TestConfig(string candidatePath)
        {
            var args = "-t" + (candidatePath != null ? " -f \"" + candidatePath + "\"" : "");
            return Proc.Run(Exe("sshd.exe"), args, 20000);
        }

        /// <summary>Effective settings as reported by sshd -T (keyword => value, lower-case keywords).</summary>
        public static Dictionary<string, string> EffectiveSettings() { string err; return EffectiveSettings(out err); }
        public static Dictionary<string, string> EffectiveSettings(out string error)
        {
            var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var r = Proc.Run(Exe("sshd.exe"), "-T", 20000);
            error = r.Ok ? null : ("sshd -T failed (exit " + r.ExitCode + "): " + r.Output);
            foreach (var line in r.StdOut.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
            {
                var i = line.IndexOf(' ');
                if (i <= 0) continue;
                var k = line.Substring(0, i); var v = line.Substring(i + 1).Trim();
                if (!d.ContainsKey(k)) d[k] = v; else d[k] += ", " + v;
            }
            return d;
        }

        /// <summary>
        /// The first authorized_keys file sshd reads for an account, with Match blocks applied (sshd -T -C, optionally on a
        /// candidate configuration), tokens expanded and relative paths resolved against the home folder. Null when sshd
        /// cannot tell.
        /// </summary>
        public static string AuthorizedKeysFileFor(string user, string home, string configPath = null)
        {
            // Match User compares with the login name in sshd's form, which sshd lower-cases.
            var r = Proc.Run(Exe("sshd.exe"), "-T" + (configPath != null ? " -f " + Proc.Quote(configPath) : "") + " -C " + Proc.Quote("user=" + Accounts.AsciiLower(user) + ",host=localhost,addr=127.0.0.1"), 20000);
            if (!r.Ok) return null;
            // sshd prints keywords in mixed case since 10.4 (AuthorizedKeysFile), lower case before.
            var m = Regex.Match(r.StdOut, @"^authorizedkeysfile\s+(.+?)\s*$", RegexOptions.Multiline | RegexOptions.IgnoreCase);
            return m.Success ? ResolveKeysFile(m.Groups[1].Value, user, home) : null;
        }

        /// <summary>The first file of an AuthorizedKeysFile value, tokens expanded; a relative path needs the home folder (null when unknown).</summary>
        public static string ResolveKeysFile(string value, string user, string home)
        {
            var first = (value ?? "").Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
            if (string.IsNullOrEmpty(first) || first.Equals("none", StringComparison.OrdinalIgnoreCase)) return null;
            if (string.IsNullOrEmpty(home) && first.Contains("%h")) return null;
            first = first.Replace("__PROGRAMDATA__", Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData))
                         .Replace("%h", home ?? "").Replace("%u", user).Replace("%%", "%").Replace('/', '\\');
            if (Path.IsPathRooted(first)) return Path.GetFullPath(first);
            return string.IsNullOrEmpty(home) ? null : Path.GetFullPath(Path.Combine(home, first));
        }

        /// <summary>Writes a known_hosts file that trusts only this server's own host keys, for connections to host:port.</summary>
        public static void WriteKnownHosts(string path, string host, int port)
        {
            var name = port == 22 ? host : "[" + host + "]:" + port;
            var lines = new List<string>();
            foreach (var f in Directory.GetFiles(ConfigDir, "ssh_host_*_key.pub"))
            {
                var parts = File.ReadAllText(f).Trim().Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length >= 2) lines.Add(name + " " + parts[0] + " " + parts[1]);
            }
            if (lines.Count == 0) throw new Exception("No host keys found in " + ConfigDir + ".");
            File.WriteAllLines(path, lines);
        }
    }

    // ------------------------------------------------------------------------------------------
    // Services
    // ------------------------------------------------------------------------------------------
    internal sealed class ServiceState { public string Name; public string Status = "not installed"; public string StartMode = "?"; public bool Exists; public int Pid; }

    internal static class Services
    {
        /// <summary>Executable named by a service's ImagePath (quotes, arguments and environment variables handled), or null.</summary>
        public static string ImagePath(string name)
        {
            try
            {
                using (var k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\" + name))
                    return ParseImagePath(k == null ? null : k.GetValue("ImagePath") as string);
            }
            catch { return null; }
        }

        public static string ParseImagePath(string img)
        {
            if (string.IsNullOrWhiteSpace(img)) return null;
            img = Environment.ExpandEnvironmentVariables(img.Trim());
            if (img.StartsWith("\"")) { int q = img.IndexOf('"', 1); return q > 1 ? img.Substring(1, q - 1) : img.Trim('"'); }
            int e = img.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
            return e > 0 ? img.Substring(0, e + 4) : img;
        }

        /// <summary>The package's copy of an executable in %ProgramFiles%\OpenSSH or %ProgramFiles(x86)%\OpenSSH, or null.</summary>
        public static string PackageExe(string exe)
        {
            foreach (var pf in new[] { Environment.GetEnvironmentVariable("ProgramW6432"), Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86) })
            {
                if (string.IsNullOrEmpty(pf)) continue;
                var p = Path.Combine(pf, "OpenSSH", exe);
                if (File.Exists(p)) return p;
            }
            return null;
        }

        /// <summary>
        /// True when a configuration file was saved after the running service started: sshd reads sshd_config only when
        /// it starts, so the saved settings are not in effect until a restart. False when not running or unknown.
        /// </summary>
        public static bool ChangedSinceStart(ServiceState s, string configPath)
        {
            if (s == null || s.Status != "Running" || s.Pid <= 0 || !File.Exists(configPath)) return false;
            try
            {
                using (var p = Process.GetProcessById(s.Pid))
                    return RestartNeeded(p.StartTime.ToUniversalTime(), File.GetLastWriteTimeUtc(configPath));
            }
            catch { return false; }
        }

        /// <summary>A file written more than a second after the process started (file times are coarser than process times).</summary>
        public static bool RestartNeeded(DateTime processStartUtc, DateTime fileWrittenUtc) { return fileWrittenUtc > processStartUtc.AddSeconds(1); }

        public static ServiceState Status(string name)
        {
            var st = new ServiceState { Name = name };
            try
            {
                using (var sc = new ServiceController(name))
                {
                    st.Status = sc.Status.ToString();
                    st.Exists = true;
                    // ServiceController.StartType only exists from .NET Framework 4.6.1; the registry works on every 4.x.
                    st.StartMode = StartModeFromRegistry(name);
                }
                st.Pid = PidOf(name);
            }
            catch (InvalidOperationException) { st.Exists = false; st.Status = "not installed"; }
            catch (Exception ex) { st.Status = "error: " + ex.Message; }
            return st;
        }

        private static string StartModeFromRegistry(string name)
        {
            try
            {
                using (var k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\" + name))
                {
                    var v = k == null ? null : k.GetValue("Start");
                    if (v is int)
                    {
                        switch ((int)v)
                        {
                            case 2:
                                object delayed = k.GetValue("DelayedAutostart");
                                return delayed is int && (int)delayed == 1 ? "Automatic (delayed)" : "Automatic";
                            case 3: return "Manual";
                            case 4: return "Disabled";
                        }
                    }
                }
            }
            catch { }
            return "?";
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SERVICE_STATUS_PROCESS { public uint dwServiceType, dwCurrentState, dwControlsAccepted, dwWin32ExitCode, dwServiceSpecificExitCode, dwCheckPoint, dwWaitHint, dwProcessId, dwServiceFlags; }
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern IntPtr OpenSCManager(string machine, string database, uint access);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern IntPtr OpenService(IntPtr scm, string name, uint access);
        [DllImport("advapi32.dll", SetLastError = true)] private static extern bool CloseServiceHandle(IntPtr handle);
        [DllImport("advapi32.dll", SetLastError = true)] private static extern bool QueryServiceStatusEx(IntPtr service, int infoLevel, ref SERVICE_STATUS_PROCESS status, int size, out int needed);

        /// <summary>Process id of a running service through the service control manager API (no localized text parsing).</summary>
        public static int PidOf(string name)
        {
            IntPtr scm = IntPtr.Zero, svc = IntPtr.Zero;
            try
            {
                scm = OpenSCManager(null, null, 0x0001 /*SC_MANAGER_CONNECT*/);
                if (scm == IntPtr.Zero) return PidOfViaSc(name);
                svc = OpenService(scm, name, 0x0004 /*SERVICE_QUERY_STATUS*/);
                if (svc == IntPtr.Zero) return 0;
                var ssp = new SERVICE_STATUS_PROCESS(); int needed;
                if (!QueryServiceStatusEx(svc, 0 /*SC_STATUS_PROCESS_INFO*/, ref ssp, Marshal.SizeOf(typeof(SERVICE_STATUS_PROCESS)), out needed)) return PidOfViaSc(name);
                return (int)ssp.dwProcessId;
            }
            catch { return PidOfViaSc(name); }
            finally { if (svc != IntPtr.Zero) CloseServiceHandle(svc); if (scm != IntPtr.Zero) CloseServiceHandle(scm); }
        }

        private static int PidOfViaSc(string name)
        {
            try
            {
                var r = Proc.Run(Path.Combine(Environment.SystemDirectory, "sc.exe"), "queryex " + name, 10000);
                var m = Regex.Match(r.StdOut, @"PID\s*:\s*(\d+)");
                return m.Success ? int.Parse(m.Groups[1].Value) : 0;
            }
            catch { return 0; }
        }

        public static void Start(string name, int timeoutSec = 40)
        {
            using (var sc = new ServiceController(name))
            {
                if (sc.Status == ServiceControllerStatus.Running) return;
                if (sc.Status != ServiceControllerStatus.StartPending) sc.Start();
                sc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(timeoutSec));
            }
        }
        public static void Stop(string name, int timeoutSec = 40)
        {
            using (var sc = new ServiceController(name))
            {
                if (sc.Status == ServiceControllerStatus.Stopped) return;
                if (sc.Status != ServiceControllerStatus.StopPending) sc.Stop();
                sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(timeoutSec));
            }
        }
        public static void Restart(string name) { Stop(name); Start(name); }

        public static void SetStartMode(string name, string mode)
        {
            var r = Proc.Run(Path.Combine(Environment.SystemDirectory, "sc.exe"), "config " + name + " start= " + mode, 10000);
            if (!r.Ok) throw new Exception("sc config failed: " + r.Output);
        }
    }

    // ------------------------------------------------------------------------------------------
    // Network: listeners and sessions
    // ------------------------------------------------------------------------------------------
    internal static class Net
    {
        public static List<string> Listeners(int port)
        {
            var l = new List<string>();
            try
            {
                foreach (var ep in IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners())
                    if (ep.Port == port) l.Add(ep.ToString());
            }
            catch (Exception ex) { l.Add("error: " + ex.Message); }
            return l;
        }
        public static List<string> Sessions(int port)
        {
            var l = new List<string>();
            try
            {
                foreach (var c in IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections())
                    if (c.LocalEndPoint.Port == port && c.State == TcpState.Established) l.Add(c.RemoteEndPoint.ToString());
            }
            catch { }
            return l;
        }
        public static string Banner(int port)
        {
            try
            {
                using (var c = new System.Net.Sockets.TcpClient())
                {
                    var ar = c.BeginConnect(IPAddress.Loopback, port, null, null);
                    if (!ar.AsyncWaitHandle.WaitOne(3000)) return "no answer on port " + port;
                    c.EndConnect(ar);
                    var s = c.GetStream(); s.ReadTimeout = 3000;
                    var b = new byte[256]; var n = s.Read(b, 0, b.Length);
                    return Encoding.ASCII.GetString(b, 0, n).Trim();
                }
            }
            catch (Exception ex) { return "no answer (" + ex.Message + ")"; }
        }
    }
}

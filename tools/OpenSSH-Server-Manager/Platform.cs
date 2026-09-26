// OpenSSH Server Manager for Windows: Platform

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
    internal static class Elevation
    {
        public static bool IsAdministrator()
        {
            try { return new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator); }
            catch { return false; }
        }
        public static bool Relaunch()
        {
            try
            {
                var psi = new ProcessStartInfo(Application.ExecutablePath) { UseShellExecute = true, Verb = "runas" };
                Process.Start(psi);
                return true;
            }
            catch { return false; }
        }
    }

    internal static class Log
    {
        private static readonly object Gate = new object();
        public static string Path
        {
            get
            {
                var dir = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "OpenSSH Server Manager");
                try { Directory.CreateDirectory(dir); } catch { }
                return System.IO.Path.Combine(dir, "manager.log");
            }
        }
        public static void Info(string msg) { Write("INFO ", msg); }
        public static void Error(string msg, Exception ex, bool show)
        {
            Write("ERROR", msg + (ex != null ? ": " + ex : ""));
            if (show && !Program.Unattended)
            {
                try
                {
                    MessageBox.Show(msg + "\n\n" + (ex != null ? ex.Message : "") + "\n\nDetails were written to\n" + Path,
                        Program.AppName, MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
                catch { }
            }
        }
        private static void Write(string level, string msg)
        {
            try { lock (Gate) File.AppendAllText(Path, DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + " " + level + " " + msg + Environment.NewLine); }
            catch { }
        }
    }

    // ------------------------------------------------------------------------------------------
    // Process runner
    // ------------------------------------------------------------------------------------------
    internal sealed class RunResult
    {
        public int ExitCode;
        public string StdOut = "";
        public string StdErr = "";
        public bool TimedOut;
        public string Output { get { return (StdOut + Environment.NewLine + StdErr).Trim(); } }
        public bool Ok { get { return ExitCode == 0 && !TimedOut; } }
    }

    internal static class Proc
    {
        /// <summary>Quotes one argument for a Windows command line (CommandLineToArgvW / C runtime rules).</summary>
        public static string Quote(string arg)
        {
            arg = arg ?? "";
            if (arg.Length > 0 && arg.IndexOfAny(new[] { ' ', '\t', '"' }) < 0) return arg;
            var sb = new StringBuilder("\"");
            int backslashes = 0;
            foreach (char c in arg)
            {
                if (c == '\\') { backslashes++; continue; }
                if (c == '"') { sb.Append('\\', backslashes * 2 + 1); sb.Append('"'); backslashes = 0; continue; }
                sb.Append('\\', backslashes); backslashes = 0; sb.Append(c);
            }
            sb.Append('\\', backslashes * 2);
            sb.Append('"');
            return sb.ToString();
        }

        public static RunResult Run(string exe, string args, int timeoutMs = 30000, string workDir = null) { return Run(exe, args, timeoutMs, workDir, null); }

        /// <summary>Runs a program without a window, capturing its output. env adds or replaces environment variables for this child only.</summary>
        public static RunResult Run(string exe, string args, int timeoutMs, string workDir, IDictionary<string, string> env)
        {
            var r = new RunResult();
            try
            {
                var psi = new ProcessStartInfo(exe, args)
                {
                    UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true,
                    RedirectStandardInput = env != null, // keeps the child from waiting on a console prompt
                    WorkingDirectory = workDir ?? (File.Exists(exe) ? Path.GetDirectoryName(exe) : Environment.CurrentDirectory)
                };
                if (env != null) foreach (var kv in env) psi.EnvironmentVariables[kv.Key] = kv.Value;
                using (var p = Process.Start(psi))
                {
                    if (psi.RedirectStandardInput) { try { p.StandardInput.Close(); } catch { } } // end-of-file for any prompt
                    var so = new StringBuilder(); var se = new StringBuilder();
                    p.OutputDataReceived += (s, e) => { if (e.Data != null) so.AppendLine(e.Data); };
                    p.ErrorDataReceived += (s, e) => { if (e.Data != null) se.AppendLine(e.Data); };
                    p.BeginOutputReadLine(); p.BeginErrorReadLine();
                    if (!p.WaitForExit(timeoutMs)) { r.TimedOut = true; try { p.Kill(); } catch { } }
                    else p.WaitForExit();
                    r.ExitCode = r.TimedOut ? -1 : p.ExitCode;
                    r.StdOut = so.ToString(); r.StdErr = se.ToString();
                }
            }
            catch (Exception ex) { r.ExitCode = -1; r.StdErr = ex.Message; }
            return r;
        }

        public static void OpenExternal(string target, string args = null)
        {
            try { Process.Start(new ProcessStartInfo(target, args ?? "") { UseShellExecute = true }); }
            catch (Exception ex) { Log.Error("Could not open " + target, ex, true); }
        }
    }

    // ------------------------------------------------------------------------------------------
    // Access control helpers (language independent, SID based)
    // ------------------------------------------------------------------------------------------
    internal static class Acl
    {
        private static readonly SecurityIdentifier Admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        private static readonly SecurityIdentifier System = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);

        public static bool IsAdminOnly(string path)
        {
            try
            {
                var fs = File.GetAccessControl(path);
                if (!fs.AreAccessRulesProtected) return false;
                foreach (FileSystemAccessRule r in fs.GetAccessRules(true, true, typeof(SecurityIdentifier)))
                {
                    var sid = (SecurityIdentifier)r.IdentityReference;
                    if (r.AccessControlType == AccessControlType.Allow && sid != Admins && sid != System) return false;
                }
                return true;
            }
            catch { return false; }
        }

        /// <summary>"ACL OK", "ACL TOO OPEN", or a note when the ACL cannot be read (a restricted file is unreadable without elevation).</summary>
        public static string Describe(string path)
        {
            try
            {
                var fs = File.GetAccessControl(path);
                if (!fs.AreAccessRulesProtected) return "ACL TOO OPEN (inherits permissions)";
                foreach (FileSystemAccessRule r in fs.GetAccessRules(true, true, typeof(SecurityIdentifier)))
                {
                    var sid = (SecurityIdentifier)r.IdentityReference;
                    if (r.AccessControlType == AccessControlType.Allow && sid != Admins && sid != System) return "ACL TOO OPEN (" + Name(sid) + " has access)";
                }
                return "ACL OK";
            }
            catch (UnauthorizedAccessException) { return "ACL not readable from this process (run elevated to check)"; }
            catch (Exception ex) { return "ACL unknown: " + ex.Message; }
        }

        private static string Name(SecurityIdentifier sid)
        {
            try { return sid.Translate(typeof(NTAccount)).Value; } catch { return sid.Value; }
        }

        /// <summary>Owner-style ACL: SYSTEM and Administrators full control, optional extra SID, inheritance removed.</summary>
        public static void Restrict(string path, SecurityIdentifier extra)
        {
            var fs = File.GetAccessControl(path);
            fs.SetAccessRuleProtection(true, false);
            foreach (FileSystemAccessRule r in fs.GetAccessRules(true, false, typeof(SecurityIdentifier))) fs.RemoveAccessRule(r);
            fs.AddAccessRule(new FileSystemAccessRule(System, FileSystemRights.FullControl, AccessControlType.Allow));
            fs.AddAccessRule(new FileSystemAccessRule(Admins, FileSystemRights.FullControl, AccessControlType.Allow));
            if (extra != null && extra != Admins && extra != System) fs.AddAccessRule(new FileSystemAccessRule(extra, FileSystemRights.FullControl, AccessControlType.Allow));
            File.SetAccessControl(path, fs);
        }

        public static SecurityIdentifier SidOfAccount(string account)
        {
            try { return (SecurityIdentifier)new NTAccount(account).Translate(typeof(SecurityIdentifier)); } catch { return null; }
        }

        /// <summary>A new folder that only SYSTEM and Administrators can open, for files a SYSTEM process reads or writes.</summary>
        public static void CreatePrivateFolder(string dir)
        {
            var ds = new DirectorySecurity();
            ds.SetAccessRuleProtection(true, false);
            var inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
            ds.AddAccessRule(new FileSystemAccessRule(System, FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
            ds.AddAccessRule(new FileSystemAccessRule(Admins, FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
            ds.SetOwner(Admins);
            if (Directory.Exists(dir)) throw new IOException(dir + " exists already.");
            Directory.CreateDirectory(dir, ds);
        }
    }
}

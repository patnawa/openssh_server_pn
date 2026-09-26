// OpenSSH Server Manager for Windows
// A WinForms application (.NET Framework 4.x) that manages the OpenSSH for Windows server: service
// control, sshd_config editing with validation and rollback, login methods (Windows authentication,
// public key, Kerberos; per user and group), authorized keys, a key generator, host keys, default
// shell, Windows Firewall rule, event log viewer and a hardening check.
//
// Source: one file per area in this folder (Program, SelfTest, Platform, Ssh, SshdConfig, Keys,
// KeyGen, Auth, AuthTest, WindowsSettings, Hardening, Sessions, MainForm, Dialogs), compiled into
// one executable by build.ps1 (the Roslyn C# compiler from Visual Studio Build Tools, or the inbox
// .NET Framework compiler). Runs elevated (see app.manifest).
//
// Command line (an optional file name receives the report):
//   --unittest   tests of the program logic alone: no sshd, no service, no administrator rights
//   --selftest   the unit tests plus tests against the installed server; changes nothing (elevated)
//   --check      status and hardening report
//   --keytest    every key type: generate, authorize, log in, remove (authorized_keys restored)
//   --authtest   every login-method setting with real logins against a temporary sshd on 127.0.0.1
//                and a temporary local account; both are removed at the end

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

// File properties (Explorer, Get-Item ...VersionInfo); keep in step with Program.AppVersion.
[assembly: System.Reflection.AssemblyTitle("OpenSSH Server Manager")]
[assembly: System.Reflection.AssemblyProduct("OpenSSH Server Manager")]
[assembly: System.Reflection.AssemblyDescription("Management console for the OpenSSH for Windows server")]
[assembly: System.Reflection.AssemblyVersion("1.5.0.0")]
[assembly: System.Reflection.AssemblyFileVersion("1.5.0.0")]
[assembly: System.Reflection.AssemblyInformationalVersion("1.5.0")]

namespace OpenSSHServerManager
{
    // ------------------------------------------------------------------------------------------
    // Entry point, crash protection, elevation
    // ------------------------------------------------------------------------------------------
    internal static class Program
    {
        public const string AppName = "OpenSSH Server Manager";
        public const string AppVersion = "1.5.0";
        /// <summary>True in --check, --selftest and --screenshot: no modal dialogs may block the process.</summary>
        public static bool Unattended;

        [DllImport("kernel32.dll")] private static extern bool AttachConsole(int pid);
        [DllImport("kernel32.dll")] private static extern bool FreeConsole();

        /// <summary>Unattended modes print to the console they were started from, if any.</summary>
        public static void AttachParentConsole() { AttachConsole(-1); }

        /// <summary>Prints a report of an unattended mode and writes it to a file when one was given.</summary>
        public static void Report(string text, string outFile)
        {
            Console.WriteLine(); Console.WriteLine(text);
            if (!string.IsNullOrEmpty(outFile)) { try { File.WriteAllText(outFile, text); } catch (Exception ex) { Console.WriteLine("Cannot write " + outFile + ": " + ex.Message); } }
            FreeConsole();
        }

        [STAThread]
        private static int Main(string[] args)
        {
            // SSH_ASKPASS helper for the key generator: ssh-keygen and ssh run this program with the prompt as argument
            // and read the answer from standard output. The answer comes from an environment variable that the
            // generator sets only for its own child processes, so a passphrase never appears on a command line
            // (process-creation auditing and Sysmon record command lines, not environments).
            if (Environment.GetEnvironmentVariable(KeyGen.SecretVariable) != null) return KeyGen.AskpassMain(args);
            {
                int ci = Array.FindIndex(args, a => a.Equals("--check", StringComparison.OrdinalIgnoreCase) || a.Equals("/check", StringComparison.OrdinalIgnoreCase));
                if (ci >= 0) { Unattended = true; return RunCheck(ci + 1 < args.Length ? args[ci + 1] : null); }
                int ki = Array.FindIndex(args, a => a.Equals("--keytest", StringComparison.OrdinalIgnoreCase));
                if (ki >= 0) { Unattended = true; return KeyGen.RunKeyTest(ki + 1 < args.Length ? args[ki + 1] : null); }
                int ai = Array.FindIndex(args, a => a.Equals("--authtest", StringComparison.OrdinalIgnoreCase));
                if (ai >= 0) { Unattended = true; return AuthTest.Run(ai + 1 < args.Length ? args[ai + 1] : null); }
            }

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
            Application.ThreadException += (s, e) => Log.Error("Unhandled UI exception", e.Exception, true);
            AppDomain.CurrentDomain.UnhandledException += (s, e) => Log.Error("Unhandled exception", e.ExceptionObject as Exception, true);

            {
                // --ui-scale 1.5: lay the window out as on a 150% display (with --screenshot, to check layouts).
                int us = Array.FindIndex(args, a => a.Equals("--ui-scale", StringComparison.OrdinalIgnoreCase)); float scale;
                if (us >= 0 && us + 1 < args.Length && float.TryParse(args[us + 1], System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out scale) && scale >= 0.5f && scale <= 4f) Ui.Scale = scale;
                // Automated UI test: render every tab off-screen to PNG files without touching the desktop.
                int si = Array.FindIndex(args, a => a.Equals("--screenshot", StringComparison.OrdinalIgnoreCase));
                if (si >= 0) { Unattended = true; return RunScreenshots(si + 1 < args.Length ? args[si + 1] : Path.GetTempPath()); }
                int ti = Array.FindIndex(args, a => a.Equals("--selftest", StringComparison.OrdinalIgnoreCase));
                if (ti >= 0) { Unattended = true; return SelfTest.Run(ti + 1 < args.Length ? args[ti + 1] : null, false); }
                int ui = Array.FindIndex(args, a => a.Equals("--unittest", StringComparison.OrdinalIgnoreCase));
                if (ui >= 0) { Unattended = true; return SelfTest.Run(ui + 1 < args.Length ? args[ui + 1] : null, true); }
            }

            if (!Elevation.IsAdministrator())
            {
                if (Elevation.Relaunch()) return 0;
                MessageBox.Show("OpenSSH Server Manager needs administrator rights to control the sshd service, edit the server configuration and manage keys.\n\nRight-click the program and choose \"Run as administrator\".",
                    AppName, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return 1;
            }

            Application.Run(new MainForm());
            return 0;
        }

        private static int RunScreenshots(string dir)
        {
            try
            {
                Directory.CreateDirectory(dir);
                using (var f = new MainForm())
                {
                    f.StartPosition = FormStartPosition.Manual;
                    f.Location = new Point(-20000, -20000);
                    f.ShowInTaskbar = false;
                    f.Show();
                    Application.DoEvents();
                    int n = f.TabCount;
                    for (int i = 0; i < n; i++)
                    {
                        f.SelectTabForTest(i);
                        Application.DoEvents();
                        using (var bmp = new Bitmap(f.Width, f.Height))
                        {
                            f.DrawToBitmap(bmp, new Rectangle(0, 0, f.Width, f.Height));
                            bmp.Save(Path.Combine(dir, "tab-" + i + "-" + Regex.Replace(f.TabName(i), @"[^A-Za-z0-9]+", "_") + ".png"), System.Drawing.Imaging.ImageFormat.Png);
                        }
                    }
                    // The Authentication tab with example rules (in the window only, nothing is saved) and the rule dialog.
                    for (int i = 0; i < n; i++) if (f.TabName(i) == "Authentication") f.SelectTabForTest(i);
                    f.ShowAuthExampleForTest();
                    Application.DoEvents();
                    using (var bmp = new Bitmap(f.Width, f.Height))
                    {
                        f.DrawToBitmap(bmp, new Rectangle(0, 0, f.Width, f.Height));
                        bmp.Save(Path.Combine(dir, "authentication-example.png"), System.Drawing.Imaging.ImageFormat.Png);
                    }
                    var sample = new AuthRule { IsGroup = true, Name = "administrators", Methods = new AuthMethods { Password = false, PublicKey = true } };
                    using (var d = new RuleDialog(sample, new List<AuthRule>(), false) { StartPosition = FormStartPosition.Manual, Location = new Point(-20000, -20000) })
                    {
                        d.Show(); Application.DoEvents();
                        using (var bmp = new Bitmap(d.Width, d.Height))
                        {
                            d.DrawToBitmap(bmp, new Rectangle(0, 0, d.Width, d.Height));
                            bmp.Save(Path.Combine(dir, "rule-dialog.png"), System.Drawing.Imaging.ImageFormat.Png);
                        }
                        d.Close();
                    }
                    f.Close();
                }
                return 0;
            }
            catch (Exception ex) { Log.Error("Screenshot mode failed", ex, false); try { File.WriteAllText(Path.Combine(dir, "error.txt"), ex.ToString()); } catch { } return 1; }
        }

        private static int RunCheck(string outFile)
        {
            AttachConsole(-1);
            var sb = new StringBuilder();
            int problems = 0;
            try
            {
                sb.AppendLine(AppName + " " + AppVersion + " self-check");
                sb.AppendLine("Elevated:            " + Elevation.IsAdministrator());
                sb.AppendLine("Install folder:      " + Ssh.InstallDir + (Directory.Exists(Ssh.InstallDir) ? "" : "  (missing)"));
                sb.AppendLine("Config folder:       " + Ssh.ConfigDir + (Directory.Exists(Ssh.ConfigDir) ? "" : "  (missing)"));
                sb.AppendLine("sshd version:        " + Ssh.ServerVersion());
                sb.AppendLine("ssh -V:              " + Ssh.ClientBanner());
                foreach (var svc in new[] { "sshd", "ssh-agent" })
                {
                    var st = Services.Status(svc);
                    sb.AppendLine((svc + " service:").PadRight(21) + st.Status + " / " + st.StartMode);
                    if (svc == "sshd" && st.Status != "Running") problems++;
                    if (svc == "sshd" && Services.ChangedSinceStart(st, Ssh.ConfigPath)) sb.AppendLine("".PadRight(21) + "sshd_config was saved after sshd started: restart sshd to apply it");
                }
                var cfg = SshdConfig.Load();
                sb.AppendLine("Port:                " + cfg.EffectivePort);
                sb.AppendLine("Listening:           " + string.Join(", ", Net.Listeners(cfg.EffectivePort)));
                if (Net.Listeners(cfg.EffectivePort).Count == 0) problems++;
                sb.AppendLine("Sessions:            " + Net.Sessions(cfg.EffectivePort).Count);
                var test = Ssh.TestConfig(null);
                sb.AppendLine("sshd -t:             " + (test.Ok ? "OK" : "FAILED: " + test.Output + (Elevation.IsAdministrator() ? "" : "  (host keys are readable by administrators only; run elevated for an accurate result)")));
                if (!test.Ok) problems++;
                var fw = Firewall.Get();
                sb.AppendLine("Firewall rule:       " + (fw == null ? "missing" : (fw.Enabled ? "enabled" : "disabled") + ", profiles " + fw.ProfilesText + ", port " + fw.Ports));
                if (fw == null || !fw.Enabled) problems++;
                sb.AppendLine("Host keys:           " + string.Join("; ", HostKeys.List().Select(k => k.Type + " " + k.Fingerprint)));
                sb.AppendLine("Admin keys file:     " + (File.Exists(Ssh.AdminKeysPath) ? "present, " + Acl.Describe(Ssh.AdminKeysPath) : "not present"));
                sb.AppendLine("Default shell:       " + (DefaultShell.Get() ?? "(cmd.exe)"));
                var auth = AuthConfig.Read(cfg);
                sb.AppendLine("Login methods:       " + auth.Global.Describe() + (auth.Rules.Count > 0 ? "; " + auth.Rules.Count + " rule(s) for users or groups" : "") +
                              (auth.RulesProblem != null ? "; rules section edited by hand (" + auth.RulesProblem + ")" : "") +
                              (auth.OtherMatchSettings.Count > 0 ? "; other Match blocks set login methods too" : ""));
                foreach (var h in Hardening.Run(cfg))
                {
                    sb.AppendLine(("[" + h.Status + "] ").PadRight(8) + h.Name + ": " + h.Detail);
                    // A service running another binary than the installed package is a fault, not a hardening advice.
                    if (h.Status == "WARN" && h.Name.StartsWith("Service binary", StringComparison.Ordinal)) problems++;
                }
                sb.AppendLine(problems == 0 ? "RESULT: OK" : "RESULT: " + problems + " problem(s)");
            }
            catch (Exception ex) { sb.AppendLine("ERROR: " + ex); problems++; }
            Console.WriteLine();
            Console.WriteLine(sb.ToString());
            if (!string.IsNullOrEmpty(outFile)) { try { File.WriteAllText(outFile, sb.ToString()); } catch (Exception ex) { Console.WriteLine("Cannot write " + outFile + ": " + ex.Message); } }
            FreeConsole();
            return problems == 0 ? 0 : 1;
        }
    }
}

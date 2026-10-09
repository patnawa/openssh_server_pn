// OpenSSH Server PN Manager: SelfTest

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
    /// <summary>--selftest and --unittest.</summary>
    internal static class SelfTest
    {
        /// <summary>
        /// --unittest (unitOnly): the program logic alone, with no sshd, no service and no administrator rights; CI runs these.
        /// --selftest: the unit tests plus tests against the installed server. Neither changes the live sshd_config, keys or service.
        /// </summary>
        public static int Run(string outFile, bool unitOnly)
        {
            Program.AttachParentConsole();
            var sb = new StringBuilder(); int failed = 0, passed = 0;
            Action<string, Func<string>> test = (name, body) =>
            {
                try { var detail = body(); passed++; sb.AppendLine("PASS  " + name + (string.IsNullOrEmpty(detail) ? "" : "  (" + detail + ")")); }
                catch (Exception ex) { failed++; sb.AppendLine("FAIL  " + name + "  " + ex.Message); }
            };
            var tmpDir = Path.Combine(Path.GetTempPath(), "osm-selftest-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(tmpDir);
            try
            {
                Unit(test, tmpDir);
                AuditTransferTests.Run(test, tmpDir);
                AuditAgentTests.Run(test);
                AuditConfigTests.Run(test, tmpDir);
                AuditDialogTests.Run(test, tmpDir);
                AuditStateTests.Run(test, tmpDir);
                AuditGuiTests.Run(test, tmpDir);
                ClientRegressionTests.Run(test, tmpDir);
                AuditInfrastructureTests.Run(test, tmpDir);
                FollowUpAuditTests.Run(test, tmpDir);
                FollowUpKeysTests.Run(test, tmpDir);
                FollowUpPartnerTests.Run(test, tmpDir);
                FollowUpAgentTests.Run(test, tmpDir);
                FollowUpConfigTests.Run(test, tmpDir);
                FollowUpGuiTests.Run(test, tmpDir);
                FollowUpClientTests.Run(test, tmpDir);
                if (!unitOnly) Server(test, tmpDir);
            }
            finally { try { Directory.Delete(tmpDir, true); } catch { } }
            sb.AppendLine((failed == 0 ? "RESULT: all " + passed + " tests passed" : "RESULT: " + failed + " of " + (passed + failed) + " tests failed") + (unitOnly ? " (unit tests only)" : ""));
            Program.Report(sb.ToString(), outFile);
            return failed == 0 ? 0 : 1;
        }

        /// <summary>Random account-like names, the same on every run (seeded), for the property tests of SshdArgs.</summary>
        private static List<string> RandomNames(int seed, int count, bool forSshd)
        {
            // Characters Windows allows in a name, plus those sshd treats specially (" ' \ # and space). For sshd runs,
            // no pattern characters (* ? ! ,) and no upper case: Match User compares patterns case-sensitively.
            var chars = (forSshd ? "" : "ABCXYZ*?!,\t") + "abcxyz0189 '\"\\#&^()%$@.-_{}~`\u0e01\u0e32\u0e44\u00e9";
            var rnd = new Random(seed); var l = new List<string>();
            while (l.Count < count)
            {
                var sb = new StringBuilder();
                if (rnd.Next(3) == 0) sb.Append("contoso\\");
                int n = 1 + rnd.Next(12);
                for (int i = 0; i < n; i++) sb.Append(chars[rnd.Next(chars.Length)]);
                var s = sb.ToString();
                if (forSshd && s.Trim() != s) continue; // Windows names never start or end with a space
                l.Add(s);
            }
            return l;
        }

        /// <summary>The main window, off-screen, on a scratch sshd_config in place of %ProgramData%\ssh (nothing live is read or written).</summary>
        private static void WithTestWindow(string tmpDir, string configText, Action<MainForm> body)
        {
            var dir = Path.Combine(tmpDir, "window-" + Guid.NewGuid().ToString("N").Substring(0, 8));
            Directory.CreateDirectory(dir);
            var old = Ssh.ConfigDirOverride; var oldContext = SynchronizationContext.Current;
            Ssh.ConfigDirOverride = dir;
            try
            {
                File.WriteAllText(Ssh.ConfigPath, configText, new UTF8Encoding(false));
                using (var f = new MainForm())
                {
                    // A scratch configuration must never write the machine's default-shell registry value.
                    bool attemptedLiveShellWrite = false;
                    typeof(MainForm).GetField("_writeDefaultShell", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)
                        .SetValue(f, (Action<string, string>)((shell, option) => { attemptedLiveShellWrite = true; throw new InvalidOperationException("The scratch window attempted a live default-shell write."); }));
                    f.StartPosition = FormStartPosition.Manual; f.Location = new Point(-20000, -20000); f.ShowInTaskbar = false;
                    // Shown is posted by WinForms. Dispatch it before waiting for the async
                    // startup operations it registers; otherwise the idle set is still empty.
                    f.Show(); Application.DoEvents(); f.WaitForIdleForTest();
                    body(f);
                    if (attemptedLiveShellWrite) throw new Exception("The scratch window attempted a live default-shell write.");
                    f.Close();
                }
            }
            finally { Ssh.ConfigDirOverride = old; SynchronizationContext.SetSynchronizationContext(oldContext); }
        }

        [DllImport("shell32.dll", CharSet = CharSet.Unicode)] private static extern uint ExtractIconEx(string file, int index, IntPtr[] large, IntPtr[] small, uint count);

        private static void Unit(Action<string, Func<string>> test, string tmpDir)
        {
            test("GUI startup: the off-screen fixture awaits posted Shown and configuration loading", () =>
            {
                WithTestWindow(tmpDir, "Port 2222\nAllowUsers alice\nAllowUsers bob\nPasswordAuthentication yes\nSubsystem sftp sftp-server.exe\n", f =>
                {
                    if (f.FieldTextForTest("AllowUsers") != "alice bob") throw new Exception("Settings were inspected before the file's AllowUsers lines were loaded");
                    if (f.WorkingValueForTest("Port") != "2222") throw new Exception("The fixture did not adopt its scratch configuration");
                    if (f.AuthCandidateForTest().Get("PasswordAuthentication") != "yes") throw new Exception("Authentication was not initialized from the file");
                    if (!SftpConfig.Read(f.SftpCandidateForTest()).Enabled) throw new Exception("SFTP was not initialized from the file");
                    if (f.UnsavedTabsForTest().Count != 0) throw new Exception("A freshly loaded fixture reports unsaved changes: " + string.Join(", ", f.UnsavedTabsForTest()));
                });
                return null;
            });
            test("GUI background fixture: refresh returns to the window after a foreground await", () =>
            {
                bool old = Control.CheckForIllegalCrossThreadCalls; Control.CheckForIllegalCrossThreadCalls = true;
                try
                {
                    WithTestWindow(tmpDir, "Port 2222\n", f =>
                    {
                        var times = f.BackgroundRefreshForTest();
                        if (times[1].TotalMilliseconds > 100) throw new Exception("Starting the background refresh blocked the window thread for " + times[1].TotalMilliseconds + " ms");
                    });
                }
                finally { Control.CheckForIllegalCrossThreadCalls = old; }
                return null;
            });
            test("program icon: every size, in the resource and in the executable", () =>
            {
                if (Ui.AppIcon == null) throw new Exception("no app.ico resource: build.ps1 did not find app.ico");
                // The sizes from the icon's own directory (ICONDIR): System.Drawing cannot pick the 256 px image, because the
                // format stores 256 as 0, so new Icon(icon, 256, 256) returns the 128 px one on .NET Framework.
                byte[] ico; using (var ms = new MemoryStream()) { Ui.AppIcon.Save(ms); ico = ms.ToArray(); }
                var sizes = Enumerable.Range(0, BitConverter.ToUInt16(ico, 4)).Select(i => ico[6 + 16 * i] == 0 ? 256 : (int)ico[6 + 16 * i]).ToList();
                var missing = new[] { 16, 20, 24, 32, 40, 48, 64, 96, 128, 256 }.Except(sizes).ToList();
                if (missing.Count > 0) throw new Exception("sizes missing from app.ico: " + string.Join(", ", missing) + " (it has " + string.Join(", ", sizes) + ")");
                var notPicked = sizes.Where(s => s < 256).Where(s => { using (var i = new Icon(Ui.AppIcon, s, s)) return i.Width != s; }).ToList();
                if (notPicked.Count > 0) throw new Exception("System.Drawing does not pick the image of size " + string.Join(", ", notPicked));
                var exe = typeof(SelfTest).Assembly.Location;
                if (ExtractIconEx(exe, -1, null, null, 0) == 0) throw new Exception(exe + " has no Win32 icon (Explorer and the taskbar show a generic one)");
                return null;
            });
            test("profile removal task: waits after boot and reports failure", () =>
            {
                var xml = SystemTasks.TaskXml("d", "c", "a", true);
                if (!xml.Contains("<BootTrigger><Enabled>true</Enabled><Delay>PT2M</Delay></BootTrigger>")) throw new Exception("the startup trigger has no delay: " + xml);
                if (SystemTasks.TaskXml("d", "c", "a", false).Contains("Trigger")) throw new Exception("a one-off task got a trigger");
                var s = SystemTasks.ProfileRemovalScript("S-1-5-21-1-2-3-1001", "OpenSSH Server PN Manager remove test profile o'x");
                foreach (var part in new[] { "-ErrorAction Stop", "if ($p[0].Loaded) { exit 1 }", "Start-Sleep -Seconds 20", "exit 1", "'OpenSSH Server PN Manager remove test profile o''x'" })
                    if (!s.Contains(part)) throw new Exception("the script lacks: " + part);
                return null;
            });
            test("key generator: a failed replacement keeps the old key", () =>
            {
                var p = Path.Combine(tmpDir, "id_old");
                File.WriteAllText(p, "OLD PRIVATE"); File.WriteAllText(p + ".pub", "OLD PUBLIC");
                var broken = new KeyTypeChoice { Label = "broken", Type = "osm-no-such-type", FileName = "x", PublicType = "x" };
                try { KeyGen.GenerateReplacing(broken, p, "c", null, new DateTime(2026, 9, 26, 12, 0, 0)); throw new Exception("a key of a type that does not exist was generated"); }
                catch (Exception ex) when (!ex.Message.StartsWith("a key of a type")) { }
                var left = !File.Exists(p) ? "the private key is gone from " + p : !File.Exists(p + ".pub") ? "the public key is gone" : File.ReadAllText(p) != "OLD PRIVATE" ? "the private key changed" : null;
                if (left != null) throw new Exception(left + " (files: " + string.Join(", ", Directory.GetFiles(tmpDir, "id_old*").Select(Path.GetFileName)) + ")");
                return null;
            });
            test("Set/Get/comment-out semantics", () =>
            {
                var c = new SshdConfig { Lines = new List<string> { "#Port 22", "PasswordAuthentication yes", "Match Group administrators", "  AuthorizedKeysFile x" } };
                c.Set("Port", "2222"); if (c.Get("Port") != "2222" || c.Lines[0] != "Port 2222") throw new Exception("replace commented example failed");
                c.Set("PasswordAuthentication", ""); if (c.Get("PasswordAuthentication") != null || !c.Lines[1].StartsWith("#")) throw new Exception("comment-out failed");
                c.Set("MaxAuthTries", "4"); if (c.Get("MaxAuthTries") != "4" || c.Lines.FindIndex(l => l.StartsWith("Match")) < c.Lines.IndexOf("MaxAuthTries 4")) throw new Exception("insert before Match failed");
                c.SetSubsystem("powershell", "pwsh -sshs"); if (c.GetSubsystem("powershell") != "pwsh -sshs") throw new Exception("subsystem add failed");
                c.SetSubsystem("powershell", null); if (c.GetSubsystem("powershell") != null) throw new Exception("subsystem remove failed");
                return null;
            });
            test("public key parser", () =>
            {
                if (!Keys.LooksLikePublicKey("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGVkMjU1MTlzZWxmdGVzdGtleTAwMDAwMDAwMDAwMDAwMDA comment")) throw new Exception("valid key rejected");
                if (Keys.LooksLikePublicKey("hello world")) throw new Exception("garbage accepted");
                var e = Keys.Parse("from=\"10.0.0.0/8\" ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7 user@host");
                if (e.Type != "ssh-rsa" || e.Options != "from=\"10.0.0.0/8\"" || e.Comment != "user@host") throw new Exception("parse mismatch");
                foreach (var t in new[] { "ssh-mldsa44-ed25519@openssh.com", "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com", "ecdsa-sha2-nistp384", "ssh-ed25519-cert-v01@openssh.com", "ssh-mldsa44-ed25519-cert-v01@openssh.com" })
                {
                    var line = "restrict " + t + " AAAAC3NzaC1lZDI1NTE5AAAAIGVkMjU1MTlzZWxmdGVzdGtleTAwMDAwMDAwMDAwMDAwMDA c";
                    if (!Keys.LooksLikePublicKey(line) || Keys.Parse(line).Type != t) throw new Exception("type " + t + " not recognised");
                }
                if (Keys.Blob("from=\"a\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGVkMjU1MTlzZWxmdGVzdGtleTAwMDAwMDAwMDAwMDAwMDA x") != Keys.Blob("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGVkMjU1MTlzZWxmdGVzdGtleTAwMDAwMDAwMDAwMDAwMDA y")) throw new Exception("blob comparison");
                return null;
            });
            test("firewall port list parser", () =>
            {
                if (!Firewall.Covers("22", 22) || !Firewall.Covers("22,2222", 2222) || !Firewall.Covers(" 2000-3000 ", 2222) || !Firewall.Covers("*", 5)) throw new Exception("covered port reported as blocked");
                if (Firewall.Covers("22", 2222) || Firewall.Covers("22,23", 24) || Firewall.Covers("", 22) || Firewall.Covers(null, 22)) throw new Exception("blocked port reported as covered");
                if (!Firewall.IsSinglePort("22") || Firewall.IsSinglePort("22,2222") || Firewall.IsSinglePort("2000-3000") || Firewall.IsSinglePort("*")) throw new Exception("single-port detection");
                return null;
            });
            test("service ImagePath parser", () =>
            {
                if (Services.ParseImagePath("\"C:\\Program Files\\OpenSSH\\sshd.exe\"") != @"C:\Program Files\OpenSSH\sshd.exe") throw new Exception("quoted path");
                if (Services.ParseImagePath("\"C:\\Program Files\\X Y\\sshd.exe\" -f cfg") != @"C:\Program Files\X Y\sshd.exe") throw new Exception("quoted path with arguments");
                if (Services.ParseImagePath(@"C:\cyg\bin\cygrunsrv.EXE -S") != @"C:\cyg\bin\cygrunsrv.EXE") throw new Exception("unquoted path with arguments");
                if (!string.Equals(Services.ParseImagePath(@"%SystemRoot%\System32\OpenSSH\sshd.exe"), Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), @"System32\OpenSSH\sshd.exe"), StringComparison.OrdinalIgnoreCase)) throw new Exception("environment variable");
                if (Services.ParseImagePath("") != null || Services.ParseImagePath(null) != null) throw new Exception("empty value");
                return null;
            });
            test("command-line quoting", () =>
            {
                var cases = new Dictionary<string, string> { { "plain", "plain" }, { "two words", "\"two words\"" }, { "", "\"\"" }, { @"C:\Program Files\x\", "\"C:\\Program Files\\x\\\\\"" }, { "say \"hi\"", "\"say \\\"hi\\\"\"" }, { @"a\""b", "\"a\\\\\\\"b\"" } };
                foreach (var c in cases) if (Proc.Quote(c.Key) != c.Value) throw new Exception("[" + c.Key + "] -> [" + Proc.Quote(c.Key) + "], expected [" + c.Value + "]");
                return null;
            });
            test("authorized_keys edits keep comments", () =>
            {
                var p = Path.Combine(tmpDir, "authorized_keys_comments");
                File.WriteAllText(p, "# team keys\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGVkMjU1MTlzZWxmdGVzdGtleTAwMDAwMDAwMDAwMDAwMDA a\n\n# end\n");
                var k2 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHNlY29uZGtleXNlbGZ0ZXN0MDAwMDAwMDAwMDAwMDAw b";
                var r = Keys.AddLines(p, new[] { k2, "from=\"x\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGVkMjU1MTlzZWxmdGVzdGtleTAwMDAwMDAwMDAwMDAwMDA dup" }, WindowsIdentity.GetCurrent().User);
                if (r[0] != 1 || r[1] != 1) throw new Exception("added " + r[0] + ", skipped " + r[1]);
                if (Keys.RemoveKey(p, k2, WindowsIdentity.GetCurrent().User) != 1) throw new Exception("remove");
                var text = File.ReadAllText(p);
                if (!text.Contains("# team keys") || !text.Contains("# end") || text.Contains("AAAAIHNlY29uZGtle")) throw new Exception("content: " + text.Replace("\n", " | "));
                return null;
            });
            test("PubkeyAcceptedAlgorithms extension", () =>
            {
                const string a = "ssh-mldsa44-ed25519@openssh.com";
                if (KeyGen.WithAlgorithm(null, a) != "+" + a) throw new Exception("unset");
                if (KeyGen.WithAlgorithm("+ssh-rsa", a) != "+ssh-rsa," + a) throw new Exception("append list");
                if (KeyGen.WithAlgorithm("ssh-ed25519,rsa-sha2-512", a) != "ssh-ed25519,rsa-sha2-512," + a) throw new Exception("explicit list");
                if (KeyGen.WithAlgorithm("+" + a, a) != "+" + a) throw new Exception("already present");
                if (KeyGen.WithAlgorithm("-ssh-rsa", a) != null) throw new Exception("removal list must not be extended");
                return null;
            });
            test("sshd_config rejects line breaks in values", () =>
            {
                var c = new SshdConfig { Path = Path.Combine(tmpDir, "sshd_config_lb") };
                try { c.Set("Banner", "none\nPermitEmptyPasswords yes"); } catch (ConfigException) { return null; }
                throw new Exception("a value with a line break was accepted");
            });
            test("ssh-keygen -l output parser", () =>
            {
                var hk = new HostKey();
                if (!HostKeys.ParseKeygenOutput("256 SHA256:Tt5GhuMPAqbE+8fk0R0XZS1F3Hkg9LNsX8b5B3Mzq0c root@host (MLDSA44-ED25519)\r\n", hk) || hk.Type != "MLDSA44-ED25519" || hk.Bits != "256" || !hk.Fingerprint.StartsWith("SHA256:")) throw new Exception("composite key type not parsed");
                if (!HostKeys.ParseKeygenOutput("3072 SHA256:abc no comment (RSA)", hk) || hk.Type != "RSA") throw new Exception("RSA not parsed");
                return null;
            });
            test("login methods: sshd_config round trip", () =>
            {
                var c = new SshdConfig { Lines = new List<string> { "Port 22", "#PasswordAuthentication yes", "", "Match Group administrators", "       AuthorizedKeysFile x" } };
                var g = new AuthMethods { Password = true, PublicKey = true, RequireBoth = true };
                var rules = new List<AuthRule>
                {
                    new AuthRule { IsGroup = true, Name = "remote desktop users", Methods = new AuthMethods { Password = false, PublicKey = true } },
                    new AuthRule { Name = "contoso\\bob", Methods = new AuthMethods { Password = true, PublicKey = false, Kerberos = true } },
                };
                AuthConfig.Apply(c, g, rules);
                var st = AuthConfig.Read(c);
                if (st.RulesProblem != null) throw new Exception("the written rules section is not readable: " + st.RulesProblem);
                if (!st.Global.SameAs(g) || !st.Global.BothRequired) throw new Exception("methods for all accounts read back as: " + st.Global.Describe());
                if (st.Rules.Count != 2 || !st.Rules[0].SameAs(rules[0]) || !st.Rules[1].SameAs(rules[1])) throw new Exception("rules not read back");
                if (c.Get("KbdInteractiveAuthentication") != "no" || c.Get("AuthenticationMethods") != "publickey,password" || c.Get("PasswordAuthentication") != "yes") throw new Exception("top-level lines");
                if (!c.Lines.Contains("Match Group \"remote desktop users\"") || !c.Lines.Contains("Match User contoso\\bob")) throw new Exception("Match lines");
                int region = c.Lines.IndexOf(AuthConfig.RegionBegin), admins = c.Lines.FindIndex(l => l.StartsWith("Match Group administrators"));
                if (region < 0 || region > admins) throw new Exception("the rules section is not before the existing Match block");
                if (st.OtherMatchSettings.Count != 0) throw new Exception("false report of other Match settings: " + string.Join("; ", st.OtherMatchSettings));
                c.Set("MaxAuthTries", "4");
                if (c.Lines.IndexOf("MaxAuthTries 4") > c.Lines.IndexOf(AuthConfig.RegionBegin)) throw new Exception("a new top-level setting landed in the rules section");
                var once = c.Text; AuthConfig.Apply(c, g, st.Rules);
                if (c.Text != once) throw new Exception("writing the same settings again changed the file");
                AuthConfig.Apply(c, new AuthMethods(), new List<AuthRule>());
                if (c.Text.Contains(AuthConfig.RegionBegin) || c.Lines.Contains("Match all") || c.Get("AuthenticationMethods") != null) throw new Exception("an empty rule list left the section or the requirement behind");
                if (c.Text.Contains("\n\n\n")) throw new Exception("blank lines pile up");
                return null;
            });
            test("login methods: a rules section edited by hand is left alone", () =>
            {
                var lines = new List<string> { "Port 22", AuthConfig.RegionBegin, "Match User bob", "\tPasswordAuthentication no", "\tForceCommand whoami", "Match all", AuthConfig.RegionEnd, "Match Group administrators", "\tPasswordAuthentication no" };
                var c = new SshdConfig { Lines = lines.ToList() };
                var st = AuthConfig.Read(c);
                if (st.RulesProblem == null) throw new Exception("a foreign setting in a rule was not detected");
                if (!st.OtherMatchSettings.Any(s => s.Contains("Match Group administrators"))) throw new Exception("PasswordAuthentication in another Match block not reported");
                AuthConfig.Apply(c, new AuthMethods { Password = false }, null);
                for (int i = 1; i <= 6; i++) if (!c.Lines.Contains(lines[i])) throw new Exception("the section was changed: " + lines[i]);
                if (c.Lines.IndexOf("PasswordAuthentication no") > c.Lines.IndexOf(AuthConfig.RegionBegin)) throw new Exception("the top-level setting landed in the section");
                try { AuthConfig.Apply(c, new AuthMethods(), new List<AuthRule>()); } catch (ConfigException) { return st.RulesProblem; }
                throw new Exception("rules were written over a section edited by hand");
            });
            test("login methods: AuthenticationMethods and offered methods", () =>
            {
                var m = new AuthMethods(); m.SetRequirement("publickey,password");
                if (!m.BothRequired || string.Join(",", m.Offered()) != "publickey" || m.WorksWithoutKey(true)) throw new Exception("both required");
                m.Kerberos = true; m.SetRequirement("gssapi-with-mic publickey,password");
                if (!m.BothRequired || m.Requirement != "publickey,password gssapi-with-mic" || string.Join(",", m.Offered()) != "gssapi-with-mic,publickey" || !m.WorksWithoutKey(true) || m.WorksWithoutKey(false)) throw new Exception("both required, or Kerberos");
                m = new AuthMethods { PublicKey = false }; m.SetRequirement("publickey,password");
                if (m.Custom == null) throw new Exception("a requirement that cannot be met was not kept as written");
                m = new AuthMethods(); m.SetRequirement("password,publickey publickey,keyboard-interactive:bsdauth");
                if (m.Custom == null || string.Join(",", m.Offered()) != "password") throw new Exception("custom lists offer " + string.Join(",", m.Offered()));
                m = new AuthMethods { Password = false }; m.SetRequirement("any");
                if (m.Requirement != "any" || string.Join(",", m.Offered()) != "publickey" || m.WorksWithoutKey(true)) throw new Exception("public key only");
                if (new AuthMethods { PublicKey = false, Kerberos = true }.Describe() != "Windows authentication or Kerberos") throw new Exception("description");
                return null;
            });
            test("sshd_config arguments: quoting as sshd reads it", () =>
            {
                // Checked against sshd -T of OpenSSH for Windows 10.5 (see the server test with random names).
                var quote = new Dictionary<string, string>
                {
                    { "bob", "bob" }, { "contoso\\bob", "contoso\\bob" }, { "o'brien", "\"o'brien\"" }, { "contoso\\'neil", "\"contoso\\\\'neil\"" },
                    { "remote desktop users", "\"remote desktop users\"" }, { "#x", "\"#x\"" }, { "", "\"\"" }, { "a\\", "a\\\\" },{ "a b\\", "\"a b\\\\\"" },
                };
                foreach (var c in quote) if (SshdArgs.Quote(c.Key) != c.Value) throw new Exception("[" + c.Key + "] -> [" + SshdArgs.Quote(c.Key) + "], expected [" + c.Value + "]");
                string err;
                var split = SshdArgs.Split("a 'b c' \"d e\" f\\ g h\\'i # comment", out err);
                if (split == null || string.Join("|", split) != "a|b c|d e|f g|h'i") throw new Exception("split: " + (split == null ? err : string.Join("|", split)));
                if (SshdArgs.Split("o'brien", out err) != null) throw new Exception("an unclosed ' was accepted; sshd rejects it (invalid quotes)");
                return null;
            });
            test("sshd_config arguments: 5000 random names read back unchanged", () =>
            {
                var names = RandomNames(20260926, 5000, false); string err;
                foreach (var n in names)
                {
                    var back = SshdArgs.Split(SshdArgs.Quote(n), out err);
                    if (back == null || back.Count != 1 || back[0] != n) throw new Exception("[" + n + "] written as [" + SshdArgs.Quote(n) + "] reads back as " + (back == null ? err : "[" + string.Join("] [", back) + "]"));
                }
                for (int i = 0; i + 5 <= names.Count; i += 5)
                {
                    var list = names.Skip(i).Take(5).ToList();
                    var back = SshdArgs.Split(SshdArgs.Join(list), out err);
                    if (back == null || !back.SequenceEqual(list)) throw new Exception("list [" + string.Join("] [", list) + "] written as " + SshdArgs.Join(list));
                    var typed = SshdArgs.FormatTyped(list);
                    if (typed != null) { var t = SshdArgs.ParseTyped(typed, out err); if (t == null || !t.SequenceEqual(list)) throw new Exception("typed list [" + typed + "] reads back differently"); }
                }
                return names.Count + " names";
            });
            test("Allow/Deny fields: typed lists", () =>
            {
                string err;
                var l = SshdArgs.ParseTyped("administrators  \"openssh users\" o'brien contoso\\bob", out err);
                if (l == null || string.Join("|", l) != "administrators|openssh users|o'brien|contoso\\bob") throw new Exception("parsed as " + (l == null ? err : string.Join("|", l)));
                if (SshdArgs.Join(l) != "administrators \"openssh users\" \"o'brien\" contoso\\bob") throw new Exception("written as " + SshdArgs.Join(l));
                if (SshdArgs.FormatTyped(l) != "administrators \"openssh users\" o'brien contoso\\bob") throw new Exception("shown as " + SshdArgs.FormatTyped(l));
                if (SshdArgs.ParseTyped("\"openssh users", out err) != null) throw new Exception("an unclosed quotation mark was accepted");
                return null;
            });
            test("login methods: rule names with ' and \\ read back", () =>
            {
                var names = new[] { "o'brien", "contoso\\'neil", "contoso\\bob", "o'brien smith" };
                var c = new SshdConfig { Lines = new List<string> { "Port 22", "Match Group administrators", "\tAuthorizedKeysFile x" } };
                AuthConfig.Apply(c, new AuthMethods(), names.Select(n => new AuthRule { Name = n, Methods = new AuthMethods { Password = false } }).ToList());
                if (!c.Lines.Contains("Match User \"o'brien\"") || !c.Lines.Contains("Match User contoso\\bob")) throw new Exception("Match lines: " + string.Join(" | ", c.Lines.Where(x => x.StartsWith("Match"))));
                var st = AuthConfig.Read(c);
                if (st.RulesProblem != null || !st.Rules.Select(r => r.Name).SequenceEqual(names)) throw new Exception("names read back as " + (st.RulesProblem ?? string.Join(" | ", st.Rules.Select(r => r.Name))));
                var once = c.Text; AuthConfig.Apply(c, new AuthMethods(), st.Rules);
                if (c.Text != once) throw new Exception("writing the same rules again changed the file");
                return null;
            });
            test("restart needed after saving sshd_config", () =>
            {
                var start = new DateTime(2026, 9, 26, 10, 0, 0, DateTimeKind.Utc);
                if (Services.RestartNeeded(start, start.AddMilliseconds(-500)) || Services.RestartNeeded(start, start.AddMilliseconds(900))) throw new Exception("a file saved before the start was reported");
                if (!Services.RestartNeeded(start, start.AddMinutes(5))) throw new Exception("a file saved after the start was not reported");
                return null;
            });
            UnitSince16(test, tmpDir);
        }

        /// <summary>Unit tests of what manager 1.6.0 added or fixed.</summary>
        private static void UnitSince16(Action<string, Func<string>> test, string tmpDir)
        {
            test("sshd_config: a comment after a value is not part of it, and survives a Set", () =>
            {
                var c = new SshdConfig { Lines = new List<string> { "MaxAuthTries 4 # company policy", "Banner C:\\notes\\a#b.txt", "AllowUsers \"x #y\" z #end" } };
                if (c.Get("MaxAuthTries") != "4") throw new Exception("MaxAuthTries read as [" + c.Get("MaxAuthTries") + "]");
                if (c.Get("Banner") != "C:\\notes\\a#b.txt") throw new Exception("a # inside an argument was cut: " + c.Get("Banner"));
                if (c.Get("AllowUsers") != "\"x #y\" z") throw new Exception("quoted # or the comment: " + c.Get("AllowUsers"));
                c.Set("MaxAuthTries", "3");
                if (c.Lines[0] != "MaxAuthTries 3 # company policy") throw new Exception("the comment was lost: " + c.Lines[0]);
                return null;
            });
            test("sshd_config: commented examples, not prose, are replaced", () =>
            {
                var c = new SshdConfig { Lines = new List<string> { "# Port forwarding is used by the tunnels", "#Port 22", "Match all" } };
                c.Set("Port", "2222");
                if (c.Lines[0] != "# Port forwarding is used by the tunnels" || c.Lines[1] != "Port 2222") throw new Exception(string.Join(" | ", c.Lines));
                var d = new SshdConfig { Lines = new List<string> { "# Port forwarding", "Match all" } };
                d.Set("Port", "2222");
                if (d.Lines[0] != "# Port forwarding" || d.Lines.IndexOf("Port 2222") != 1) throw new Exception(string.Join(" | ", d.Lines));
                return null;
            });
            test("sshd_config: SetFirst keeps the other Port and ListenAddress lines, Set keeps one", () =>
            {
                var c = new SshdConfig { Lines = new List<string> { "Port 22", "Port 2222", "ListenAddress 10.0.0.1", "ListenAddress ::1" } };
                c.SetFirst("Port", "2200");
                if (!c.Lines.SequenceEqual(new[] { "Port 2200", "Port 2222", "ListenAddress 10.0.0.1", "ListenAddress ::1" })) throw new Exception(string.Join(" | ", c.Lines));
                c.SetFirst("ListenAddress", "");
                if (c.Lines[2] != "#ListenAddress 10.0.0.1" || c.Lines[3] != "ListenAddress ::1") throw new Exception(string.Join(" | ", c.Lines));
                c.Set("Port", "22");
                if (c.Lines[0] != "Port 22" || c.Lines[1] != "#Port 2222") throw new Exception(string.Join(" | ", c.Lines));
                return null;
            });
            test("sshd_config: Allow and Deny lines add up", () =>
            {
                var c = new SshdConfig { Lines = new List<string> { "AllowUsers alice bob", "AllowGroups administrators", "AllowUsers \"o'brien\"", "Match User x", "AllowUsers y" } };
                string err; var all = c.GetCombinedArgs("AllowUsers", out err);
                if (all == null || !all.SequenceEqual(new[] { "alice", "bob", "o'brien" })) throw new Exception(all == null ? err : string.Join(",", all));
                c.Set("AllowUsers", SshdArgs.Join(all.Concat(new[] { "carol" })));
                if (c.Lines[0] != "AllowUsers alice bob \"o'brien\" carol" || !c.Lines[2].StartsWith("#")) throw new Exception(string.Join(" | ", c.Lines));
                if (!SshdConfig.CumulativeKeywords.Contains("DenyGroups")) throw new Exception("DenyGroups is cumulative in sshd");
                return null;
            });
            test("sshd_config: the port of ListenAddress (IPv6 without a port has none)", () =>
            {
                var cases = new Dictionary<string, int> { { "::1", 0 }, { "fe80::1", 0 }, { "[::1]:2222", 2222 }, { "0.0.0.0:2200", 2200 }, { "10.0.0.1", 0 }, { "host.example:2022", 2022 }, { "[fe80::1%3]:22 rdomain x", 22 }, { "0.0.0.0:99999", 0 } };
                foreach (var kv in cases) if (SshdConfig.ListenPort(kv.Key) != kv.Value) throw new Exception(kv.Key + " -> " + SshdConfig.ListenPort(kv.Key) + ", expected " + kv.Value);
                var c = new SshdConfig { Lines = new List<string> { "ListenAddress ::1" } };
                if (c.EffectivePort != 22) throw new Exception("ListenAddress ::1 gave port " + c.EffectivePort);
                c = new SshdConfig { Lines = new List<string> { "ListenAddress [::1]:2222" } };
                if (c.EffectivePort != 2222) throw new Exception("ListenAddress [::1]:2222 gave port " + c.EffectivePort);
                return null;
            });
            test("sshd_config: new settings go before the first Include", () =>
            {
                var c = new SshdConfig { Lines = new List<string> { "Include C:/ProgramData/ssh/sshd_config.d/*.conf", "Port 22", "Match Group administrators", "\tX y" } };
                c.Set("MaxAuthTries", "4");
                if (c.Lines[0] != "MaxAuthTries 4") throw new Exception(string.Join(" | ", c.Lines));
                if (c.Includes().Count != 1) throw new Exception("Include not found");
                return null;
            });
            test("sshd_config: a commented example below an Include is not used", () =>
            {
                var c = new SshdConfig { Lines = new List<string> { "Include C:/x/*.conf", "#PasswordAuthentication yes", "Match all" } };
                c.Set("PasswordAuthentication", "no");
                if (c.Lines[0] != "PasswordAuthentication no" || c.Lines[2] != "#PasswordAuthentication yes") throw new Exception(string.Join(" | ", c.Lines));
                return null;
            });
            test("the ports sshd listens on (Port and ListenAddress together)", () =>
            {
                Func<string[], string> ports = lines => string.Join(",", MainForm.ExpectedPorts(new SshdConfig { Lines = lines.ToList() }));
                if (ports(new string[0]) != "22") throw new Exception("defaults");
                if (ports(new[] { "Port 22", "Port 2222" }) != "22,2222") throw new Exception("two Port lines");
                if (ports(new[] { "Port 22", "ListenAddress 10.0.0.1:2200" }) != "2200") throw new Exception("every ListenAddress has its port: Port is not used, got " + ports(new[] { "Port 22", "ListenAddress 10.0.0.1:2200" }));
                if (ports(new[] { "Port 2222", "ListenAddress 10.0.0.1", "ListenAddress [::1]:2200" }) != "2222,2200") throw new Exception("mixed");
                return null;
            });
            test("Allow and Deny patterns as sshd for Windows keeps them", () =>
            {
                if (AuthConfig.NormalisePattern("CORP/Alice") != "corp\\alice" || AuthConfig.NormalisePattern("Admins*") != "admins*") throw new Exception(AuthConfig.NormalisePattern("CORP/Alice"));
                if (Export.Neutralise("\t=1+1") != "'\t=1+1" || Export.Neutralise("\r@x") != "'\r@x" || Export.Neutralise("-2") != "-2" || Export.Neutralise("ok") != "ok") throw new Exception("export cells");
                return null;
            });
            test("sshd_config: backups get unique names, are listed newest first and pruned", () =>
            {
                var dir = Path.Combine(tmpDir, "backups"); Directory.CreateDirectory(dir);
                var p = Path.Combine(dir, "sshd_config"); File.WriteAllText(p, "Port 22\n");
                var t = new DateTime(2026, 9, 26, 12, 0, 0);
                var b1 = SshdConfig.NewBackupPath(p, t); File.WriteAllText(b1, "1");
                var b2 = SshdConfig.NewBackupPath(p, t); File.WriteAllText(b2, "2");
                var b3 = SshdConfig.NewBackupPath(p, t.AddSeconds(1)); File.WriteAllText(b3, "3");
                File.WriteAllText(p + ".bak.notes.txt", "not a backup");
                if (b1 == b2 || !b2.EndsWith("-2")) throw new Exception("two saves in the same second: " + b1 + ", " + b2);
                var list = SshdConfig.ListBackups(p).Select(Path.GetFileName).ToList();
                if (!list.SequenceEqual(new[] { b3, b2, b1 }.Select(Path.GetFileName))) throw new Exception("order: " + string.Join(", ", list));
                if (SshdConfig.PruneBackups(p, 1) != 2 || File.Exists(b1) || File.Exists(b2) || !File.Exists(b3) || !File.Exists(p + ".bak.notes.txt")) throw new Exception("pruning");
                return null;
            });
            test("sshd_config: ReplaceFile keeps the permissions of the file it replaces", () =>
            {
                var p = Path.Combine(tmpDir, "acl_config"); File.WriteAllText(p, "old\n");
                var fs = File.GetAccessControl(p);
                var everyone = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
                fs.AddAccessRule(new FileSystemAccessRule(everyone, FileSystemRights.ReadData, AccessControlType.Allow)); File.SetAccessControl(p, fs);
                SshdConfig.WriteReplacing(p, "new\n");
                if (File.ReadAllText(p) != "new\n") throw new Exception("content not written");
                if (!File.GetAccessControl(p).GetAccessRules(true, false, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().Any(r => (SecurityIdentifier)r.IdentityReference == everyone)) throw new Exception("the explicit permission of the replaced file was lost");
                if (Directory.GetFiles(tmpDir, "acl_config.new-*").Length > 0) throw new Exception("a temporary file was left behind");
                return null;
            });
            test("sshd_config: a file changed on disk after it was read is detected", () =>
            {
                var p = Path.Combine(tmpDir, "changed_config"); File.WriteAllText(p, "Port 22\n");
                var c = SshdConfig.Load(p);
                if (c.LoadedHash != SshdConfig.FileHash(p) || c.LoadedHash.Length != 64) throw new Exception("hash at load: " + c.LoadedHash);
                if (c.Copy().LoadedHash != c.LoadedHash) throw new Exception("a copy lost the hash");
                File.WriteAllText(p, "Port 2222\n");
                if (SshdConfig.FileHash(p) == c.LoadedHash) throw new Exception("the change was not seen");
                if (SshdConfig.FileHash(Path.Combine(tmpDir, "no-such-file")) != "") throw new Exception("a missing file must hash to empty");
                return null;
            });
            test("line differences", () =>
            {
                var a = new List<string> { "a", "b", "c", "d", "e" }; var b = new List<string> { "a", "B", "c", "d", "e", "f" };
                var d = Diff.Lines(a, b);
                var s = string.Join("", d.Select(x => x.Kind + x.Text));
                if (s != " a-b+B c d e+f") throw new Exception(s);
                if (Diff.Changed(d, '+') != 2 || Diff.Changed(d, '-') != 1) throw new Exception("counts");
                var ctx = Diff.WithContext(Diff.Lines(Enumerable.Range(0, 40).Select(i => "l" + i).ToList(), Enumerable.Range(0, 40).Select(i => i == 20 ? "X" : "l" + i).ToList()), 2);
                if (ctx.Count != 1 + 2 + 2 + 2 + 1 || ctx.First().Kind != '@' || ctx.Last().Kind != '@') throw new Exception("context: " + Diff.Format(ctx).Replace("\r\n", "|"));
                if (Diff.Lines(new List<string>(), new List<string> { "x" }).Single().Kind != '+') throw new Exception("empty old text");
                return null;
            });
            test("access check: DenyUsers, AllowUsers, DenyGroups, AllowGroups as sshd decides", () =>
            {
                // alice is in the local group administrators and the domain group corp\sshusers ("sshusers" resolves to it by SID).
                var names = new List<string> { "administrators", "corp\\sshusers" };
                Func<List<string>, bool> admins = list => AuthConfig.GaMatch(list, () => names, p => p == "administrators" || p == "sshusers" || p == "corp\\sshusers");
                var none = new List<string>();
                if (AuthConfig.AccessRefusal("alice", none, none, none, none, admins) != null) throw new Exception("no lists refused");
                if (AuthConfig.AccessRefusal("alice", new List<string> { "al*" }, none, none, none, admins) == null) throw new Exception("DenyUsers al* did not refuse alice");
                if (AuthConfig.AccessRefusal("alice", none, new List<string> { "bob", "carol" }, none, none, admins) == null) throw new Exception("AllowUsers without alice did not refuse");
                if (AuthConfig.AccessRefusal("alice", none, new List<string> { "alice@10.0.0.*" }, none, none, admins) != null) throw new Exception("user@host counts as matching (the host is not known here)");
                if (AuthConfig.AccessRefusal("alice", none, new List<string> { "Alice" }, none, none, admins) != null) throw new Exception("sshd for Windows lower-cases the lists (servconf.c), so Alice must match alice");
                if (AuthConfig.AccessRefusal("corp\\alice", none, new List<string> { "CORP/alice" }, none, none, admins) != null) throw new Exception("DOMAIN/name must match domain\\name");
                if (AuthConfig.AccessRefusal("alice", none, none, new List<string> { "admin*" }, none, admins) == null) throw new Exception("DenyGroups admin* did not refuse an administrator");
                if (AuthConfig.AccessRefusal("alice", none, none, none, new List<string> { "openssh users" }, admins) == null) throw new Exception("AllowGroups without a group of alice did not refuse");
                if (AuthConfig.AccessRefusal("alice", none, none, none, new List<string> { "openssh users", "administrators" }, admins) != null) throw new Exception("AllowGroups with administrators refused an administrator");
                // ga_match: one pattern with a wildcard makes sshd compare every entry by name, so "sshusers" no longer
                // matches the domain group corp\sshusers.
                if (AuthConfig.AccessRefusal("alice", none, none, none, new List<string> { "sshusers" }, admins) != null) throw new Exception("a group found by its SID refused");
                if (AuthConfig.AccessRefusal("alice", none, none, none, new List<string> { "sshusers", "ops-*" }, admins) == null) throw new Exception("with a wildcard in the list, sshusers must be compared by name and fail as sshd does");
                foreach (var g in new[] { new[] { "abc", "a?c", "1" }, new[] { "abc", "a*", "1" }, new[] { "abc", "*c", "1" }, new[] { "abc", "a*d", "0" }, new[] { "", "*", "1" }, new[] { "ab", "a", "0" }, new[] { "a*b", "a*b", "1" } })
                    if (AuthConfig.Glob(g[0], g[1]) != (g[2] == "1")) throw new Exception("Glob(" + g[0] + ", " + g[1] + ")");
                return null;
            });
            test("failed logins: the client address of sshd's messages", () =>
            {
                var cases = new Dictionary<string, string>
                {
                    { "sshd: Failed password for alice from 192.0.2.10 port 50123 ssh2", "192.0.2.10|alice" },
                    { "sshd: Failed password for invalid user admin from 2001:db8::5 port 22 ssh2", "2001:db8::5|admin" },
                    { "sshd: Invalid user oracle from 198.51.100.7 port 4444", "198.51.100.7|oracle" },
                    { "sshd: Connection closed by authenticating user bob 203.0.113.9 port 61000 [preauth]", "203.0.113.9|bob" },
                    { "sshd: Disconnected from invalid user test 203.0.113.10 port 61001 [preauth]", "203.0.113.10|test" },
                    { "sshd: error: maximum authentication attempts exceeded for root from 192.0.2.11 port 1 ssh2 [preauth]", "192.0.2.11|root" },
                    { "sshd: Timeout before authentication for 192.0.2.12 port 2", "192.0.2.12|" },
                    { "sshd: Failed password for alice from ::ffff:192.0.2.13 port 3 ssh2", "192.0.2.13|alice" },
                    // A user name chosen to put an innocent address first: the real one is the last.
                    { "sshd: Invalid user x from 10.1.2.3 port 22 from 203.0.113.5 port 5555", "203.0.113.5|x from 10.1.2.3 port 22" },
                    { "sshd: Failed password for invalid user x from 10.1.2.3 port 22 from 203.0.113.6 port 1 ssh2", "203.0.113.6|x from 10.1.2.3 port 22" },
                    { "sshd: Accepted publickey for alice from 192.0.2.14 port 4 ssh2: ED25519 SHA256:x", null },
                    { "sshd: Server listening on 0.0.0.0 port 22.", null },
                };
                foreach (var kv in cases)
                {
                    string user; var a = EventLogs.FailedLoginAddress(kv.Key, out user);
                    var got = a == null ? null : a + "|" + (user ?? "");
                    if (got != kv.Value) throw new Exception("[" + kv.Key + "] -> " + (got ?? "null") + ", expected " + (kv.Value ?? "null"));
                }
                var t = new DateTime(2026, 9, 26, 12, 0, 0);
                var by = EventLogs.FailedByAddress(cases.Keys.Select((m, i) => new LogEvent { Time = t.AddMinutes(i), Message = m }).Concat(new[] { new LogEvent { Time = t.AddHours(1), Message = "sshd: Failed password for carol from 192.0.2.10 port 9 ssh2" } }));
                if (by[0].Address != "192.0.2.10" || by[0].Count != 2 || by[0].Users.Count != 2 || by[0].Last != t.AddHours(1)) throw new Exception("grouping: " + by[0].Address + " " + by[0].Count);
                return by.Count + " addresses";
            });
            test("firewall block list: addresses as Windows stores them, and addresses never blocked", () =>
            {
                if (Firewall.NormaliseAddress("192.0.2.1/255.255.255.255") != "192.0.2.1" || Firewall.NormaliseAddress("2001:db8::1/128") != "2001:db8::1" || Firewall.NormaliseAddress("10.0.0.0/255.0.0.0") != "10.0.0.0/255.0.0.0") throw new Exception("normalising");
                if (Firewall.NotBlockable("127.0.0.1") == null || Firewall.NotBlockable("::1") == null || Firewall.NotBlockable("nonsense") == null) throw new Exception("loopback or garbage accepted");
                if (Firewall.NotBlockable("192.0.2.200") != null) throw new Exception("a documentation address was refused");
                return null;
            });
            test("list sorting: numbers, dates and text", () =>
            {
                if (ListSorter.CompareText("9", "10") >= 0 || ListSorter.CompareText("2026-09-26 10:00:00", "2026-09-26 09:00:00") <= 0 || ListSorter.CompareText("b", "A") <= 0) throw new Exception("order");
                return null;
            });
            test("export: CSV quoting and formula cells, HTML encoding", () =>
            {
                var csv = Export.Csv(new[] { "a", "b" }, new[] { (IList<string>)new[] { "x,y", "=cmd|' /c calc'!A0" }, new[] { "-5", "say \"hi\"" } });
                if (!csv.Contains("\"x,y\"") || !csv.Contains("\"'=cmd|' /c calc'!A0\"") || !csv.Contains("\"-5\"") || !csv.Contains("\"say \"\"hi\"\"\"")) throw new Exception(csv);
                var html = Export.Html("T <1>", "i & j", new[] { "c" }, new[] { (IList<string>)new[] { "<script>" } });
                if (html.Contains("<script>") || !html.Contains("&lt;script&gt;") || !html.Contains("T &lt;1&gt;")) throw new Exception("HTML not encoded");
                return null;
            });
            test("ssh client: known_hosts and config parsing, host editing keeps other lines", () =>
            {
                var k = SshClient.ParseKnownHost("@cert-authority *.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGVkMjU1MTlzZWxmdGVzdGtleTAwMDAwMDAwMDAwMDAwMDA ca");
                if (k == null || k.Marker != "@cert-authority" || k.Hosts != "*.example.com" || k.Type != "ssh-ed25519") throw new Exception("marker line");
                if (!SshClient.ParseKnownHost("|1|abc=|def= ssh-rsa AAAA").Hashed || SshClient.ParseKnownHost("# comment") != null || SshClient.ParseKnownHost("host ssh-rsa") != null) throw new Exception("hashed, comment or short line");
                var lines = new List<string> { "# my hosts", "Host web", "    HostName web.example.com", "    User alice", "    ForwardAgent no", "", "Host *", "    ServerAliveInterval 60" };
                var hosts = SshClient.ParseConfig(lines);
                if (hosts.Count != 2 || hosts[0].Pattern != "web" || hosts[0].Get("User") != "alice" || hosts[0].First != 1 || hosts[0].Last != 4) throw new Exception("parse: " + string.Join(";", hosts.Select(h => h.Pattern + " " + h.First + "-" + h.Last)));
                var edited = SshClient.WithHost(lines, hosts[0], "web", new Dictionary<string, string> { { "HostName", "web2.example.com" }, { "User", "" }, { "Port", "2222" }, { "IdentityFile", "C:\\Users\\Jane Doe\\.ssh\\id_ed25519" } });
                var e = string.Join("|", edited);
                if (!e.Contains("Host web|    HostName web2.example.com|    Port 2222|    IdentityFile \"C:\\Users\\Jane Doe\\.ssh\\id_ed25519\"|    ForwardAgent no|") || e.Contains("User alice") || !e.StartsWith("# my hosts|")) throw new Exception(e);
                var added = SshClient.WithHost(lines, null, "db", new Dictionary<string, string> { { "HostName", "10.0.0.5" } });
                if (added.IndexOf("Host db") >= added.IndexOf("Host *") || added[added.IndexOf("Host db") + 1] != "    HostName 10.0.0.5") throw new Exception("add: " + string.Join("|", added));
                var removed = SshClient.WithoutHost(lines, hosts[0]);
                if (string.Join("|", removed) != "# my hosts||Host *|    ServerAliveInterval 60") throw new Exception("remove: " + string.Join("|", removed));
                try { SshClient.WithHost(lines, null, "x", new Dictionary<string, string> { { "User", "a\nProxyCommand evil" } }); throw new Exception("a line break was accepted"); } catch (ConfigException) { }
                if (SshClient.CheckHostName("-oProxyCommand=x") != null || SshClient.CheckHostName("a b") != null || SshClient.CheckHostName("[::1]") == null || SshClient.CheckHostName("host.example.com") == null) throw new Exception("host names");
                return null;
            });
            test("find in the sshd_config text", () =>
            {
                var t = "Port 22\nport 2222\nMatch all";
                if (MainForm.FindIn(t, "PORT", 0, true) != 0 || MainForm.FindIn(t, "port", 1, true) != 8 || MainForm.FindIn(t, "port", 9, true) != 0) throw new Exception("forward");
                if (MainForm.FindIn(t, "port", 7, false) != 0 || MainForm.FindIn(t, "port", -1, false) != 8 || MainForm.FindIn(t, "none", 0, true) != -1) throw new Exception("backward or missing");
                return null;
            });
            test("hardening fixes: each writes the recommended value", () =>
            {
                var c = new SshdConfig { Lines = new List<string> { "PerSourcePenalties no", "Ciphers aes128-cbc,aes256-ctr", "Match all" } };
                foreach (var name in new[] { "Keyboard-interactive", "Empty passwords", "MaxAuthTries", "Per-source penalties", "MaxStartups throttling", "Idle session timeout", "Login grace time", "Minimum RSA key size", "Log level", "Ciphers" })
                {
                    var fix = MainForm.ConfigFix(name); if (fix == null) throw new Exception("no fix for " + name); fix(c);
                }
                if (c.Get("KbdInteractiveAuthentication") != "no" || c.Get("MaxAuthTries") != "4" || c.Get("PerSourcePenalties") != null || c.Get("Ciphers") != null || c.Get("ClientAliveInterval") != "300" || c.Get("LogLevel") != "VERBOSE") throw new Exception(string.Join(" | ", c.Lines));
                if (MainForm.ConfigFix("Password authentication") != null || MainForm.ConfigFix("Login restriction") != null) throw new Exception("login methods and restrictions must never be changed automatically");
                return null;
            });
            test("themes: dark, light and high contrast palettes", () =>
            {
                var dark = Theme.Make(true, false); var light = Theme.Make(false, false); var hc = Theme.Make(true, true);
                if (!dark.Dark || light.Dark || hc.Dark || !hc.HighContrast) throw new Exception("flags");
                if (dark.Back.GetBrightness() > 0.3f || light.Surface != SystemColors.Window) throw new Exception("colours");
                if (dark.Semantic.Length != light.Semantic.Length) throw new Exception("the semantic colours must correspond one to one");
                return null;
            });
            test("preferences stay in memory in the unattended modes", () =>
            {
                if (!Program.Unattended) throw new Exception("not unattended");
                var old = Prefs.ConfirmSeconds; Prefs.ConfirmSeconds = 5;
                if (Prefs.ConfirmSeconds != 15) throw new Exception("the lower bound (15 s) was not applied: " + Prefs.ConfirmSeconds);
                Prefs.ConfirmSeconds = old;
                return null;
            });
            test("setup wizard: the plan in words", () =>
            {
                var p = new WizardPlan { Port = 2222, Profiles = 3, Login = WizardLogin.AdministratorsKeyOnly, Recommended = true, AllowGroups = "administrators" };
                var l = p.Describe(22, 3, true);
                if (l.Count != 5 || !l[0].Contains("2222") || !l[2].StartsWith("Administrators")) throw new Exception(string.Join(" / ", l));
                if (new WizardPlan { Port = 22, Profiles = 3 }.Describe(22, 3, true).Count != 0) throw new Exception("no change described as a change");
                return null;
            });
            UnitSince20(test);
            UnitSince21(test, tmpDir);
            UnitSince22(test, tmpDir);
        }

        /// <summary>The configuration of a default installation, with the rules section of the Authentication tab when auth is given.</summary>
        private static SshdConfig DefaultLike(string authBegin = null)
        {
            var l = new List<string> { "#Port 22", "AuthorizedKeysFile\t.ssh/authorized_keys", "", "# override default of no subsystems", "Subsystem\tsftp\tsftp-server.exe", "" };
            if (authBegin != null) l.AddRange(new[] { authBegin, AuthConfig.RegionNote, "Match User alice", "\tPasswordAuthentication no", "\tPubkeyAuthentication yes", "\tGSSAPIAuthentication no", "\tAuthenticationMethods any", "Match all", AuthConfig.RegionEnd, "" });
            l.AddRange(new[] { "Match Group administrators", "       AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys" });
            return new SshdConfig { Lines = l };
        }

        /// <summary>Unit tests of what manager 2.0.0 added: SFTP, the new name, session activity.</summary>
        private static void UnitSince20(Action<string, Func<string>> test)
        {
            test("SFTP: transfer logging on and off keeps the program and its other options", () =>
            {
                var cases = new[]
                {
                    new[] { "sftp-server.exe", "on", "sftp-server.exe -l INFO" },
                    new[] { "sftp-server.exe -l INFO", "off", "sftp-server.exe" },
                    new[] { "sftp-server.exe -f LOCAL0 -lVERBOSE", "on", "sftp-server.exe -f LOCAL0 -lVERBOSE" },
                    new[] { "sftp-server.exe -f LOCAL0 -lVERBOSE", "off", "sftp-server.exe -f LOCAL0" },
                    new[] { "\"C:/Program Files/OpenSSH/sftp-server.exe\" -l ERROR", "on", "\"C:/Program Files/OpenSSH/sftp-server.exe\" -l INFO" },
                    new[] { "internal-sftp", "on", "internal-sftp -l INFO" },
                };
                foreach (var c in cases)
                {
                    var got = SftpConfig.WithLogging(c[0], c[1] == "on");
                    if (got != c[2]) throw new Exception("[" + c[0] + "] " + c[1] + ": [" + got + "], expected [" + c[2] + "]");
                    if (SftpConfig.LogsTransfers(got) != (c[1] == "on")) throw new Exception("[" + got + "] is not read back as logging " + c[1]);
                }
                if (SftpConfig.LogsTransfers("sftp-server.exe -l ERROR") || SftpConfig.LogsTransfers("sftp-server.exe") || !SftpConfig.LogsTransfers("sftp-server.exe -l debug3")) throw new Exception("log levels misread");
                return null;
            });
            test("SFTP: SFTP-only rules are written, read back, and put before the other Match blocks", () =>
            {
                var c = DefaultLike();
                var rules = new List<SftpRule>
                {
                    new SftpRule { Name = "alice", Folder = "C:\\SFTP\\%u" },
                    new SftpRule { IsGroup = true, Name = "sftp users", Folder = "D:\\Shared Files\\in", ReadOnly = true },
                    new SftpRule { Name = "contoso\\bob" },
                };
                SftpConfig.Apply(c, true, true, rules);
                var st = SftpConfig.Read(c);
                if (st.RulesProblem != null) throw new Exception("the section as written is not readable: " + st.RulesProblem);
                if (st.Rules.Count != 3 || st.Rules.Where((r, i) => !r.SameAs(rules[i])).Any()) throw new Exception("read back: " + string.Join("; ", st.Rules.Select(r => r.Kind + " " + r.Name + " " + r.Describe())));
                if (st.Subsystem != "sftp-server.exe -l INFO" || !st.LogTransfers) throw new Exception("subsystem " + st.Subsystem);
                int begin = c.Lines.IndexOf(SftpConfig.RegionBegin), admins = c.Lines.FindIndex(l => l.StartsWith("Match Group administrators"));
                if (begin < 0 || admins < begin) throw new Exception("the section is not before the other Match blocks");
                foreach (var want in new[] { "Match Group \"sftp users\"", "\tForceCommand internal-sftp -l INFO -R", "\tChrootDirectory \"D:\\Shared Files\\in\"", "\tChrootDirectory C:\\SFTP\\%u", "\tForceCommand internal-sftp -l INFO", "\tChrootDirectory none", "\tAllowStreamLocalForwarding no", "Match all" })
                    if (!c.Lines.Contains(want)) throw new Exception("missing line [" + want + "]:\n" + c.Text);
                var once = c.Text;
                SftpConfig.Apply(c, true, true, rules);
                if (c.Text != once) throw new Exception("applying the same settings again changed the file");
                c.Set("MaxAuthTries", "4");
                if (c.Lines.IndexOf("MaxAuthTries 4") > c.Lines.IndexOf(SftpConfig.RegionBegin) || SftpConfig.Read(c).RulesProblem != null) throw new Exception("a new top-level setting landed in the section");
                SftpConfig.Apply(c, true, false, new List<SftpRule>());
                if (c.Text.Contains(SftpConfig.RegionBegin) || c.Lines.Contains("Match all") || c.GetSubsystem("sftp") != "sftp-server.exe") throw new Exception("no rules and no logging left something behind:\n" + c.Text);
                return null;
            });
            test("SFTP: a section edited by hand is left alone, SFTP off with SFTP-only accounts is refused", () =>
            {
                var c = DefaultLike();
                SftpConfig.Apply(c, true, false, new List<SftpRule> { new SftpRule { Name = "alice", Folder = "C:\\SFTP\\%u" } });
                // Each edit replaces a line the tab wrote (old != null) or adds one before "Match all".
                var edits = new[] { new[] { "\tAllowTcpForwarding no", "\tAllowTcpForwarding yes" }, new[] { "\tForceCommand internal-sftp", "\tForceCommand internal-sftp -d /in" }, new[] { null, "\tPasswordAuthentication no" }, new[] { "Match User alice", "Match User alice,bob" } };
                foreach (var e in edits)
                {
                    var h = c.Copy(); var edit = e[1];
                    if (e[0] != null) h.Lines[h.Lines.IndexOf(e[0])] = edit; else h.Lines.Insert(h.Lines.IndexOf("Match all"), edit);
                    var st = SftpConfig.Read(h);
                    if (st.RulesProblem == null) throw new Exception("[" + edit.Trim() + "] was not noticed");
                    var before = h.Text;
                    try { SftpConfig.Apply(h, true, false, new List<SftpRule>()); throw new Exception("rules were written over a section edited by hand"); }
                    catch (ConfigException) { }
                    try { SftpConfig.Apply(h.Copy(), false, false, null); throw new Exception("SFTP was switched off under a hand-edited section of SFTP-only accounts"); }
                    catch (ConfigException) { }
                    SftpConfig.Apply(h, true, true, null); // the subsystem alone can still change
                    if (!h.Lines.Contains(edit) || h.GetSubsystem("sftp") != "sftp-server.exe -l INFO") throw new Exception("the hand-edited section or the subsystem: " + h.Text);
                }
                try { SftpConfig.Apply(c.Copy(), false, false, SftpConfig.Read(c).Rules); throw new Exception("SFTP was switched off with SFTP-only accounts"); }
                catch (ConfigException) { }
                var off = c.Copy(); SftpConfig.Apply(off, false, false, new List<SftpRule>());
                if (off.GetSubsystem("sftp") != null || SftpConfig.Read(off).Enabled) throw new Exception("SFTP off left the subsystem");
                if (SftpConfig.Read(DefaultLike()).OtherMatchSettings.Count != 0) throw new Exception("the default configuration was reported to force a command");
                var other = DefaultLike(); other.Lines.Add("Match User carol"); other.Lines.Add("\tForceCommand internal-sftp");
                if (SftpConfig.Read(other).OtherMatchSettings.Count != 1) throw new Exception("a ForceCommand in another Match block was not reported");
                return null;
            });
            test("SFTP: folders with a drive letter, %u and %h as sshd works them out", () =>
            {
                foreach (var bad in new[] { "", "SFTP\\%u", "\\\\server\\share\\%u", "C:SFTP", "C:\\SFTP\\%x", "C:\\a\"b", " C:\\SFTP", "C:\\a*b", "C:\\a:b", "C:\\%h\\x", "%hx", "%h\\a\\%h" })
                    if (SftpConfig.FolderError(bad) == null) throw new Exception("accepted [" + bad + "]");
                foreach (var good in new[] { "C:\\SFTP\\%u", "d:/data/%u/in", "E:\\Shared Files", "%h\\sftp", "%h", "C:\\100%%" })
                    if (SftpConfig.FolderError(good) != null) throw new Exception("refused [" + good + "]: " + SftpConfig.FolderError(good));
                var cases = new[] { new[] { "C:\\SFTP\\%u", "contoso\\bob", "C:\\SFTP\\contoso\\bob" }, new[] { "C:/x/%%/%u", "bob", "C:\\x\\%\\bob" }, new[] { "%h\\sftp", "bob", "C:\\Users\\bob\\sftp" } };
                foreach (var e in cases)
                {
                    var got = SftpConfig.ExpandFolder(e[0], e[1], "C:\\Users\\bob");
                    if (got != e[2]) throw new Exception(e[0] + " for " + e[1] + ": " + got);
                }
                if (SftpConfig.ExpandFolder("%h\\sftp", "bob", null) != null) throw new Exception("%h without a profile folder was worked out");
                return null;
            });
            test("new name: the rules section of OpenSSH Server Manager is read and rewritten under the new name", () =>
            {
                var c = DefaultLike(AuthConfig.LegacyRegionBegin);
                var st = AuthConfig.Read(c);
                if (st.RulesProblem != null || st.Rules.Count != 1 || st.Rules[0].Name != "alice") throw new Exception("the earlier section was not read: " + (st.RulesProblem ?? st.Rules.Count + " rule(s)"));
                c.Set("MaxAuthTries", "4");
                if (c.Lines.IndexOf("MaxAuthTries 4") > c.Lines.IndexOf(AuthConfig.LegacyRegionBegin)) throw new Exception("a new top-level setting landed in the earlier section");
                AuthConfig.Apply(c, st.Global, st.Rules);
                if (c.Lines.Contains(AuthConfig.LegacyRegionBegin) || c.Lines.Count(l => l == AuthConfig.RegionBegin) != 1) throw new Exception("not rewritten under the new name:\n" + c.Text);
                SftpConfig.Apply(c, true, true, new List<SftpRule> { new SftpRule { Name = "carol" } });
                if (AuthConfig.Read(c).RulesProblem != null || SftpConfig.Read(c).RulesProblem != null) throw new Exception("the two sections disturb each other:\n" + c.Text);
                AuthConfig.Apply(c, st.Global, new List<AuthRule>());
                if (SftpConfig.Read(c).Rules.Count != 1 || c.Text.Contains(AuthConfig.RegionBegin)) throw new Exception("removing the login-method rules touched the SFTP section:\n" + c.Text);
                return null;
            });
            test("sessions: the activity from the programs a session started, SFTP through the shell", () =>
            {
                var cases = new Dictionary<string, string[]> { { "SFTP", new[] { "conhost.exe", "sftp-server.exe" } }, { "scp", new[] { "scp.exe" } }, { "cmd.exe", new[] { "cmd.exe", "conhost.exe" } }, { "", new string[0] }, { "powershell.exe, whoami.exe", new[] { "powershell.exe", "whoami.exe", "powershell.exe" } } };
                foreach (var kv in cases) { var got = Sessions.Activity(kv.Value); if (got != kv.Key) throw new Exception(string.Join(",", kv.Value) + ": [" + got + "], expected [" + kv.Key + "]"); }
                // As seen on 10.5.2.0: sshd-session.exe (SYSTEM) > sshd-session.exe (the user) > cmd.exe > sftp-server.exe.
                Func<int, int, string, Sessions.ProcessEntry> P = (pid, parent, name) => new Sessions.ProcessEntry { Pid = pid, ParentPid = parent, Name = name };
                var all = new List<Sessions.ProcessEntry>
                {
                    P(10, 4, "sshd.exe"), P(100, 10, "sshd-session.exe"), P(101, 100, "sshd-session.exe"), P(200, 101, "cmd.exe"), P(300, 200, "sftp-server.exe"),
                    P(110, 10, "sshd-session.exe"), P(111, 110, "sshd-session.exe"), P(210, 111, "cmd.exe"), P(211, 111, "conhost.exe"),
                    P(400, 4, "explorer.exe"), P(401, 400, "sftp-server.exe"), // an sftp-server.exe that no session started
                    P(500, 500, "loop.exe"), P(501, 502, "a.exe"), P(502, 501, "b.exe"), // a process that is its own parent, and a cycle (reused ids)
                };
                if (Sessions.Activity(Sessions.Descendants(101, all)) != "SFTP") throw new Exception("SFTP under cmd.exe: " + Sessions.Activity(Sessions.Descendants(101, all)));
                if (Sessions.Activity(Sessions.Descendants(111, all)) != "cmd.exe") throw new Exception("a shell: " + Sessions.Activity(Sessions.Descendants(111, all)));
                if (Sessions.Descendants(501, all).Count > 1 || Sessions.Descendants(500, all).Count != 0) throw new Exception("a cycle of parent ids was followed");
                if (Sessions.SftpSessionCount(all) != 1) throw new Exception("SFTP sessions counted: " + Sessions.SftpSessionCount(all));
                return null;
            });
            test("new name: file properties, publisher and links of this project only", () =>
            {
                var fvi = FileVersionInfo.GetVersionInfo(typeof(SelfTest).Assembly.Location);
                if (fvi.ProductVersion != Program.AppVersion || fvi.FileDescription != Program.AppName || fvi.CompanyName != Program.Publisher || fvi.LegalCopyright != Program.Copyright)
                    throw new Exception("file properties: " + fvi.FileDescription + ", " + fvi.ProductVersion + ", " + fvi.CompanyName + ", " + fvi.LegalCopyright);
                if (Path.GetFileName(typeof(SelfTest).Assembly.Location) != "OpenSSHServerPNManager.exe") throw new Exception("the executable is called " + Path.GetFileName(typeof(SelfTest).Assembly.Location));
                foreach (var u in new[] { Program.Website, Program.SupportUrl, Program.ReleasesUrl }) if (!u.StartsWith("https://github.com/patnawa/openssh_server_pn")) throw new Exception("a link to another project: " + u);
                return fvi.FileDescription + " " + fvi.ProductVersion + ", " + fvi.LegalCopyright;
            });
        }

        /// <summary>Unit tests of what manager 2.1.0 added: key files in the OpenSSH and PuTTY formats, the askpass answers.</summary>
        private static void UnitSince21(Action<string, Func<string>> test, string tmpDir)
        {
            Func<byte[], string> hex = b => string.Concat(b.Select(x => x.ToString("x2")));
            test("key files: BLAKE2b and Argon2 give the test vectors of RFC 7693 and RFC 9106", () =>
            {
                if (hex(Blake2b.Hash(64, new byte[0])) != "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce") throw new Exception("BLAKE2b-512 of nothing");
                if (hex(Blake2b.Hash(64, Encoding.ASCII.GetBytes("abc"))) != "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923") throw new Exception("BLAKE2b-512 of abc");
                Func<byte, int, byte[]> fill = (v, n) => Enumerable.Repeat(v, n).ToArray();
                var vectors = new Dictionary<Argon2.Kind, string>
                {
                    { Argon2.Kind.D, "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb" },
                    { Argon2.Kind.I, "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8" },
                    { Argon2.Kind.Id, "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659" },
                };
                foreach (var v in vectors)
                {
                    var tag = hex(Argon2.Hash(v.Key, fill(1, 32), fill(2, 16), 32, 3, 4, 32, fill(3, 8), fill(4, 12)));
                    if (tag != v.Value) throw new Exception("Argon2" + v.Key.ToString().ToLowerInvariant() + ": " + tag);
                }
                return null;
            });
            test("key files: bcrypt_pbkdf gives OpenBSD's test vector", () =>
            {
                var k = hex(BcryptPbkdf.Derive(Encoding.ASCII.GetBytes("password"), Encoding.ASCII.GetBytes("salt"), 4, 32));
                if (k != "5bbf0cc293587f1c3635555c27796598d47e579071bf427e9d8fbe842aba34d9") throw new Exception(k);
                return null;
            });
            test("key files: keys of ssh-keygen and the .ppk files WinSCP made of them are the same keys", () =>
            {
                var pairs = new[] { new[] { FxEd25519, FxEd25519Ppk, "Fixture-pass-1", "Fixture-pass-1" }, new[] { FxEcdsa, FxEcdsaPpk, null, null }, new[] { FxRsa, FxRsaPpk, "Fixture-pass-1", null } };
                var types = new List<string>();
                foreach (var p in pairs)
                {
                    var ossh = OpenSshKeyFile.Parse(Fixture(p[0]));
                    var ppk = PpkFile.Parse(Encoding.UTF8.GetBytes(Fixture(p[1])));
                    if (ossh.Encrypted != (p[2] != null) || ppk.Encrypted != (p[3] != null)) throw new Exception(ossh.Type + ": encryption read wrongly");
                    var a = ossh.Decrypt(p[2]); var b = ppk.Decrypt(p[3]);
                    if (a.Type != b.Type || !KeyFormats.Equal(a.PublicBlob, b.PublicBlob) || !KeyFormats.Equal(a.Private, b.Private) || a.Comment != b.Comment) throw new Exception(a.Type + ": the two files give different keys");
                    if (p[2] != null) try { ossh.Decrypt("Fixture-pass-2"); throw new Exception(a.Type + ": the OpenSSH key opened with a wrong passphrase"); } catch (WrongPassphraseException) { }
                    if (p[3] != null) try { ppk.Decrypt("Fixture-pass-2"); throw new Exception(a.Type + ": the .ppk key opened with a wrong passphrase"); } catch (WrongPassphraseException) { }
                    types.Add(KeyFormats.Describe(a.PublicBlob));
                }
                return string.Join(", ", types);
            });
            test("key files: written as OpenSSH and .ppk (versions 2 and 3), with and without a passphrase, and read back", () =>
            {
                int n = 0;
                foreach (var fx in new[] { new[] { FxEd25519, "Fixture-pass-1" }, new[] { FxEcdsa, null }, new[] { FxRsa, "Fixture-pass-1" } })
                {
                    var k = OpenSshKeyFile.Parse(Fixture(fx[0])).Decrypt(fx[1]);
                    Action<PrivateKeyData, string> same = (x, what) => { if (x.Type != k.Type || !KeyFormats.Equal(x.PublicBlob, k.PublicBlob) || !KeyFormats.Equal(x.Private, k.Private) || x.Comment != k.Comment) throw new Exception(k.Type + ", " + what + ": another key came back"); n++; };
                    foreach (var pass in new[] { "Written-pass-3", null })
                    {
                        var text = OpenSshKeyFile.Write(k, pass, 2);
                        if (!text.StartsWith(OpenSshKeyFile.Begin + "\n") || text.Split('\n').Any(l => l.Length > 70)) throw new Exception("not laid out as ssh-keygen does");
                        same(OpenSshKeyFile.Parse(text).Decrypt(pass), "OpenSSH " + (pass ?? "no passphrase"));
                        foreach (var v in new[] { 2, 3 })
                        {
                            var ppk = PpkFile.Write(k, pass, v);
                            var parsed = PpkFile.Parse(Encoding.UTF8.GetBytes(ppk));
                            if (parsed.Version != v || parsed.Encrypted != (pass != null) || (v == 3 && pass != null) != (parsed.Kdf == "Argon2id")) throw new Exception(".ppk " + v + " header: " + ppk.Split('\n')[0]);
                            same(parsed.Decrypt(pass), ".ppk " + v + " " + (pass ?? "no passphrase"));
                            if (pass != null) try { parsed.Decrypt("Written-pass-4"); throw new Exception(".ppk " + v + " opened with a wrong passphrase"); } catch (WrongPassphraseException) { }
                        }
                    }
                }
                return n + " round trips";
            });
            test("key files: damaged and tampered files are refused", () =>
            {
                var k = OpenSshKeyFile.Parse(Fixture(FxEcdsa)).Decrypt(null);
                var ppk = PpkFile.Write(k, null, 3);
                var tampered = ppk.Replace("Comment: osm fixture ecdsa", "Comment: osm fixture ecdsA");
                try { PpkFile.Parse(Encoding.UTF8.GetBytes(tampered)).Decrypt(null); throw new Exception("a .ppk file with a changed comment was accepted"); } catch (FormatException) { }
                var cut = ppk.Substring(0, ppk.IndexOf("Private-MAC", StringComparison.Ordinal));
                try { PpkFile.Parse(Encoding.UTF8.GetBytes(cut)); throw new Exception("a .ppk file without its MAC was accepted"); } catch (FormatException) { }
                var lines = OpenSshKeyFile.Write(k, null, 2).Split('\n');
                lines[3] = lines[3].Substring(0, 10) + (lines[3][10] == 'A' ? 'B' : 'A') + lines[3].Substring(11);
                try { OpenSshKeyFile.Parse(string.Join("\n", lines)).Decrypt(null); throw new Exception("a changed OpenSSH key was accepted"); } catch (FormatException) { }
                try { OpenSshKeyFile.Parse(Fixture(FxRsa)).Decrypt(null); throw new Exception("an encrypted key opened without its passphrase"); } catch (WrongPassphraseException) { }
                try { OpenSshKeyFile.Parse("-----BEGIN RSA " + "PRIVATE KEY-----\nMIIB\n-----END RSA " + "PRIVATE KEY-----\n"); throw new Exception("a PEM file was taken for an OpenSSH key"); } catch (FormatException) { }
                if (!PpkFile.IsPpk(Fixture(FxRsaPpk)) || PpkFile.IsPpk(Fixture(FxRsa)) || OpenSshKeyFile.IsOpenSsh(Fixture(FxRsaPpk))) throw new Exception("formats told apart wrongly");
                try { OpenSshKeyFile.Parse(OpenSshKeyFile.Begin + OpenSshKeyFile.End.Substring(5)); throw new Exception("overlapping first and last lines were read"); } catch (FormatException) { }
                // Settings that would take hours or all memory are refused before any work (a crafted file).
                var slow = OpenSshKeyFile.Parse(Fixture(FxEd25519)); slow.KdfOptions = new SshWriter().String(new byte[16]).UInt32(1000000).ToArray();
                try { slow.Decrypt("Fixture-pass-1"); throw new Exception("a million bcrypt_pbkdf rounds were started"); } catch (ConfigException ex) when (!(ex is WrongPassphraseException)) { }
                var big = PpkFile.Parse(Encoding.UTF8.GetBytes(Fixture(FxEd25519Ppk))); big.Memory = 4 * 1024 * 1024;
                try { big.Decrypt("Fixture-pass-1"); throw new Exception("Argon2 with 4 GiB was started"); } catch (ConfigException ex) when (!(ex is WrongPassphraseException)) { }
                var lanes = PpkFile.Parse(Encoding.UTF8.GetBytes(Fixture(FxEd25519Ppk))); lanes.Memory = 64; lanes.Parallelism = 64;
                try { lanes.Decrypt("Fixture-pass-1"); throw new Exception("more Argon2 lanes than memory allows were started"); } catch (ConfigException ex) when (!(ex is WrongPassphraseException)) { }
                return null;
            });
            test("key files: the askpass helper answers old and new passphrases of ssh-keygen -p", () =>
            {
                var old = KeyGen.Wrap("Old-pass-1"); var nw = KeyGen.Wrap("");
                var cases = new[]
                {
                    new[] { "Enter passphrase (empty for no passphrase): ", old, null, "Old-pass-1" },
                    new[] { "Enter same passphrase again: ", old, null, "Old-pass-1" },
                    new[] { "Enter old passphrase: ", old, nw, "Old-pass-1" },
                    new[] { "Enter new passphrase (empty for no passphrase): ", old, nw, "" },
                    new[] { "Enter same passphrase again: ", old, nw, "" },
                    new[] { "Enter passphrase for \"C:\\Users\\a\\.ssh\\id_ed25519\": ", old, null, "Old-pass-1" },
                    new[] { "Are you sure you want to continue connecting (yes/no/[fingerprint])? ", old, null, null },
                };
                foreach (var c in cases)
                {
                    var got = KeyGen.AskpassAnswer(c[0], null, c[1], c[2]);
                    if (got != c[3]) throw new Exception("[" + c[0] + "]: [" + got + "], expected [" + c[3] + "]");
                }
                if (KeyGen.AskpassAnswer("alice@localhost's password: ", "password", KeyGen.Wrap("pw"), null) != "pw" || KeyGen.AskpassAnswer("Enter passphrase: ", "password", KeyGen.Wrap("pw"), null) != null) throw new Exception("password mode");
                var env = KeyGen.AskpassEnvironment("", "");
                if (env[KeyGen.SecretVariable] != "=" || env[KeyGen.NewSecretVariable] != "=") throw new Exception("an empty passphrase is not passed on as a set variable");
                return null;
            });
            test("key files: an export never loses the file that was at its place", () =>
            {
                var dir = Path.Combine(tmpDir, "aside"); Directory.CreateDirectory(dir);
                // A name so long that its backup name (.bak-date-time) passes 260 characters: moving the file aside may fail
                // where deleting it would not. Either the export fails and the file stays, or the file is kept under the backup name.
                var target = Path.Combine(dir, new string('k', Math.Max(1, 250 - dir.Length - 1)));
                File.WriteAllText(target, "the file that was there");
                var key = new KeyFileInfo { Path = Path.Combine(dir, "id_x"), PublicLine = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINFhfnIhjngEwHGzCWQanrghnwUez4F1AURuXtiqig8t test" };
                KeyWriteResult w = null; string outcome;
                try { w = KeyGen.Export(key, KeyExportFormat.OpenSshPublic, target, null, null, new DateTime(2026, 9, 27, 12, 0, 0)); outcome = "exported, the file kept aside"; }
                catch (Exception ex) { outcome = "refused (" + ex.GetType().Name + "), the file kept"; }
                if (w == null) { if (!File.Exists(target) || File.ReadAllText(target) != "the file that was there") throw new Exception("the file at the target was lost: " + outcome); }
                else if (w.MovedAside.Count != 1 || File.ReadAllText(w.MovedAside[0]) != "the file that was there") throw new Exception("exported, but the earlier file was not kept");
                return outcome;
            });
            test("key files: the names suggested for exports never take the key's own", () =>
            {
                var key = new KeyFileInfo { Path = @"C:\Users\a\.ssh\id_ed25519" };
                var names = new[] { KeyExportFormat.OpenSshPrivate, KeyExportFormat.PuttyV3, KeyExportFormat.PuttyV2, KeyExportFormat.OpenSshPublic, KeyExportFormat.Rfc4716Public }.Select(f => KeyGen.ExportFileName(key, f)).ToList();
                if (names.Distinct(StringComparer.OrdinalIgnoreCase).Count() != 5 || names.Contains("id_ed25519") || names.Contains("id_ed25519.pub")) throw new Exception(string.Join(", ", names));
                return string.Join(", ", names);
            });
        }

        /// <summary>Unit tests of what manager 2.2.0 added: SFTP partners.</summary>
        private static void UnitSince22(Action<string, Func<string>> test, string tmpDir)
        {
            test("partners: generated passwords have 20 characters of every kind and none that is easy to confuse", () =>
            {
                var seen = new HashSet<string>(); var chars = new HashSet<char>();
                for (int i = 0; i < 2000; i++)
                {
                    var p = Partners.NewPassword();
                    if (p.Length != Partners.PasswordLength || !p.Any(char.IsUpper) || !p.Any(char.IsLower) || !p.Any(char.IsDigit) || p.All(char.IsLetterOrDigit)) throw new Exception("not every kind of character: " + p);
                    if (p.IndexOfAny("Il1O0o \"'`\\".ToCharArray()) >= 0 || p.Any(c => c > 126)) throw new Exception("a character that is easy to confuse or hard to type: " + p);
                    if (!seen.Add(p)) throw new Exception("the same password twice");
                    foreach (var c in p) chars.Add(c);
                }
                if (chars.Count < 60) throw new Exception("only " + chars.Count + " different characters in 2000 passwords");
                return chars.Count + " different characters";
            });
            test("partners: account names", () =>
            {
                foreach (var good in new[] { "acme", "Acme-Logistics", "p_01", "a.b", "x" })
                    if (Partners.NameError(good) != null) throw new Exception("refused [" + good + "]: " + Partners.NameError(good));
                var users = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null).Translate(typeof(NTAccount)).Value;
                foreach (var bad in new[] { "", "a b", "-acme", ".acme", "acme.", "a\"b", "a%b", "a@b", "a/b", "abcdefghijklmnopqrstu", "ก", users.Substring(users.IndexOf('\\') + 1) })
                    if (Partners.NameError(bad) == null) throw new Exception("accepted [" + bad + "]");
                return null;
            });
            test("partners: the setup writes the SFTP and login-method rules first, once, and keeps the others", () =>
            {
                var g = new PartnerGroups { KeysDir = @"C:\ProgramData\ssh\partner_keys" };
                var c = DefaultLike(AuthConfig.RegionBegin);
                SftpConfig.Apply(c, true, false, new List<SftpRule> { new SftpRule { Name = "carol", Folder = @"C:\SFTP\%u" } });
                PartnerSetup.Apply(c, g, @"D:\Partners");
                var sftp = SftpConfig.Read(c); var auth = AuthConfig.Read(c);
                if (sftp.RulesProblem != null || auth.RulesProblem != null) throw new Exception("a section is not readable: " + (sftp.RulesProblem ?? auth.RulesProblem));
                if (!sftp.LogTransfers) throw new Exception("file transfers are not logged");
                var names = sftp.Rules.Select(r => r.Kind + " " + r.Name).ToList();
                if (string.Join(", ", names) != "Group sftp-partners-readonly, Group sftp-partners, User carol") throw new Exception("SFTP rules: " + string.Join(", ", names));
                if (sftp.Rules[0].Folder != @"D:\Partners\%u" || !sftp.Rules[0].ReadOnly || sftp.Rules[1].ReadOnly || sftp.Rules[0].KeysFile != "__PROGRAMDATA__/ssh/partner_keys/%u") throw new Exception("partner SFTP rule: " + sftp.Rules[0].Describe() + ", keys " + sftp.Rules[0].KeysFile);
                var auths = auth.Rules.Select(r => r.Name + ":" + (r.Methods.Password ? "p" : "") + (r.Methods.PublicKey ? "k" : "")).ToList();
                if (string.Join(", ", auths.Take(3)) != "sftp-partners-keyonly:k, sftp-partners:pk, sftp-partners-readonly:pk" || auths.Count != 4) throw new Exception("login-method rules: " + string.Join(", ", auths));
                if (!c.Lines.Contains("\tAuthorizedKeysFile __PROGRAMDATA__/ssh/partner_keys/%u")) throw new Exception("no AuthorizedKeysFile line:\n" + c.Text);
                var st = PartnerSetup.Check(c, g);
                if (st.Missing.Count != 0 || st.Root != @"D:\Partners") throw new Exception("after the setup, still missing: " + string.Join("; ", st.Missing) + ", root " + st.Root);
                var once = c.Text; PartnerSetup.Apply(c, g, @"D:\Partners");
                if (c.Text != once) throw new Exception("a second setup changed the file");
                if (PartnerSetup.Check(DefaultLike(), g).Missing.Count < 5) throw new Exception("a configuration without the setup is reported as set up");
                return st.MissingGroups.Count + " group(s) not on this computer (created by the setup)";
            });
            test("partners: AllowGroups gets the partner groups, AllowUsers and a hand-edited section are reported", () =>
            {
                var g = new PartnerGroups();
                var c = DefaultLike(); c.Set("AllowGroups", "administrators \"openssh users\"");
                if (!PartnerSetup.Check(c, g).Missing.Any(m => m.Contains("AllowGroups"))) throw new Exception("AllowGroups without the partner groups is not reported");
                PartnerSetup.Apply(c, g, @"C:\SFTP");
                string err; var allow = c.GetCombinedArgs("AllowGroups", out err);
                if (!allow.Contains("administrators") || !allow.Contains("openssh users") || !allow.Contains("sftp-partners") || !allow.Contains("sftp-partners-readonly")) throw new Exception("AllowGroups " + SshdArgs.FormatTyped(allow));
                if (PartnerSetup.Check(c, g).Missing.Count != 0) throw new Exception("still missing: " + string.Join("; ", PartnerSetup.Check(c, g).Missing));
                c.Set("AllowUsers", "admin");
                if (!PartnerSetup.Check(c, g).Problems.Any(p => p.Contains("AllowUsers"))) throw new Exception("AllowUsers is not reported");
                var h = DefaultLike(); SftpConfig.Apply(h, true, false, new List<SftpRule> { new SftpRule { Name = "carol", Folder = @"C:\SFTP\%u" } });
                h.Lines.Insert(h.Lines.IndexOf("Match all"), "\tPasswordAuthentication no");
                try { PartnerSetup.Apply(h, g, @"C:\SFTP"); throw new Exception("rules were written over a hand-edited section"); } catch (ConfigException) { }
                return null;
            });
            test("partners: SFTP rules with and without AuthorizedKeysFile are read back as written", () =>
            {
                var c = DefaultLike();
                var rules = new List<SftpRule> { new SftpRule { IsGroup = true, Name = "sftp-partners", Folder = @"C:\SFTP\%u", KeysFile = "C:/Keys dir/%u" }, new SftpRule { Name = "bob", Folder = @"C:\SFTP\%u" } };
                SftpConfig.Apply(c, true, true, rules);
                var back = SftpConfig.Read(c);
                if (back.RulesProblem != null || back.Rules.Count != 2 || !back.Rules[0].SameAs(rules[0]) || !back.Rules[1].SameAs(rules[1])) throw new Exception("read back: " + (back.RulesProblem ?? string.Join("; ", back.Rules.Select(r => r.Name + " " + r.KeysFile))));
                if (!c.Lines.Contains("\tAuthorizedKeysFile \"C:/Keys dir/%u\"")) throw new Exception("the path with a space is not quoted:\n" + c.Text);
                return null;
            });
            test("partners: the partner dialog refuses a bad name before anything is made, and passes the choices on", () =>
            {
                bool ran = false;
                using (var d = new PartnerDialog(null, @"C:\SFTP", "", x => ran = true))
                {
                    d.StartPosition = FormStartPosition.Manual; d.Location = new Point(-20000, -20000); d.ShowInTaskbar = false; d.Show(); Application.DoEvents();
                    d.TypeForTest("Account name", "bad name"); d.OkForTest();
                    if (ran || d.LastError == null || !d.LastError.StartsWith("Use letters")) throw new Exception("a name with a space: " + (d.LastError ?? "accepted"));
                    d.TypeForTest("Account name", "osm-dialog-test"); d.TypeForTest("Company", "ACME"); d.TickForTest("Download only"); d.TickForTest("Public key only");
                    d.OkForTest();
                    if (!ran || d.DialogResult != DialogResult.OK) throw new Exception("valid input was refused: " + d.LastError);
                    if (d.AccountName != "osm-dialog-test" || d.Company != "ACME" || !d.ReadOnlyAccess || !d.KeyOnly || d.LastDay != null) throw new Exception("the choices did not come through");
                }
                return null;
            });
            test("transfers: sftp-server events become transfers with the client address, two sessions apart", () =>
            {
                var t0 = new DateTime(2026, 9, 27, 10, 0, 0);
                Func<int, int, string, Transfers.SftpEvent> E = (sec, pid, text) => new Transfers.SftpEvent { Time = t0.AddSeconds(sec), Pid = pid, Text = text };
                var events = new List<Transfers.SftpEvent>
                {
                    E(0, 100, "user: acme: session opened for local user acme from [203.0.113.7] [postauth]"),
                    E(1, 200, "user: globex: session opened for local user globex from [2001:db8::5] [postauth]"),
                    E(2, 100, "user: acme: open \"/in/a, \"b\".csv\" flags WRITE,CREATE,TRUNCATE mode 0666 [postauth]"),
                    E(3, 200, "user: globex: open \"/report.pdf\" flags READ mode 0666 [postauth]"),
                    E(4, 100, "user: acme: close \"/in/a, \"b\".csv\" bytes read 0 written 52873 [postauth]"),
                    E(5, 200, "user: globex: close \"/report.pdf\" bytes read 1048576 written 0 [postauth]"),
                    E(6, 100, "user: acme: open \"/empty.txt\" flags WRITE,CREATE,TRUNCATE mode 0666 [postauth]"),
                    E(7, 100, "user: acme: close \"/empty.txt\" bytes read 0 written 0 [postauth]"),
                    E(8, 100, "user: acme: posix-rename old \"/in/x.tmp\" new \"/in/x.csv\" [postauth]"),
                    E(9, 100, "user: acme: remove name \"/old.csv\" [postauth]"),
                    E(10, 100, "user: acme: mkdir name \"/out\" mode 0777 [postauth]"),
                    E(11, 200, "user: globex: open \"/up.bin\" flags WRITE,CREATE,TRUNCATE mode 0666 [postauth]"),
                    E(12, 200, "user: globex: sent status Permission denied [postauth]"),
                    E(13, 200, "user: globex: sent status Permission denied [postauth]"),
                    E(14, 100, "user: acme: open \"/peek.txt\" flags READ mode 0666 [postauth]"),
                    E(15, 100, "user: acme: close \"/peek.txt\" bytes read 0 written 0 [postauth]"),
                };
                var r = Transfers.Parse(events);
                var got = string.Join("; ", r.Select(x => x.User + " " + x.Address + " " + x.Action + " " + x.File + " " + x.Bytes + (x.Detail.Length > 0 ? " (" + x.Detail + ")" : "")));
                var want = "acme 203.0.113.7 upload /in/a, \"b\".csv 52873; globex 2001:db8::5 download /report.pdf 1048576; acme 203.0.113.7 upload /empty.txt 0; " +
                           "acme 203.0.113.7 rename /in/x.csv 0 (from /in/x.tmp); acme 203.0.113.7 delete /old.csv 0; acme 203.0.113.7 new folder /out 0; globex 2001:db8::5 refused /up.bin 0 (upload refused)";
                if (got != want) throw new Exception("\n got: " + got + "\nwant: " + want);
                var t = Transfers.Totals(r);
                if (t.Count != 2 || t[0].User != "globex" || t[0].DownloadBytes != 1048576 || t[0].Refused != 1 || t[1].Uploads != 2 || t[1].UploadBytes != 52873 || t[1].Changes != 3) throw new Exception("totals: " + string.Join("; ", t.Select(x => x.User + " " + x.Short)));
                return r.Count + " records";
            });
            test("transfers: CSV lines come back as written, and spreadsheets do not run a name as a formula", () =>
            {
                var recs = new[]
                {
                    new TransferRecord { Time = new DateTime(2026, 9, 27, 10, 11, 12), User = "acme", Address = "203.0.113.7", Action = "upload", File = "/in/a, \"b\"\n.csv", Bytes = 5, Detail = "" },
                    new TransferRecord { Time = new DateTime(2026, 9, 27, 10, 11, 13), User = "x", Address = "::1", Action = "download", File = "=HYPERLINK(\"http://x\")", Bytes = 0, Detail = "-2" },
                    new TransferRecord { Time = new DateTime(2026, 9, 27, 10, 11, 14), User = "y", Address = "", Action = "rename", File = "@sum", Bytes = 0, Detail = "+from" },
                };
                foreach (var x in recs)
                {
                    var line = Transfers.CsvLine(x);
                    if (Regex.IsMatch(line, "(^|,)\"?[=+@]")) throw new Exception("a field starts like a formula: " + line);
                    var back = Transfers.FromCsv(line);
                    var expected = x.File.Replace("\n", "?"); // control characters are written as ?: one record per line
                    if (back == null || back.Key != x.Key.Replace(x.File, expected) || back.File != expected || back.Address != x.Address || back.Detail != x.Detail) throw new Exception("round trip of " + line + " gave " + (back == null ? "nothing" : back.File + " / " + back.Detail));
                }
                return null;
            });
            test("transfers: the report encodes names, and the periods start and end where they should", () =>
            {
                var recs = new List<TransferRecord> { new TransferRecord { Time = new DateTime(2026, 9, 3, 9, 0, 0), User = "acme", Address = "203.0.113.7", Action = "upload", File = "/<script>alert(1)</script>.csv", Bytes = 2048 } };
                var html = Transfers.ReportHtml(recs, new DateTime(2026, 9, 1), new DateTime(2026, 10, 1), "srv<1>", new Dictionary<string, string> { { "acme", "ACME & Sons" } });
                if (html.Contains("<script>") || html.Contains("srv<1>") || !html.Contains("ACME &amp; Sons") || !html.Contains("2026-09-01 to 2026-09-30")) throw new Exception("the report is not encoded as it should be");
                DateTime f, to; var now = new DateTime(2026, 3, 15, 14, 30, 0);
                TransfersWindow.Range("Last month", now, out f, out to);
                if (f != new DateTime(2026, 2, 1) || to != new DateTime(2026, 3, 1)) throw new Exception("last month: " + f + " to " + to);
                TransfersWindow.Range("Yesterday", now, out f, out to);
                if (f != new DateTime(2026, 3, 14) || to != new DateTime(2026, 3, 15)) throw new Exception("yesterday: " + f + " to " + to);
                TransfersWindow.Range("This month", now, out f, out to);
                if (f != new DateTime(2026, 3, 1) || to != now) throw new Exception("this month: " + f + " to " + to);
                return null;
            });
            test("alerts: networks, the allow list, and the settings with their secrets sealed", () =>
            {
                Network n;
                if (!Network.TryParse("203.0.113.0/24", out n) || !n.Contains("203.0.113.77") || n.Contains("203.0.114.1")) throw new Exception("IPv4 network");
                if (!Network.TryParse("2001:db8::/32", out n) || !n.Contains("2001:db8:1::5") || n.Contains("2001:db9::1") || n.Contains("203.0.113.1")) throw new Exception("IPv6 network");
                if (!Network.TryParse("198.51.100.7", out n) || !n.Contains("::ffff:198.51.100.7") || n.Contains("198.51.100.8")) throw new Exception("one address");
                foreach (var bad in new[] { "x", "1.2.3.4/33", "1.2.3.4/-1", "1.2.3.4/8/1", "" }) if (Network.TryParse(bad, out n)) throw new Exception("accepted [" + bad + "]");
                var s = new AlertSettings { SmtpHost = "mail.example.com", SmtpUser = "u", SmtpPassword = "p=ss;word", From = "a@example.com", AdminTo = "b@example.com, c@example.com", Webhook = "https://example.com/hook?sig=abc", AllowList = "203.0.113.0/24 198.51.100.7" };
                s.PartnerNotify["acme"] = "d@example.com";
                var v = s.ToValues();
                if (v["smtp.password"].Contains("p=ss") || !v["smtp.password"].StartsWith("dpapi:") || v["webhook.url"].Contains("example.com")) throw new Exception("a secret is stored in the clear");
                var back = AlertSettings.FromValues(v);
                if (back.SmtpPassword != s.SmtpPassword || back.Webhook != s.Webhook || back.AdminTo != s.AdminTo || back.PartnerNotify["acme"] != "d@example.com" || back.Problem() != null) throw new Exception("read back: " + back.Problem());
                s.AdminTo = "not an address"; if (s.Problem() == null) throw new Exception("a wrong address was accepted");
                s.AdminTo = "b@example.com"; s.Webhook = "http://example.com/hook"; if (s.Problem() == null) throw new Exception("a webhook without https was accepted");
                s.Webhook = ""; s.AllowList = "10.0.0.0/33"; if (s.Problem() == null) throw new Exception("a wrong network in the allow list was accepted");
                return null;
            });
            test("alerts: automatic blocking: threshold, allow list, open sessions, longer blocks for repeat offenders", () =>
            {
                var s = new AlertSettings { AllowList = "203.0.113.0/24", BlockThreshold = 10 };
                var st = new AgentState(); var now = new DateTime(2026, 9, 27, 12, 0, 0);
                Func<string, int, EventLogs.FailedSource> F = (a, c) => new EventLogs.FailedSource { Address = a, Count = c, First = now, Last = now };
                var src = new List<EventLogs.FailedSource> { F("198.51.100.9", 12), F("198.51.100.10", 9), F("203.0.113.5", 50), F("192.0.2.1", 40), F("192.0.2.2", 11), F("127.0.0.1", 99) };
                var add = Agent.PlanBlocks(s, st, src, now, new HashSet<string> { "192.0.2.2" }, new HashSet<string> { "192.0.2.1" }, a => a == "127.0.0.1");
                if (string.Join(",", add) != "198.51.100.9") throw new Exception("blocked: " + string.Join(",", add) + " (below the threshold, allowed, connected, blocked already and this computer must not be)");
                var b = st.Blocks["198.51.100.9"];
                if (b.Until != now.AddHours(1) || b.Strikes != 1) throw new Exception("first block until " + b.Until);
                var one = src.Take(1).ToList(); var none = new HashSet<string>();
                b.Until = DateTime.MinValue; Agent.PlanBlocks(s, st, one, now.AddHours(2), none, none, a => false);
                if (b.Until != now.AddHours(26)) throw new Exception("second block until " + b.Until);
                b.Until = DateTime.MinValue; Agent.PlanBlocks(s, st, one, now.AddDays(2), none, none, a => false);
                if (b.Until != now.AddDays(9)) throw new Exception("third block until " + b.Until);
                b.Until = DateTime.MinValue; Agent.PlanBlocks(s, st, one, now.AddDays(20), none, none, a => false);
                b = st.Blocks["198.51.100.9"];
                if (b.Until != now.AddDays(20).AddHours(1) || b.Strikes != 1) throw new Exception("after a quiet week: until " + b.Until + ", strike " + b.Strikes);
                return null;
            });
            test("alerts: uploads of a partner wait 5 minutes and go out together; others are not reported", () =>
            {
                var st = new AgentState(); var t0 = new DateTime(2026, 9, 27, 12, 0, 0);
                var recs = new[]
                {
                    new TransferRecord { Time = t0, User = "acme", Action = TransferRecord.Upload, File = "/a.csv", Bytes = 10 },
                    new TransferRecord { Time = t0.AddMinutes(3), User = "acme", Action = TransferRecord.Upload, File = "/b.csv", Bytes = 20 },
                    new TransferRecord { Time = t0, User = "alice", Action = TransferRecord.Upload, File = "/x" },
                    new TransferRecord { Time = t0, User = "acme", Action = TransferRecord.Download, File = "/c" },
                };
                Agent.AddPending(st, recs, new HashSet<string> { "acme" });
                if (st.Pending.Count != 1 || st.Pending["acme"].Count != 2) throw new Exception("waiting: " + string.Join("; ", st.Pending.Select(p => p.Key + " " + p.Value.Count)));
                if (Agent.DuePending(st, t0.AddMinutes(4)).Count != 0) throw new Exception("sent before 5 minutes");
                if (string.Join(",", Agent.DuePending(st, t0.AddMinutes(5))) != "acme") throw new Exception("not sent after 5 minutes");
                return null;
            });
            test("alerts: an e-mail and a webhook reach a server (test servers on 127.0.0.1)", () =>
            {
                using (var smtp = new TestServer(false))
                using (var http = new TestServer(true))
                {
                    var s = new AlertSettings { SmtpHost = "127.0.0.1", SmtpPort = smtp.Port, SmtpTls = false, From = "osm@example.com", AdminTo = "admin@example.com" };
                    Agent.SendMail(s, "Test subject", "Body line", null, AlertSettings.Addresses(s.AdminTo), "report.csv", "x,y\r\n");
                    var mail = smtp.Wait();
                    if (!mail.Contains("RCPT TO:<admin@example.com>") || !mail.Contains("MAIL FROM:<osm@example.com>") || !mail.Contains("report.csv")) throw new Exception("the mail server got:\n" + mail);
                    s.Webhook = "http://127.0.0.1:" + http.Port + "/hook"; s.WebhookTeams = true;
                    Agent.SendHook(s, "Subject \"q\"", "line1\nline2");
                    var req = http.Wait();
                    if (!req.StartsWith("POST /hook") || !req.Contains("application/vnd.microsoft.card.adaptive") || !req.Contains("Subject \\\"q\\\"") || !req.Contains("line1\\n\\nline2")) throw new Exception("the webhook got:\n" + req);
                    if (Agent.HookBody(false, "a\\b", "c") != "{\"text\":\"a\\\\b\\nc\"}") throw new Exception("text body: " + Agent.HookBody(false, "a\\b", "c"));
                }
                return null;
            });
            test("partners: the last day an account can log in, and sizes for people", () =>
            {
                if (LocalAccounts.LastDay(new DateTime(2026, 10, 1, 0, 0, 0)) != new DateTime(2026, 9, 30)) throw new Exception("LastDay of midnight");
                if (LocalAccounts.LastDay(null) != null) throw new Exception("LastDay of never");
                var sizes = new[] { Ui.Bytes(0), Ui.Bytes(1023), Ui.Bytes(1536), Ui.Bytes(10L << 20), Ui.Bytes(3L << 30) };
                if (string.Join("|", sizes) != "0 bytes|1023 bytes|1.5 KB|10 MB|3.0 GB") throw new Exception(string.Join("|", sizes));
                return null;
            });
            test("after installing: the package's request for the setup wizard counts once, and only while it is fresh", () =>
            {
                var old = Ssh.ConfigDirOverride;
                Ssh.ConfigDirOverride = Path.Combine(tmpDir, "wizard-request");
                try
                {
                    var now = new DateTime(2026, 9, 27, 12, 0, 0);
                    bool admin = Elevation.IsAdministrator();
                    if (!admin) Directory.CreateDirectory(AlertSettings.Dir); // the admin-only folder needs administrator rights
                    if (WizardRequest.Take(now)) throw new Exception("taken without a request");
                    WizardRequest.Leave(now.AddMinutes(-2));
                    if (admin && !Acl.IsAdminOnly(AlertSettings.Dir)) throw new Exception("the folder of the request is open to others");
                    if (!WizardRequest.Take(now)) throw new Exception("a request of 2 minutes ago is not taken");
                    if (File.Exists(WizardRequest.FilePath) || WizardRequest.Take(now)) throw new Exception("a request counts twice");
                    WizardRequest.Leave(now.AddMinutes(-20));
                    if (WizardRequest.Take(now) || File.Exists(WizardRequest.FilePath)) throw new Exception("a request of 20 minutes ago counts, or stays");
                    WizardRequest.Leave(now.AddHours(2));
                    if (WizardRequest.Take(now)) throw new Exception("a request from the future counts");
                    File.WriteAllText(WizardRequest.FilePath, "not a time");
                    if (WizardRequest.Take(now) || File.Exists(WizardRequest.FilePath)) throw new Exception("an unreadable request counts, or stays");
                    return null;
                }
                finally { Ssh.ConfigDirOverride = old; }
            });
        }

        /// <summary>A one-connection SMTP or HTTP server on 127.0.0.1 for the tests of sending: it records what it receives.</summary>
        private sealed class TestServer : IDisposable
        {
            private readonly System.Net.Sockets.TcpListener _l = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
            private readonly StringBuilder _got = new StringBuilder();
            private readonly ManualResetEvent _done = new ManualResetEvent(false);
            public int Port { get { return ((IPEndPoint)_l.LocalEndpoint).Port; } }

            public TestServer(bool http)
            {
                _l.Start();
                new Thread(() =>
                {
                    try
                    {
                        using (var c = _l.AcceptTcpClient())
                        {
                            c.ReceiveTimeout = 20000;
                            if (http) Http(c.GetStream()); else Smtp(c.GetStream());
                        }
                    }
                    catch (Exception ex) { lock (_got) _got.Append("ERROR " + ex.Message); }
                    finally { _done.Set(); }
                }) { IsBackground = true }.Start();
            }

            private void Smtp(System.Net.Sockets.NetworkStream s)
            {
                var r = new StreamReader(s, Encoding.ASCII); var w = new StreamWriter(s, Encoding.ASCII) { NewLine = "\r\n", AutoFlush = true };
                w.WriteLine("220 test ESMTP");
                string line; bool data = false;
                while ((line = r.ReadLine()) != null)
                {
                    lock (_got) _got.AppendLine(line);
                    if (data) { if (line == ".") { data = false; w.WriteLine("250 OK queued"); } continue; }
                    var u = line.ToUpperInvariant();
                    if (u.StartsWith("EHLO")) { w.WriteLine("250-test"); w.WriteLine("250 SIZE 10000000"); }
                    else if (u.StartsWith("DATA")) { data = true; w.WriteLine("354 go on"); }
                    else if (u.StartsWith("QUIT")) { w.WriteLine("221 bye"); break; }
                    else w.WriteLine("250 OK");
                }
            }

            private void Http(System.Net.Sockets.NetworkStream s)
            {
                var r = new StreamReader(s, Encoding.UTF8); string line; int length = 0;
                while (!string.IsNullOrEmpty(line = r.ReadLine()))
                {
                    lock (_got) _got.AppendLine(line);
                    if (line.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase)) int.TryParse(line.Substring(15).Trim(), out length);
                }
                var buf = new char[length]; int read = 0;
                while (read < length) { int n = r.Read(buf, read, length - read); if (n <= 0) break; read += n; }
                lock (_got) _got.Append(new string(buf, 0, read));
                var resp = Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                s.Write(resp, 0, resp.Length);
            }

            public string Wait() { if (!_done.WaitOne(30000)) throw new Exception("the test server received nothing within 30 s"); lock (_got) return _got.ToString(); }
            public void Dispose() { try { _l.Stop(); } catch { } }
        }

        // Test keys made for these tests only, never used anywhere else: ssh-keygen 10.5.3.0 made the OpenSSH files, WinSCP 6.5.7's
        // key converter (PuTTY's code) the .ppk files of the same keys. The first lines are put together at run time, so that
        // scanners for leaked keys do not take this source file for a key.
        private static string Fixture(string text) { return text.Replace("{OSSH-B}", OpenSshKeyFile.Begin).Replace("{OSSH-E}", OpenSshKeyFile.End).Replace("{PPK}", PpkFile.Header); }
        private const string FxEd25519 =
            "{OSSH-B}\n" +
            "b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABAP+qFdKY\n" +
            "mNH6VXTtkugQAaAAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAINFhfnIhjngEwHGz\n" +
            "CWQanrghnwUez4F1AURuXtiqig8tAAAAoBBt7A2df9/MElBDi02I87zKecP9EcizatJH+M\n" +
            "npSOns+Cqw1H3VxWDccg4k4Nhkj0D1XQQoIfHrkkXqdpTSKZ6KPSMd3cgnW04kbVYaeA1F\n" +
            "45Y5K6DL0Cbf2MWI+yc+068Qa+/UjQlrsQBC7A8iXCuBFITfTAWeOYwv4O1t+wn0XPk/eW\n" +
            "E13GqB5A00AwUeGvvay+u32H9a9Q+PvM1plng=\n" +
            "{OSSH-E}\n";
        private const string FxEd25519Ppk =
            "{PPK}3: ssh-ed25519\n" +
            "Encryption: aes256-cbc\n" +
            "Comment: osm fixture ed25519\n" +
            "Public-Lines: 2\n" +
            "AAAAC3NzaC1lZDI1NTE5AAAAINFhfnIhjngEwHGzCWQanrghnwUez4F1AURuXtiq\n" +
            "ig8t\n" +
            "Key-Derivation: Argon2id\n" +
            "Argon2-Memory: 8192\n" +
            "Argon2-Passes: 21\n" +
            "Argon2-Parallelism: 1\n" +
            "Argon2-Salt: 3474998e543220d90ca371e6b769208b\n" +
            "Private-Lines: 1\n" +
            "LpWPicjC/xy6Lq3jAsqHc/wLNlL2z903Pl+tOKdyICtvWxSb0F4M9fwgOKqfIS1J\n" +
            "Private-MAC: ca3bec77078f08a6607297cb174edd8622572f6962d9e05c4bb8e0a320b96f87\n";
        private const string FxEcdsa =
            "{OSSH-B}\n" +
            "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS\n" +
            "1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQSsYHuzfCKZ5sTpDGWymtxazwv5A+6C\n" +
            "urxII+3+IgY/uyss2Uuj5mry11mQTk5c4Xj1+SiHsm4RR+2cDQwM5cTVAAAAsDK3yGIyt8\n" +
            "hiAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKxge7N8IpnmxOkM\n" +
            "ZbKa3FrPC/kD7oK6vEgj7f4iBj+7KyzZS6PmavLXWZBOTlzhePX5KIeybhFH7ZwNDAzlxN\n" +
            "UAAAAhAKjjy7FNGkGX+nJHfTgdz7bjaUZF59NmcpiJEwgiV3qeAAAAEW9zbSBmaXh0dXJl\n" +
            "IGVjZHNhAQIDBAUG\n" +
            "{OSSH-E}\n";
        private const string FxEcdsaPpk =
            "{PPK}3: ecdsa-sha2-nistp256\n" +
            "Encryption: none\n" +
            "Comment: osm fixture ecdsa\n" +
            "Public-Lines: 3\n" +
            "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKxge7N8Ipnm\n" +
            "xOkMZbKa3FrPC/kD7oK6vEgj7f4iBj+7KyzZS6PmavLXWZBOTlzhePX5KIeybhFH\n" +
            "7ZwNDAzlxNU=\n" +
            "Private-Lines: 1\n" +
            "AAAAIQCo48uxTRpBl/pyR304Hc+242lGRefTZnKYiRMIIld6ng==\n" +
            "Private-MAC: 6739a31c8cc88ae4f8a62f0826d366c20577702f5980c5fc498ffad7386595f3\n";
        private const string FxRsa =
            "{OSSH-B}\n" +
            "b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABC5Pi+vN8\n" +
            "LsjQyNjnhCno2wAAAAGAAAAAEAAACXAAAAB3NzaC1yc2EAAAADAQABAAAAgQDQp8OeUP5G\n" +
            "gBVpoj9A4BoSAZA0IN7hR2LCdwN37XAneK1YAHBWFNNt5+2eOuoiCokszgR40LbhksZ6md\n" +
            "Ot+X92Aox20cBvDE+LHkzvEoGDKr4NSeN/w4t0VB0h/oOp6OHff5wuienepELIbHUwzTG0\n" +
            "UUvbu4TiJo6fIertTEm0BwAAAhBYq+CEg2Jt9RDQ7rFvQY9+NIOchLCOiOBZlozRtNkjBN\n" +
            "dlRk0qgwE355VeEKMf67+rCsQ+OvqZVMclLbGPg5ZxQesVoVctA2+gGo/ayXS5KK/qcZXh\n" +
            "NRRz4GmJHhwZyGVFIrr42R5TZ+PdapMM/9jryj9O51de7HrFPwRTjRF3aVK1+wtp/r/XmM\n" +
            "PdLWYZRjAML99BTqZbXLzC5skhOUW2P8CrLuAhf8UE/lcf/nwuJ5dpT+/VOKxMfzpB6/eH\n" +
            "wXDLClB68U/tr/vz7yFPWpTAgq5uGHbikD57lQzfvC0btt5bMV6UqBfEFReTBKkC9eLLlS\n" +
            "5J2an60VqpBg4Tq0TY77HABUYctotm5HvMsnYjgJ1KHfzWwmTfZ9nESecWAbmreFRz/3Jy\n" +
            "cXJbjMNVn73XU8ytss5IGdnEzK/ue7LJTo+o6Ir15K9K8eoMyuSlmUnl8c20D8b+QzHOHN\n" +
            "nhvbriOYAE5W9PR+w0He/qZ0HNpjjKsomQuYjzcuzrcGffbl1v8TpasPGqtLSi0uVWbJZj\n" +
            "YfCfuPAqtKBNFU6oKVSfFdYLS4rkLJBKHXdF2SlHOcGx7s07No1URitn0mN/5q/6uWawDY\n" +
            "R/A4VjhMy90NZnfymALgsD+ByAihcknT/XupDQgGWwzZ8y9Ro6aaiO3BnQWOTw/Sw5VGTn\n" +
            "smIEsB2SRnJKV3FxDWdN4zWg3G6gEJU=\n" +
            "{OSSH-E}\n";
        private const string FxRsaPpk =
            "{PPK}3: ssh-rsa\n" +
            "Encryption: none\n" +
            "Comment: osm fixture rsa\n" +
            "Public-Lines: 4\n" +
            "AAAAB3NzaC1yc2EAAAADAQABAAAAgQDQp8OeUP5GgBVpoj9A4BoSAZA0IN7hR2LC\n" +
            "dwN37XAneK1YAHBWFNNt5+2eOuoiCokszgR40LbhksZ6mdOt+X92Aox20cBvDE+L\n" +
            "HkzvEoGDKr4NSeN/w4t0VB0h/oOp6OHff5wuienepELIbHUwzTG0UUvbu4TiJo6f\n" +
            "IertTEm0Bw==\n" +
            "Private-Lines: 8\n" +
            "AAAAgHSUl5a4OCoZ3Fzl+yN7UvWmi/SkPQNvyD1RE84JCvXy1h9qN1nRTwSEZl5X\n" +
            "GoQkkNpIzXTXYKcOQ/kyQ3RcB5tbd6d6pFlmDngsePQ5fDzTmRrnw+xF3O/VJuXP\n" +
            "Xrba8ef4Rmr4Jbx7e5d//4lFFYT5wCS6zb/z6scbSMDsKscZAAAAQQD+0qFQKupi\n" +
            "0nQaY9xJ/kf7NNBAs5I5/xlzU79ZwhcWjMfgHQ3ZfGCmkw3AqfLCkCyoQjhpLik/\n" +
            "HWQRAN81scstAAAAQQDRnoiNDtZ229AxpYTHtl7LIK/q6og2zEO1VKi3I7rJRDAc\n" +
            "vF6ikOfWaKt7W6cL3OgResus/ATd4xkBC4cizyyDAAAAQFrcMeaFNCujCCvoVcqR\n" +
            "gDNq0G3qBhmRoa2NeHTmA86kECRusVzdeISsX03uLRB3EZQaQ1nbEE2ctohZgC9q\n" +
            "inU=\n" +
            "Private-MAC: 6a995abfe936e1b80373f7015a6378da9c4ace10df6f463142ed5fdccb6913b2\n";

        private static void Server(Action<string, Func<string>> test, string tmpDir)
        {
            test("sshd.exe present", () => { if (!File.Exists(Ssh.Exe("sshd.exe"))) throw new Exception("missing in " + Ssh.InstallDir); return Ssh.ServerVersion(); });
            test("config load", () => { var c = SshdConfig.Load(); if (c.Lines.Count == 0) throw new Exception("empty"); return c.Lines.Count + " lines, port " + c.EffectivePort; });
            test("config round-trip keeps content", () => { var c = SshdConfig.Load(); var before = c.Text; var d = new SshdConfig { Lines = c.Lines.ToList(), NewLine = c.NewLine }; if (d.Text != before) throw new Exception("text differs"); return null; });
            test("sshd -t accepts a valid candidate", () =>
            {
                var c = SshdConfig.Load(); c.Set("ClientAliveInterval", "300");
                var p = Path.Combine(tmpDir, "good.conf"); File.WriteAllText(p, c.Text, new UTF8Encoding(false));
                var r = Ssh.TestConfig(p); if (!r.Ok) throw new Exception(r.Output); return null;
            });
            test("sshd -t rejects an invalid candidate", () =>
            {
                var c = SshdConfig.Load(); c.Set("Port", "notaport");
                var p = Path.Combine(tmpDir, "bad.conf"); File.WriteAllText(p, c.Text, new UTF8Encoding(false));
                var r = Ssh.TestConfig(p); if (r.Ok) throw new Exception("invalid config was accepted"); return "rejected as expected";
            });
            test("authorized_keys write + admin-only ACL", () =>
            {
                // Restricting a file to SYSTEM and Administrators locks a non-elevated user out of its own temp file.
                if (!Elevation.IsAdministrator()) return "skipped: not elevated";
                var p = Path.Combine(tmpDir, "administrators_authorized_keys");
                Keys.Write(p, new[] { "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGVkMjU1MTlzZWxmdGVzdGtleTAwMDAwMDAwMDAwMDAwMDA selftest" }, null);
                if (!Acl.IsAdminOnly(p)) throw new Exception("ACL not restricted"); return null;
            });
            test("security audit probes", () =>
            {
                var parts = new List<string>();
                parts.Add("install folder " + SecurityAudit.InstallFolder().Count);
                parts.Add("config " + SecurityAudit.ConfigFolder().Count);
                parts.Add("registry " + SecurityAudit.RegistryKey(@"SOFTWARE\OpenSSH").Count);
                parts.Add("services " + (SecurityAudit.Service("sshd").Count + SecurityAudit.Service("ssh-agent").Count));
                parts.Add("public networks " + SecurityAudit.PublicNetworks().Count);
                // A folder that grants Everyone write access must be reported.
                var d = Path.Combine(tmpDir, "open-folder"); Directory.CreateDirectory(d);
                var ds = Directory.GetAccessControl(d); ds.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.WorldSid, null), FileSystemRights.Modify, AccessControlType.Allow)); Directory.SetAccessControl(d, ds);
                if (!SecurityAudit.FileAccess(d, false).Any(x => x.Contains("can modify"))) throw new Exception("Everyone:Modify not detected");
                return "findings: " + string.Join(", ", parts);
            });
            test("key generator, every type (via SSH_ASKPASS)", () =>
            {
                var me = WindowsIdentity.GetCurrent().User; int n = 0; var sw = Stopwatch.StartNew();
                foreach (var t in KeyGen.Types)
                {
                    var path = Path.Combine(tmpDir, "gen" + (++n));
                    var res = KeyGen.Generate(t, path, "selftest " + n, "Selftest-Pass-" + n);
                    if (!res.Encrypted || !KeyGen.IsEncrypted(res.PrivatePath)) throw new Exception(t.Label + ": key not encrypted");
                    if (!KeyGen.PrivateKeyAclOk(res.PrivatePath, me)) throw new Exception(t.Label + ": private key permissions too open");
                    if (!res.Fingerprint.StartsWith("SHA256:")) throw new Exception(t.Label + ": fingerprint " + res.Fingerprint);
                }
                var plain = KeyGen.Generate(KeyGen.Types[0], Path.Combine(tmpDir, "gen-plain"), "selftest plain", null);
                if (plain.Encrypted || KeyGen.IsEncrypted(plain.PrivatePath)) throw new Exception("key without passphrase is encrypted");
                try { KeyGen.Generate(KeyGen.Types[0], plain.PrivatePath, "x", null); throw new Exception("an existing key was overwritten"); } catch (ConfigException) { }
                return (n + 1) + " keys in " + sw.Elapsed.TotalSeconds.ToString("0.0") + " s";
            });
            test("key generator: change, add and remove a passphrase (ssh-keygen -p through SSH_ASKPASS)", () =>
            {
                var res = KeyGen.Generate(KeyGen.Types[0], Path.Combine(tmpDir, "pass-change"), "selftest passphrase", "Selftest-Old-1");
                var before = File.ReadAllBytes(res.PrivatePath);
                try { KeyGen.ChangePassphrase(res.PrivatePath, "Selftest-Wrong-1", "Selftest-New-2"); throw new Exception("changed with a wrong passphrase"); } catch (WrongPassphraseException) { }
                if (!KeyFormats.Equal(File.ReadAllBytes(res.PrivatePath), before)) throw new Exception("a wrong passphrase changed the file");
                KeyGen.ChangePassphrase(res.PrivatePath, "Selftest-Old-1", "Selftest-New-2");
                if (Keys.Blob(KeyGen.DerivePublic(res.PrivatePath, "Selftest-New-2")) != Keys.Blob(res.PublicKey)) throw new Exception("after the change, another key");
                try { KeyGen.DerivePublic(res.PrivatePath, "Selftest-Old-1"); throw new Exception("the old passphrase still opens the key"); } catch (WrongPassphraseException) { }
                KeyGen.ChangePassphrase(res.PrivatePath, "Selftest-New-2", null);
                if (KeyGen.IsEncrypted(res.PrivatePath)) throw new Exception("the passphrase was not removed");
                KeyGen.ChangePassphrase(res.PrivatePath, null, "Selftest-New-3");
                if (!KeyGen.IsEncrypted(res.PrivatePath) || !KeyGen.PrivateKeyAclOk(res.PrivatePath, WindowsIdentity.GetCurrent().User)) throw new Exception("the passphrase was not set, or the file is readable by others");
                var info = KeyGen.Inspect(res.PrivatePath);
                if (!info.Encrypted || info.Format != "OpenSSH" || info.Comment != "selftest passphrase" || Keys.Blob(info.PublicLine) != Keys.Blob(res.PublicKey)) throw new Exception("read back: " + info.Format + ", " + info.Comment);
                return "changed, removed, set";
            });
            test("key generator: export in every format, import from .ppk, read a PEM key", () =>
            {
                var me = WindowsIdentity.GetCurrent().User; var now = new DateTime(2026, 9, 27, 12, 0, 0); var done = new List<string>();
                foreach (var t in KeyGen.Types.Where(x => KeyFormats.PuttyCanUse(x.PublicType) && x.Bits != 4096))
                {
                    var name = t.Type + (t.Bits > 0 ? t.Bits.ToString() : "");
                    var res = KeyGen.Generate(t, Path.Combine(tmpDir, "exp-" + name), "selftest export " + name, "Selftest-Export-1");
                    var info = KeyGen.Inspect(res.PrivatePath);
                    var ppk = Path.Combine(tmpDir, "exp-" + name + ".ppk");
                    KeyGen.Export(info, KeyExportFormat.PuttyV3, ppk, "Selftest-Export-1", "Selftest-Ppk-2", now);
                    if (!KeyGen.PrivateKeyAclOk(ppk, me)) throw new Exception(name + ": the .ppk file is readable by others");
                    var back = KeyGen.ImportPuttyKey(ppk, "Selftest-Ppk-2", Path.Combine(tmpDir, "imp-" + name), "Selftest-Import-3", now);
                    if (Keys.Blob(KeyGen.DerivePublic(back.PrivatePath, "Selftest-Import-3")) != Keys.Blob(res.PublicKey)) throw new Exception(name + ": the key converted back from .ppk is another key");
                    var copy = Path.Combine(tmpDir, "copy-" + name);
                    KeyGen.Export(info, KeyExportFormat.OpenSshPrivate, copy, "Selftest-Export-1", null, now);
                    if (KeyGen.IsEncrypted(copy) || Keys.Blob(KeyGen.DerivePublic(copy, null)) != Keys.Blob(res.PublicKey) || !KeyGen.PrivateKeyAclOk(copy, me)) throw new Exception(name + ": the OpenSSH copy without a passphrase");
                    done.Add(KeyFormats.Describe(Convert.FromBase64String(Keys.Blob(res.PublicKey))));
                }
                var ed = KeyGen.Inspect(Path.Combine(tmpDir, "exp-ed25519"));
                var v2 = Path.Combine(tmpDir, "exp-ed25519-v2.ppk");
                KeyGen.Export(ed, KeyExportFormat.PuttyV2, v2, "Selftest-Export-1", "Selftest-Export-1", now);
                if (PpkFile.Parse(File.ReadAllBytes(v2)).Version != 2) throw new Exception("not a .ppk file of version 2");
                var rfc = Path.Combine(tmpDir, "exp-ed25519-rfc4716.pub");
                KeyGen.Export(ed, KeyExportFormat.Rfc4716Public, rfc, null, null, now);
                if (!File.ReadAllText(rfc).Contains("---- BEGIN SSH2 PUBLIC KEY ----")) throw new Exception("RFC 4716: " + File.ReadAllText(rfc));
                var pub = Path.Combine(tmpDir, "exp-ed25519-public.pub");
                KeyGen.Export(ed, KeyExportFormat.OpenSshPublic, pub, null, null, now);
                var moved = KeyGen.Export(ed, KeyExportFormat.OpenSshPublic, pub, null, null, now).MovedAside;
                if (Keys.Blob(File.ReadAllText(pub).Trim()) != Keys.Blob(ed.PublicLine) || moved.Count != 1 || !File.Exists(moved[0])) throw new Exception("the public key, or the backup of the file it replaced");
                try { KeyGen.Export(ed, KeyExportFormat.PuttyV3, Path.Combine(tmpDir, "wrong.ppk"), "Selftest-Wrong-1", null, now); throw new Exception("exported with a wrong passphrase"); } catch (WrongPassphraseException) { }
                if (File.Exists(Path.Combine(tmpDir, "wrong.ppk"))) throw new Exception("a failed export left a file");
                // The older PEM format (ssh-keygen -m PEM): read through a copy that ssh-keygen rewrites in the OpenSSH format.
                var pem = Path.Combine(tmpDir, "pem-rsa");
                var r = Proc.Run(Ssh.Exe("ssh-keygen.exe"), "-q -t rsa -b 2048 -m PEM -N Selftest-Pem-4 -C selftest-pem -f " + Proc.Quote(pem), 60000);
                if (!r.Ok) throw new Exception("ssh-keygen -m PEM: " + r.Output);
                try { KeyGen.Inspect(pem); throw new Exception("an encrypted PEM key was shown without its passphrase (from its .pub file)"); } catch (WrongPassphraseException) { }
                var pi = KeyGen.Inspect(pem, "Selftest-Pem-4");
                if (!pi.Format.StartsWith("PEM") || !pi.Encrypted || pi.Comment != "selftest-pem") throw new Exception("PEM key read as " + pi.Format + (pi.Encrypted ? "" : ", without a passphrase") + ", comment " + pi.Comment);
                var pk = KeyGen.ReadPrivate(pem, "Selftest-Pem-4");
                if (Convert.ToBase64String(pk.PublicBlob) != Keys.Blob(pi.PublicLine)) throw new Exception("the PEM key read in memory is another key");
                var pemCopy = Path.Combine(tmpDir, "pem-rsa-openssh");
                KeyGen.Export(pi, KeyExportFormat.OpenSshPrivate, pemCopy, "Selftest-Pem-4", "Selftest-Pem-4", now);
                if (!OpenSshKeyFile.IsOpenSsh(File.ReadAllText(pemCopy)) || Keys.Blob(KeyGen.DerivePublic(pemCopy, "Selftest-Pem-4")) != Keys.Blob(pi.PublicLine)) throw new Exception("the PEM key exported as an OpenSSH key");
                return string.Join(", ", done) + "; .ppk 2 and 3, RFC 4716, PEM";
            });
            test("key dialogs: create a key, change its passphrase and export it as a user would, refusals included", () =>
            {
                var dir = Path.Combine(tmpDir, "dialogs"); Directory.CreateDirectory(dir);
                var path = Path.Combine(dir, "id_dialog");
                Action<Form> place = f => { f.StartPosition = FormStartPosition.Manual; f.Location = new Point(-20000, -20000); f.ShowInTaskbar = false; f.Show(); Application.DoEvents(); };
                KeyGenResult made = null;
                using (var d = new NewKeyDialog(x => made = KeyGen.GenerateReplacing(x.KeyType, x.PrivatePath, x.Comment, x.Passphrase, DateTime.Now)))
                {
                    place(d);
                    d.TypeForTest("Private key file", path); d.TypeForTest("Passphrase", "Dialog-pass-1"); d.TypeForTest("Confirm passphrase", "Dialog-pass-X");
                    d.OkForTest();
                    if (made != null || d.LastError == null || !d.LastError.Contains("do not match")) throw new Exception("two different passphrases: " + (d.LastError ?? "accepted"));
                    d.TypeForTest("Confirm passphrase", "Dialog-pass-1"); d.OkForTest();
                    if (made == null || d.DialogResult != DialogResult.OK) throw new Exception("not created: " + d.LastError);
                }
                var info = KeyGen.Inspect(path);
                using (var d = new PassphraseChangeDialog(info, x => KeyGen.ChangePassphrase(info.Path, x.OldPassphrase, x.NewPassphrase)))
                {
                    place(d);
                    d.TypeForTest("Current passphrase", "Dialog-wrong-1"); d.TypeForTest("New passphrase", "Dialog-pass-2"); d.TypeForTest("Confirm the new passphrase", "Dialog-pass-2");
                    d.OkForTest();
                    if (d.DialogResult == DialogResult.OK || d.LastError != "Wrong passphrase.") throw new Exception("a wrong current passphrase: " + (d.LastError ?? "accepted"));
                    d.TypeForTest("Current passphrase", "Dialog-pass-1"); d.OkForTest();
                    if (d.DialogResult != DialogResult.OK) throw new Exception("not changed: " + d.LastError);
                }
                KeyGen.DerivePublic(path, "Dialog-pass-2");
                var ppk = Path.Combine(dir, "id_dialog.ppk");
                using (var d = new KeyExportDialog(info, x => KeyGen.Export(info, x.Format, x.Target, x.CurrentPassphrase, x.NewPassphrase, DateTime.Now)))
                {
                    place(d);
                    d.TickForTest("PuTTY private key, .ppk version 3"); d.TypeForTest("File to export to", ppk);
                    d.OkForTest();
                    if (d.DialogResult == DialogResult.OK || d.LastError == null || !d.LastError.StartsWith("Enter the current passphrase")) throw new Exception("no current passphrase: " + (d.LastError ?? "accepted"));
                    d.TypeForTest("Current passphrase of the key", "Dialog-pass-2"); d.OkForTest();
                    if (d.DialogResult != DialogResult.OK) throw new Exception("not exported: " + d.LastError);
                }
                var k = PpkFile.Parse(File.ReadAllBytes(ppk)).Decrypt("Dialog-pass-2"); // "The same as the key's", the default
                if (Convert.ToBase64String(k.PublicBlob) != Keys.Blob(made.PublicKey)) throw new Exception("the .ppk file holds another key");
                return null;
            });
            test("host key listing", () => { var l = HostKeys.List(); return l.Count + " key(s)"; });
            test("service status", () => { var s = Services.Status("sshd"); if (!s.Exists) throw new Exception("sshd service not installed"); return s.Status + "/" + s.StartMode; });
            test("listeners and sessions", () => { var c = SshdConfig.Load(); return Net.Listeners(c.EffectivePort).Count + " listener(s), " + Net.Sessions(c.EffectivePort).Count + " session(s)"; });
            test("banner", () => { var c = SshdConfig.Load(); var b = Net.Banner(c.EffectivePort); if (!b.StartsWith("SSH-")) throw new Exception(b); return b; });
            test("firewall API", () => { var f = Firewall.Get(); return f == null ? "no rule" : f.Name + " " + (f.Enabled ? "enabled" : "disabled") + " " + f.ProfilesText; });
            test("event log API", () => { var l = EventLogs.Read(5, null); return l.Count + " event(s)"; });
            test("default shell registry", () => DefaultShell.Get() ?? "(cmd.exe)");
            test("effective settings (sshd -T)", () => { string err; var d = Ssh.EffectiveSettings(out err); if (d.Count < 20) throw new Exception("only " + d.Count + " values: " + err); return d.Count + " values"; });
            test("hardening checks", () => Hardening.Run(SshdConfig.Load()).Count + " checks");
            test("service PID lookup", () => { var s = Services.Status("sshd"); return s.Status == "Running" ? (s.Pid > 0 ? "PID " + s.Pid : "running but no PID") : "service " + s.Status; });
            test("profile list (registry)", () => { var p = Keys.UserProfiles(); if (p.Count == 0) throw new Exception("no user profiles found"); var sid = Keys.SidOfProfile(p[0]); return p.Count + " profile(s), first " + p[0] + (sid == null ? " (SID unknown)" : " " + sid.Value); });
            test("SFTP: sshd reads the SFTP-only rules as the SFTP tab writes them (sshd -T)", () =>
            {
                if (!Elevation.IsAdministrator()) return "skipped: not elevated";
                string err;
                var me = Accounts.Canonical(KeyGen.LoginName(), false, out err);
                if (me == null) throw new Exception(err);
                var baseCfg = SshdConfig.Load();
                int port = baseCfg.EffectivePort;
                var p = Path.Combine(tmpDir, "sftp.conf");
                Func<List<SftpRule>, Dictionary<string, string>> eff = rules =>
                {
                    var c = new SshdConfig { Lines = baseCfg.Lines.ToList(), NewLine = baseCfg.NewLine, Path = p };
                    // The SFTP tab refuses a hand-edited section; a live file with one is not this test's subject.
                    if (SftpConfig.Read(c).RulesProblem != null) c = DefaultLike();
                    SftpConfig.Apply(c, true, true, rules);
                    File.WriteAllText(p, c.Text, new UTF8Encoding(false));
                    var t = Ssh.TestConfig(p); if (!t.Ok) throw new Exception("sshd -t: " + t.Output);
                    var lines = AuthConfig.EffectiveLinesFor(me, p, port, out err);
                    if (lines == null) throw new Exception(err);
                    var d = new Dictionary<string, string>();
                    foreach (var kv in lines) if (!d.ContainsKey(kv.Key) || kv.Key == "subsystem" && kv.Value.StartsWith("sftp ")) d[kv.Key] = kv.Value;
                    return d;
                };
                Func<Dictionary<string, string>, string, string> v = (d, k) => { string x; return d.TryGetValue(k, out x) ? x : ""; };
                var mine = eff(new List<SftpRule> { new SftpRule { Name = me, Folder = "C:\\SFTP Test\\%u", ReadOnly = true } });
                if (v(mine, "forcecommand") != "internal-sftp -l INFO -R") throw new Exception("forcecommand " + v(mine, "forcecommand"));
                if (v(mine, "chrootdirectory") != "C:\\SFTP Test\\%u") throw new Exception("chrootdirectory " + v(mine, "chrootdirectory"));
                if (v(mine, "subsystem") != "sftp sftp-server.exe -l INFO") throw new Exception("subsystem " + v(mine, "subsystem"));
                foreach (var k in SftpConfig.Locks) if (v(mine, k.ToLowerInvariant()) != "no") throw new Exception(k + " " + v(mine, k.ToLowerInvariant()));
                var other = eff(new List<SftpRule> { new SftpRule { Name = "osm-no-such-user", Folder = "C:\\SFTP\\%u" } });
                if (v(other, "forcecommand").StartsWith("internal-sftp") || v(other, "permittty") == "no") throw new Exception("a rule for another account applied");
                return me + ": " + v(mine, "forcecommand") + ", " + v(mine, "chrootdirectory");
            });
            test("SFTP: a folder made for an account is its own, and the parents made for it are closed", () =>
            {
                if (!Elevation.IsAdministrator()) return "skipped: not elevated";
                var users = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);
                var root = Path.Combine(tmpDir, "sftp-root"); var leaf = Path.Combine(root, "contoso", "bob");
                SftpConfig.PrepareFolder(leaf, users, false);
                Func<string, List<string>> grants = p => Directory.GetAccessControl(p).GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>()
                    .Where(r => r.AccessControlType == AccessControlType.Allow).Select(r => ((SecurityIdentifier)r.IdentityReference).Value + ":" + r.FileSystemRights).ToList();
                if (!Directory.GetAccessControl(leaf).GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().Any(r => users.Equals(r.IdentityReference) && (r.FileSystemRights & FileSystemRights.Modify) == FileSystemRights.Modify))
                    throw new Exception("the account has no modify rights on its folder: " + string.Join(", ", grants(leaf)));
                foreach (var p in new[] { root, Path.Combine(root, "contoso") })
                {
                    var g = grants(p);
                    if (g.Any(x => x.StartsWith(users.Value + ":"))) throw new Exception("the account got rights on the parent " + p + ": " + string.Join(", ", g));
                    if (!Directory.GetAccessControl(p).AreAccessRulesProtected) throw new Exception("the parent " + p + " inherits permissions");
                }
                if (SftpConfig.PrepareFolder(leaf, users, false).IndexOf("exists, with access", StringComparison.Ordinal) < 0) throw new Exception("a second run changed the folder");
                var open = Path.Combine(tmpDir, "sftp-open"); Directory.CreateDirectory(open);
                var ds = Directory.GetAccessControl(open); ds.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.WorldSid, null), FileSystemRights.ReadAndExecute, AccessControlType.Allow)); Directory.SetAccessControl(open, ds);
                var note = SftpConfig.FolderNote(open, users);
                if (note == null || note.IndexOf("also open to", StringComparison.Ordinal) < 0) throw new Exception("a folder open to Everyone gave no note: " + note);
                return note;
            });
            test("login methods: sshd applies the rules in order (sshd -T)", () =>
            {
                if (!Elevation.IsAdministrator()) return "skipped: not elevated";
                string err;
                var me = Accounts.Canonical(KeyGen.LoginName(), false, out err);
                if (me == null) throw new Exception(err);
                if (me != Accounts.AsciiLower(KeyGen.LoginName())) throw new Exception("name in sshd's form " + me + " differs from the login name " + KeyGen.LoginName());
                var admins = Accounts.Canonical(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null).Translate(typeof(NTAccount)).Value, true, out err);
                if (admins == null) throw new Exception(err);
                var baseCfg = SshdConfig.Load();
                int port = baseCfg.EffectivePort;
                var p = Path.Combine(tmpDir, "auth.conf");
                Func<AuthMethods, List<AuthRule>, AuthMethods> eff = (g, r) =>
                {
                    var c = new SshdConfig { Lines = baseCfg.Lines.ToList(), NewLine = baseCfg.NewLine, Path = p };
                    AuthConfig.Apply(c, g, r);
                    File.WriteAllText(p, c.Text, new UTF8Encoding(false));
                    var t = Ssh.TestConfig(p); if (!t.Ok) throw new Exception("sshd -t: " + t.Output);
                    string e; var m = AuthConfig.EffectiveFor(me, p, port, out e);
                    if (m == null) throw new Exception(e);
                    return m;
                };
                var pwOnly = new AuthMethods { PublicKey = false };
                var keyOnly = new AuthMethods { Password = false };
                var both = new AuthMethods { RequireBoth = true };
                if (!eff(pwOnly, new List<AuthRule>()).SameAs(pwOnly)) throw new Exception("methods for all accounts not applied");
                if (!eff(pwOnly, new List<AuthRule> { new AuthRule { IsGroup = true, Name = admins, Methods = keyOnly } }).SameAs(keyOnly)) throw new Exception("group rule not applied");
                if (!eff(pwOnly, new List<AuthRule> { new AuthRule { Name = me, Methods = both }, new AuthRule { IsGroup = true, Name = admins, Methods = keyOnly } }).SameAs(both)) throw new Exception("the first matching rule (user) did not win");
                if (!eff(pwOnly, new List<AuthRule> { new AuthRule { IsGroup = true, Name = admins, Methods = keyOnly }, new AuthRule { Name = me, Methods = both } }).SameAs(keyOnly)) throw new Exception("the first matching rule (group) did not win");
                if (!eff(keyOnly, new List<AuthRule> { new AuthRule { Name = "osm-no-such-user", Methods = pwOnly } }).SameAs(keyOnly)) throw new Exception("a rule for another account applied");
                return me + ", group " + admins;
            });
            test("account names in sshd's form", () =>
            {
                string err;
                var users = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null).Translate(typeof(NTAccount)).Value;
                var g = Accounts.Canonical(users, true, out err);
                if (g == null || g.Contains("\\") || g != Accounts.AsciiLower(g)) throw new Exception("built-in group " + users + ": " + (g ?? err));
                if (Accounts.Canonical(users, false, out err) != null) throw new Exception("a group was accepted as a user");
                var everyone = new SecurityIdentifier(WellKnownSidType.WorldSid, null).Translate(typeof(NTAccount)).Value;
                if (Accounts.Canonical(everyone, true, out err) != null) throw new Exception("the well-known group " + everyone + " was accepted");
                if (Accounts.Canonical("osm-no-such-" + Guid.NewGuid().ToString("N").Substring(0, 8), false, out err) != null) throw new Exception("a missing account was accepted");
                if (Accounts.Canonical("bad,name", false, out err) != null || Accounts.Canonical("adm*", true, out err) != null || Accounts.Canonical("!x", false, out err) != null || Accounts.Canonical("x%PATH%", false, out err) != null) throw new Exception("pattern characters were accepted");
                if (SystemTasks.SshdTest(Ssh.ConfigPath, "user=x%PATH%,host=localhost", 1000).Ok) throw new Exception("% reached the SYSTEM check");
                var login = KeyGen.LoginName();
                if (login.IndexOf('\\') < 0)
                {
                    var viaMachine = Accounts.Canonical(Environment.MachineName + "\\" + login, false, out err);
                    if (viaMachine != Accounts.AsciiLower(login)) throw new Exception("COMPUTER\\name of a local account gives " + (viaMachine ?? err));
                }
                return g + "; " + Accounts.LocalUsers().Count + " local user(s), " + Accounts.LocalGroups().Count + " local group(s), domain member: " + Accounts.DomainJoined();
            });
            test("sshd -T as SYSTEM (one-off scheduled task)", () =>
            {
                if (!Elevation.IsAdministrator()) return "skipped: not elevated";
                var me = Accounts.AsciiLower(KeyGen.LoginName());
                var spec = "user=" + me + ",host=localhost,addr=127.0.0.1,laddr=127.0.0.1,lport=" + SshdConfig.Load().EffectivePort;
                var sw = Stopwatch.StartNew();
                var sys = SystemTasks.SshdTest(Ssh.ConfigPath, spec, 60000);
                if (!sys.Ok) throw new Exception(sys.Output);
                var direct = Proc.Run(Ssh.Exe("sshd.exe"), "-T -C " + Proc.Quote(spec), 20000);
                Func<string, string, string> val = (text, key) => { var m = Regex.Match(text, "^" + key + @"\s+(.+?)\s*$", RegexOptions.Multiline | RegexOptions.IgnoreCase); return m.Success ? m.Groups[1].Value : null; };
                foreach (var k in new[] { "passwordauthentication", "pubkeyauthentication", "authorizedkeysfile", "authenticationmethods", "allowgroups" })
                    if (val(sys.StdOut, k) != val(direct.StdOut, k)) throw new Exception(k + ": as SYSTEM " + val(sys.StdOut, k) + ", as administrator " + val(direct.StdOut, k));
                var left = Directory.GetDirectories(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "osm-check-*");
                if (left.Length > 0) throw new Exception("left behind: " + string.Join(", ", left));
                return "same answer for " + me + " in " + sw.Elapsed.TotalSeconds.ToString("0.0") + " s";
            });
            test("scheduled tasks: SYSTEM task definitions are staged where only administrators can write", () =>
            {
                if (!Elevation.IsAdministrator()) return "skipped: not elevated";
                var dir = SystemTasks.StagingDir(Guid.NewGuid().ToString("N"));
                Acl.CreatePrivateFolder(dir);
                try { ConfigurationRecovery.RequireTrustedPath(dir); }
                finally { Directory.Delete(dir, true); }
                return null;
            });
            test("login methods: lock-out warning for the current account", () =>
            {
                if (!Elevation.IsAdministrator()) return "skipped: not elevated";
                var baseCfg = SshdConfig.Load();
                var me = Accounts.AsciiLower(KeyGen.LoginName());
                // Counted as LockoutWarning counts: every configured file, usable keys only.
                int keys = 0; try { keys = Keys.UsableCount(Ssh.AuthorizedKeysFilesFor(me, Environment.GetFolderPath(Environment.SpecialFolder.UserProfile))); } catch { }
                Func<AuthMethods, string> warn = g =>
                {
                    var c = new SshdConfig { Lines = baseCfg.Lines.ToList(), NewLine = baseCfg.NewLine };
                    AuthConfig.Apply(c, g, new List<AuthRule>());
                    var p = Path.Combine(tmpDir, "lockout.conf"); File.WriteAllText(p, c.Text, new UTF8Encoding(false));
                    return AuthConfig.LockoutWarning(p, baseCfg.EffectivePort);
                };
                if (warn(new AuthMethods()) != null) throw new Exception("warning although Windows authentication stays on");
                var keyOnly = warn(new AuthMethods { Password = false });
                if ((keys == 0) != (keyOnly != null)) throw new Exception(keys + " key(s) authorized, warning: " + (keyOnly ?? "none"));
                if (warn(new AuthMethods { RequireBoth = true }) == null && keys == 0) throw new Exception("no warning for key and password required without a key");
                if (warn(new AuthMethods { Password = false, PublicKey = false, Kerberos = true }) == null && !Accounts.DomainJoined()) throw new Exception("no warning for Kerberos only outside a domain");
                return keys + " key(s) authorized for " + me + (keyOnly != null ? "; public key only would lock you out and is warned about" : "");
            });
            test("login methods offered by the running server", () =>
            {
                if (!Elevation.IsAdministrator()) return "skipped: not elevated";
                var c = SshdConfig.Load(); string err;
                var me = Accounts.AsciiLower(KeyGen.LoginName());
                var expected = AuthConfig.EffectiveFor(me, null, c.EffectivePort, out err);
                if (expected == null) throw new Exception(err);
                var offered = AuthConfig.Probe(me, "localhost", c.EffectivePort, out err);
                if (offered == null) throw new Exception(err);
                if (!offered.SetEquals(expected.Offered())) throw new Exception("the server offers " + string.Join(",", offered) + ", sshd -T gives " + string.Join(",", expected.Offered()) + " (sshd_config changed without a restart?)");
                return string.Join(",", offered);
            });
            test("window: a rejected Settings save changes nothing", () =>
            {
                string detail = null;
                WithTestWindow(tmpDir, "Port 22\nPermitEmptyPasswords no\n", f =>
                {
                    // Permit empty passwords is written first; the bad number then stops the save.
                    f.SetSettingForTest("PermitEmptyPasswords", "yes");
                    f.SetSettingForTest("MaxAuthTries", "abc");
                    detail = f.SaveSettingsForTest();
                    if (detail == null) throw new Exception("MaxAuthTries abc was saved");
                    if (f.WorkingValueForTest("PermitEmptyPasswords") != "no") throw new Exception("after \"" + detail + "\" the working configuration has PermitEmptyPasswords " + f.WorkingValueForTest("PermitEmptyPasswords") + "; the next save of another tab would write it");
                    if (f.AuthCandidateForTest().Get("PermitEmptyPasswords") != "no") throw new Exception("Apply on the Authentication tab would write the rejected PermitEmptyPasswords yes");
                });
                return "rejected: " + detail;
            });
            test("window: reloading sshd_config refreshes the Authentication tab", () =>
            {
                Func<string, string> withRule = name =>
                {
                    var c = new SshdConfig { Lines = new List<string> { "Port 22" } };
                    AuthConfig.Apply(c, new AuthMethods(), new List<AuthRule> { new AuthRule { Name = name, Methods = new AuthMethods { Password = false } } });
                    return c.Text;
                };
                WithTestWindow(tmpDir, withRule("bob"), f =>
                {
                    File.WriteAllText(Ssh.ConfigPath, withRule("carol"), new UTF8Encoding(false)); // changed outside the window
                    f.ReloadFromFileForTest();
                    var rules = AuthConfig.Read(f.AuthCandidateForTest()).Rules.Select(r => r.Name).ToList();
                    if (!rules.SequenceEqual(new[] { "carol" })) throw new Exception("after Reload, Apply on the Authentication tab would write the rules " + string.Join(", ", rules) + " instead of carol from the file");
                });
                return null;
            });
            test("window: login-method changes survive a reload unless the file's methods changed", () =>
            {
                WithTestWindow(tmpDir, "Port 22\nPasswordAuthentication yes\n", f =>
                {
                    f.TickPasswordForTest(false);
                    File.WriteAllText(Ssh.ConfigPath, "Port 2222\nPasswordAuthentication yes\n", new UTF8Encoding(false)); // another setting changed
                    f.ReloadFromFileForTest();
                    if (!f.AuthEditedForTest() || f.AuthCandidateForTest().Get("PasswordAuthentication") != "no") throw new Exception("the change on the Authentication tab was lost although the file's login methods did not change");
                    if (f.AuthCandidateForTest().Get("Port") != "2222") throw new Exception("Apply would not start from the reloaded file");
                    File.WriteAllText(Ssh.ConfigPath, "Port 2222\nPasswordAuthentication yes\nPubkeyAuthentication no\n", new UTF8Encoding(false)); // login methods changed
                    f.ReloadFromFileForTest();
                    if (f.AuthEditedForTest()) throw new Exception("the tab kept its changes over login methods changed in the file");
                });
                return null;
            });
            test("window: SFTP changes wait for Apply, and survive a reload unless the file's SFTP settings changed", () =>
            {
                WithTestWindow(tmpDir, "Port 22\nSubsystem\tsftp\tsftp-server.exe\n", f =>
                {
                    if (f.SftpEditedForTest()) throw new Exception("a fresh SFTP tab reports changes");
                    f.ShowSftpExampleForTest(); // logging on and two SFTP-only rules, in the window only
                    if (!f.SftpEditedForTest() || !f.UnsavedTabsForTest().Contains("the SFTP tab") || !f.TabNamesForTest().Contains("SFTP *")) throw new Exception("the SFTP changes are not marked as not applied");
                    if (File.ReadAllText(Ssh.ConfigPath).Contains(SftpConfig.RegionBegin) || f.WorkingValueForTest("Port") != "22") throw new Exception("an edit on the SFTP tab reached the file or the working configuration");
                    var cand = SftpConfig.Read(f.SftpCandidateForTest());
                    if (cand.Rules.Count != 2 || !cand.LogTransfers) throw new Exception("Apply would write " + cand.Rules.Count + " rule(s), logging " + cand.LogTransfers);
                    File.WriteAllText(Ssh.ConfigPath, "Port 2222\nSubsystem\tsftp\tsftp-server.exe\n", new UTF8Encoding(false)); // another setting changed
                    f.ReloadFromFileForTest();
                    if (!f.SftpEditedForTest() || f.SftpCandidateForTest().Get("Port") != "2222") throw new Exception("the SFTP changes were lost, or Apply would not start from the reloaded file");
                    File.WriteAllText(Ssh.ConfigPath, "Port 2222\n", new UTF8Encoding(false)); // SFTP switched off in the file
                    f.ReloadFromFileForTest();
                    if (f.SftpEditedForTest()) throw new Exception("the tab kept its changes over SFTP settings changed in the file");
                });
                return null;
            });
            test("window: no clipped text at 100% and 150% on a 1024 x 768 screen", () =>
            {
                // Windows keeps a window within the screen: on the smallest screen the window is narrower than its minimum size.
                var report = new List<string>();
                foreach (var s in new[] { 1f, 1.5f })
                {
                    var old = Ui.Scale; Ui.Scale = s;
                    try
                    {
                        WithTestWindow(tmpDir, "Port 22\n", f =>
                        {
                            f.MinimumSize = Size.Empty; f.Size = new Size(1024, 768); Application.DoEvents();
                            report.AddRange(f.ClippedTextForTest().Select(x => (int)(s * 100) + "%: " + x));
                        });
                    }
                    finally { Ui.Scale = old; }
                }
                if (report.Count > 0) throw new Exception(report.Count + " place(s): " + string.Join(" | ", report.Take(15)) + (report.Count > 15 ? " | ..." : ""));
                return null;
            });
            test("firewall rule found by name, also from a background thread", () =>
            {
                if (!Elevation.IsAdministrator()) return "skipped: not elevated";
                // A disabled inbound rule of its own (it opens no port), removed at the end.
                var name = "OpenSSH Server PN Manager selftest " + Guid.NewGuid().ToString("N").Substring(0, 8);
                dynamic policy = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));
                dynamic rule = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule"));
                rule.Name = name; rule.Direction = 1; rule.Action = 1; rule.Enabled = false; rule.Protocol = 6; rule.LocalPorts = "65001"; rule.Profiles = 2;
                policy.Rules.Add(rule);
                try
                {
                    FirewallRule onWindowThread = Firewall.Get(name), onOther = null; long ms = 0;
                    var th = new Thread(() => { var sw = Stopwatch.StartNew(); onOther = Firewall.Get(name); ms = sw.ElapsedMilliseconds; });
                    th.SetApartmentState(ApartmentState.STA); th.Start();
                    if (!th.Join(60000)) throw new Exception("the lookup on a background thread took more than a minute");
                    foreach (var r in new[] { onWindowThread, onOther })
                        if (r == null || r.Enabled || r.Ports != "65001" || r.Profiles != 2) throw new Exception("rule read as " + (r == null ? "missing" : (r.Enabled ? "enabled" : "disabled") + ", ports " + r.Ports + ", profiles " + r.Profiles));
                    if (Firewall.Get("OpenSSH Server PN Manager no such rule " + Guid.NewGuid().ToString("N")) != null) throw new Exception("a missing rule was found");
                    return "background thread: " + ms + " ms";
                }
                finally { try { policy.Rules.Remove(name); } catch { } }
            });
            test("window: the dashboard refreshes in the background", () =>
            {
                string detail = null;
                WithTestWindow(tmpDir, "Port 22\n", f =>
                {
                    var t = f.BackgroundRefreshForTest();
                    detail = "on the window's thread: " + t[0].TotalMilliseconds.ToString("0") + " ms refreshing there, " + t[1].TotalMilliseconds.ToString("0.0") + " ms to start it in the background";
                    if (t[1].TotalMilliseconds > 100) throw new Exception(detail);
                });
                return detail;
            });
            test("window: unsaved changes are marked, kept when another tab saves, and listed on close", () =>
            {
                WithTestWindow(tmpDir, "Port 22\nMaxAuthTries 6\n", f =>
                {
                    if (f.UnsavedTabsForTest().Count != 0) throw new Exception("a window just opened reports unsaved changes: " + string.Join(", ", f.UnsavedTabsForTest()));
                    f.SetSettingForTest("MaxAuthTries", "3");
                    if (f.TabName(2) != "Settings *") throw new Exception("the Settings tab is not marked: " + f.TabName(2));
                    f.SetRawTextForTest(f.RawTextForTest() + "# my note\r\n");
                    File.WriteAllText(Ssh.ConfigPath, "Port 2222\nMaxAuthTries 6\n", new UTF8Encoding(false));
                    f.OtherTabSavedForTest();
                    if (f.FieldTextForTest("MaxAuthTries") != "3") throw new Exception("the typed Max auth tries was replaced when another tab saved");
                    if (f.WorkingValueForTest("Port") != "2222") throw new Exception("the saved file was not adopted");
                    if (!f.RawTextForTest().Contains("# my note") || f.RawNoteForTest().IndexOf("another tab", StringComparison.Ordinal) < 0) throw new Exception("the text tab lost its edit, or did not say the file changed: " + f.RawNoteForTest());
                    var unsaved = f.UnsavedTabsForTest();
                    if (unsaved.Count != 2) throw new Exception("closing would list: " + string.Join(", ", unsaved));
                    f.ReloadFromFileForTest(); // Reload on the Settings tab
                    if (f.SettingsEditedForTest() || f.TabName(2) != "Settings" || f.FieldTextForTest("MaxAuthTries") != "6") throw new Exception("Reload on the Settings tab did not show the file");
                    if (!f.RawEditedForTest()) throw new Exception("Reload on the Settings tab discarded the edit on the text tab");
                });
                return null;
            });
            test("window: fields are checked as they are typed", () =>
            {
                WithTestWindow(tmpDir, "Port 22\n", f =>
                {
                    f.SetSettingForTest("MaxAuthTries", "abc");
                    if (f.FieldErrorForTest("MaxAuthTries").Length == 0) throw new Exception("no error for Max auth tries abc");
                    f.SetSettingForTest("MaxAuthTries", "4");
                    if (f.FieldErrorForTest("MaxAuthTries").Length != 0) throw new Exception("an error stays after correcting it: " + f.FieldErrorForTest("MaxAuthTries"));
                    f.SetSettingForTest("AllowUsers", "\"openssh users");
                    if (f.FieldErrorForTest("AllowUsers").Length == 0) throw new Exception("no error for an unclosed quotation mark");
                });
                return null;
            });
            test("window: the program icon in the title bar and on the About tab", () =>
            {
                WithTestWindow(tmpDir, "Port 22\n", f =>
                {
                    if (Ui.AppIcon == null || !ReferenceEquals(f.Icon, Ui.AppIcon)) throw new Exception("the window does not use the program icon");
                    if (!f.HasAboutIconForTest()) throw new Exception("the About tab does not show the program icon");
                });
                return null;
            });
            test("window: every input and list has a name for screen readers", () =>
            {
                List<string> unnamed = null;
                WithTestWindow(tmpDir, "Port 22\n", f => unnamed = f.UnnamedInputsForTest());
                if (unnamed.Count > 0) throw new Exception(unnamed.Count + " without a name: " + string.Join(", ", unnamed));
                return null;
            });
            test("window: Settings writes the first Port only, all AllowUsers lines as one, and never over a file changed meanwhile", () =>
            {
                // A host key of its own, so that sshd -t works without administrator rights.
                var dir = Path.Combine(tmpDir, "window-hostkey"); Directory.CreateDirectory(dir);
                var hk = KeyGen.Generate(KeyGen.Types[0], Path.Combine(dir, "host_key"), "selftest host key", null);
                string detail = null;
                WithTestWindow(tmpDir, "HostKey " + SshdArgs.Quote(hk.PrivatePath) + "\nPort 22\nPort 2222\nAllowUsers alice\nAllowUsers bob\n", f =>
                {
                    if (f.FieldTextForTest("AllowUsers") != "alice bob") throw new Exception("AllowUsers shows [" + f.FieldTextForTest("AllowUsers") + "], not both lines");
                    f.SetSettingForTest("Port", "2200");
                    f.SetSettingForTest("AllowUsers", "alice bob carol");
                    var err = f.SaveSettingsForTest(); if (err != null) throw new Exception("not saved: " + err);
                    var text = File.ReadAllText(Ssh.ConfigPath);
                    if (!text.Contains("Port 2200\n") || !text.Contains("\nPort 2222\n")) throw new Exception("ports: " + text.Replace("\n", " | "));
                    if (!text.Contains("AllowUsers alice bob carol\n") || !text.Contains("#AllowUsers bob")) throw new Exception("AllowUsers: " + text.Replace("\n", " | "));
                    if (SshdConfig.ListBackups(Ssh.ConfigPath).Count != 1) throw new Exception("no backup was kept");
                    File.WriteAllText(Ssh.ConfigPath, text + "# edited in Notepad\n", new UTF8Encoding(false)); // changed outside the window
                    f.SetSettingForTest("MaxAuthTries", "3");
                    detail = f.SaveSettingsForTest();
                    var after = File.ReadAllText(Ssh.ConfigPath);
                    if (detail == null || !after.Contains("# edited in Notepad") || after.Contains("MaxAuthTries 3")) throw new Exception("the file changed outside the window was written over");
                });
                return "refused: " + detail;
            });
            test("window: the changes shown before a save mark added and removed lines", () =>
            {
                using (var d = new ChangesDialog("Changes to sshd_config", "test", "a\nb\nc\n", "a\nB\nc\nd\n", "Save") { StartPosition = FormStartPosition.Manual, Location = new Point(-20000, -20000), ShowInTaskbar = false })
                {
                    d.Show(); Application.DoEvents();
                    var text = d.DiffTextForTest.Replace("\r", "");
                    if (text != "  a\n- b\n+ B\n  c\n+ d\n") throw new Exception("shown as [" + text.Replace("\n", "|") + "]");
                    // Under high contrast both backgrounds are the window colour: only the + and - tell the lines apart.
                    if (!Theme.Current.HighContrast && (d.LineBackForTest("+ B").ToArgb() != Theme.Current.Added.ToArgb() || d.LineBackForTest("- b").ToArgb() != Theme.Current.Removed.ToArgb())) throw new Exception("line colours: " + d.LineBackForTest("+ B") + ", " + d.LineBackForTest("- b"));
                    d.Close();
                }
                return null;
            });
            test("window: the dark palette reaches lists, buttons and text boxes; light gives the Windows look back", () =>
            {
                if (SystemInformation.HighContrast) return "skipped: high contrast is on (its colours are always used)";
                string detail = null;
                WithTestWindow(tmpDir, "Port 22\n", f =>
                {
                    bool owner; FlatStyle style;
                    var dark = f.ThemeForTest("dark", out owner, out style); var p = Theme.Make(true, false);
                    if (dark[0] != p.Surface || dark[1] != p.Surface || dark[2] != p.Back || !owner || style != FlatStyle.Flat) throw new Exception("dark: list " + dark[0] + ", text box " + dark[1] + ", window " + dark[2] + ", owner-drawn headers " + owner + ", buttons " + style);
                    var light = f.ThemeForTest("light", out owner, out style);
                    if (light[0] != SystemColors.Window || light[1] != SystemColors.Window || light[2] != SystemColors.Control || owner || style != FlatStyle.Standard) throw new Exception("light: list " + light[0] + ", text box " + light[1] + ", window " + light[2] + ", owner-drawn headers " + owner + ", buttons " + style);
                    detail = string.Join(", ", f.TabNamesForTest());
                });
                return detail;
            });
            test("profile removal task: script for a profile that does not exist", () =>
            {
                // No profile has this SID: the script must end at once with 0 (and try to delete its task, which does not exist).
                var script = SystemTasks.ProfileRemovalScript("S-1-5-21-1-2-3-999999", "OpenSSH Server PN Manager selftest no such task " + Guid.NewGuid().ToString("N").Substring(0, 8));
                var ps = Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe");
                var sw = Stopwatch.StartNew();
                var r = Proc.Run(ps, "-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand " + Convert.ToBase64String(Encoding.Unicode.GetBytes(script)), 60000);
                if (r.TimedOut || r.ExitCode != 0) throw new Exception("exit " + r.ExitCode + (r.TimedOut ? " (timed out)" : "") + ": " + r.Output);
                return "exit 0 in " + sw.Elapsed.TotalSeconds.ToString("0.0") + " s";
            });
            test("service ImagePath (registry)", () => { var img = Services.ImagePath("sshd"); return img == null ? "sshd service not registered" : "sshd: " + img; });
            test("server accepts ML-DSA keys", () => KeyGen.ServerAccepts("ssh-mldsa44-ed25519@openssh.com") ? "yes" : "no (default)");
            test("restart needed (live sshd)", () => Services.ChangedSinceStart(Services.Status("sshd"), Ssh.ConfigPath) ? "sshd_config was saved after sshd started" : "sshd runs the saved sshd_config");
            test("sshd reads rule names as written (sshd -T, random names)", () =>
            {
                // A configuration and host key of its own, so that no administrator rights are needed.
                var dir = Path.Combine(tmpDir, "names"); Directory.CreateDirectory(dir);
                var hk = KeyGen.Generate(KeyGen.Types[0], Path.Combine(dir, "host_key"), "selftest host key", null);
                var names = new[] { "o'brien", "contoso\\'neil", "contoso\\bob", "o'brien smith" }.Concat(RandomNames(7, 40, true)).Distinct().ToList();
                var p = Path.Combine(dir, "sshd_config");
                Func<string, string> pw = user =>
                {
                    var r = Proc.Run(Ssh.Exe("sshd.exe"), "-T -f " + Proc.Quote(p) + " -C " + Proc.Quote("user=" + user + ",host=localhost,addr=127.0.0.1"), 20000);
                    if (!r.Ok) throw new Exception("sshd -T for [" + user + "]: " + r.Output);
                    var m = Regex.Match(r.StdOut, @"^passwordauthentication\s+(\S+)", RegexOptions.Multiline | RegexOptions.IgnoreCase);
                    return m.Success ? m.Groups[1].Value.ToLowerInvariant() : "?";
                };
                Action<SshdConfig, List<string>, string> check = (c, list, how) =>
                {
                    File.WriteAllText(p, c.Text, new UTF8Encoding(false));
                    foreach (var n in list) if (pw(n) != "no") throw new Exception(how + ": the rule for [" + n + "], written as " + SshdArgs.Quote(n) + ", did not apply");
                    if (pw("osm-no-rule") != "yes") throw new Exception(how + ": a rule applied to an account without a rule");
                };
                // 1. The Allow and Deny fields (SshdArgs.Join), for every name, also with " # %: sshd -T must list each one
                //    back as it was. Not names with @, which is pattern syntax there (user@host) like * ? !. sshd prints
                //    UTF-8, so its output is read as UTF-8 here.
                var listed = names.Where(n => n.IndexOf('@') < 0).ToList();
                File.WriteAllText(p, "HostKey " + SshdArgs.Quote(hk.PrivatePath) + "\nAllowUsers " + SshdArgs.Join(listed) + "\n", new UTF8Encoding(false));
                var psi = new ProcessStartInfo(Ssh.Exe("sshd.exe"), "-T -f " + Proc.Quote(p)) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true, StandardOutputEncoding = new UTF8Encoding(false), StandardErrorEncoding = new UTF8Encoding(false) };
                string output, errors;
                using (var proc = Process.Start(psi)) { var e = proc.StandardError.ReadToEndAsync(); output = proc.StandardOutput.ReadToEnd(); errors = e.Result; proc.WaitForExit(); if (proc.ExitCode != 0) throw new Exception("sshd -T with AllowUsers " + SshdArgs.Join(listed) + ": " + errors); }
                var back = Regex.Matches(output, @"^allowusers (.*?)\r?$", RegexOptions.Multiline | RegexOptions.IgnoreCase).Cast<Match>().Select(m => m.Groups[1].Value).ToList();
                if (!back.SequenceEqual(listed)) throw new Exception("AllowUsers " + SshdArgs.Join(listed) + " was read by sshd as [" + string.Join("] [", back) + "]");
                // 2. The Authentication tab (AuthConfig.Apply), for the names it accepts: it refuses " , * ? ! # % in account
                //    names. (sshd could not match a name that starts with # anyway: match_cfg_line in servconf.c reads any
                //    Match argument that starts with # as a comment, quoted or not.) One name per configuration, so that a
                //    failure names the name, then all rules together in their order.
                var accepted = names.Where(n => n.IndexOfAny(Accounts.ForbiddenNameChars) < 0).ToList();
                Func<List<string>, SshdConfig> withRules = list =>
                {
                    var c = new SshdConfig { Lines = new List<string> { "HostKey " + SshdArgs.Quote(hk.PrivatePath) } };
                    AuthConfig.Apply(c, new AuthMethods(), list.Select(n => new AuthRule { Name = n, Methods = new AuthMethods { Password = false } }).ToList());
                    return c;
                };
                foreach (var n in accepted) check(withRules(new List<string> { n }), new List<string> { n }, "AuthConfig.Apply");
                check(withRules(accepted), accepted, "AuthConfig.Apply, all rules");
                return listed.Count + " names in AllowUsers (" + (names.Count - listed.Count) + " with @ left out), " + accepted.Count + " as rules of the Authentication tab";
            });
        }
    }
}

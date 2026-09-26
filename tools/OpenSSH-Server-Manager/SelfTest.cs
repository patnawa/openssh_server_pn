// OpenSSH Server Manager for Windows: SelfTest

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
            var old = Ssh.ConfigDirOverride; Ssh.ConfigDirOverride = dir;
            try
            {
                File.WriteAllText(Ssh.ConfigPath, configText, new UTF8Encoding(false));
                using (var f = new MainForm())
                {
                    f.StartPosition = FormStartPosition.Manual; f.Location = new Point(-20000, -20000); f.ShowInTaskbar = false;
                    f.Show(); Application.DoEvents();
                    body(f);
                    f.Close();
                }
            }
            finally { Ssh.ConfigDirOverride = old; }
        }

        [DllImport("shell32.dll", CharSet = CharSet.Unicode)] private static extern uint ExtractIconEx(string file, int index, IntPtr[] large, IntPtr[] small, uint count);

        private static void Unit(Action<string, Func<string>> test, string tmpDir)
        {
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
                var s = SystemTasks.ProfileRemovalScript("S-1-5-21-1-2-3-1001", "OpenSSH Server Manager remove test profile o'x");
                foreach (var part in new[] { "-ErrorAction Stop", "if ($p[0].Loaded) { exit 1 }", "Start-Sleep -Seconds 20", "exit 1", "'OpenSSH Server Manager remove test profile o''x'" })
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
        }

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
            test("login methods: lock-out warning for the current account", () =>
            {
                if (!Elevation.IsAdministrator()) return "skipped: not elevated";
                var baseCfg = SshdConfig.Load();
                var me = Accounts.AsciiLower(KeyGen.LoginName());
                var file = Ssh.AuthorizedKeysFileFor(me, Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));
                int keys = 0; try { if (file != null) keys = Keys.Read(file).Count(k => k.Type != "?"); } catch { }
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
            test("window: no clipped text at 100% and 150%", () =>
            {
                var report = new List<string>();
                foreach (var s in new[] { 1f, 1.5f })
                {
                    var old = Ui.Scale; Ui.Scale = s;
                    try { WithTestWindow(tmpDir, "Port 22\n", f => report.AddRange(f.ClippedTextForTest().Select(x => (int)(s * 100) + "%: " + x))); }
                    finally { Ui.Scale = old; }
                }
                if (report.Count > 0) throw new Exception(report.Count + " place(s): " + string.Join(" | ", report.Take(15)) + (report.Count > 15 ? " | ..." : ""));
                return null;
            });
            test("firewall rule found by name, also from a background thread", () =>
            {
                if (!Elevation.IsAdministrator()) return "skipped: not elevated";
                // A disabled inbound rule of its own (it opens no port), removed at the end.
                var name = "OpenSSH Server Manager selftest " + Guid.NewGuid().ToString("N").Substring(0, 8);
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
                    if (Firewall.Get("OpenSSH Server Manager no such rule " + Guid.NewGuid().ToString("N")) != null) throw new Exception("a missing rule was found");
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
            test("profile removal task: script for a profile that does not exist", () =>
            {
                // No profile has this SID: the script must end at once with 0 (and try to delete its task, which does not exist).
                var script = SystemTasks.ProfileRemovalScript("S-1-5-21-1-2-3-999999", "OpenSSH Server Manager selftest no such task " + Guid.NewGuid().ToString("N").Substring(0, 8));
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

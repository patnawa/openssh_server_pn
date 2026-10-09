// OpenSSH Server PN Manager: AuthTest

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
    /// <summary>
    /// --authtest: the settings of the Authentication tab, checked with real logins. Each case is written by AuthConfig.Apply
    /// into a copy of the live sshd_config and served by a second, temporary sshd service that listens on 127.0.0.1 only, on
    /// a free port; the live sshd, its sshd_config and its keys are not touched. Password logins need a password the test
    /// knows, so a temporary local account (random name and password, member of Users only) is created; it is deleted with
    /// its profile at the end, like the service and the test folder.
    /// </summary>
    internal static class AuthTest
    {
        private const string Marker = "OSM-AUTH-LOGIN-OK";

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern IntPtr OpenSCManager(string machine, string database, uint access);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern IntPtr CreateService(IntPtr scm, string name, string display, uint access, uint type, uint start, uint errorControl, string path, string group, IntPtr tag, string dependencies, string account, string password);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern IntPtr OpenService(IntPtr scm, string name, uint access);
        [DllImport("advapi32.dll", SetLastError = true)] private static extern bool DeleteService(IntPtr service);
        [DllImport("advapi32.dll", SetLastError = true)] private static extern bool CloseServiceHandle(IntPtr handle);

        private sealed class Case
        {
            public string Name; public AuthMethods Global; public List<AuthRule> Rules = new List<AuthRule>();
            /// <summary>The expected "Permission denied (...)" list, sorted and comma-separated.</summary>
            public string Offered;
            public bool Password, Key, KeyAndPassword, WrongPassword;
        }

        private static AuthMethods M(bool password, bool key, bool kerberos, bool both) { return new AuthMethods { Password = password, PublicKey = key, Kerberos = kerberos, RequireBoth = both }; }
        private static AuthRule R(bool group, string name, AuthMethods m) { return new AuthRule { IsGroup = group, Name = name, Methods = m }; }

        public static int Run(string outFile)
        {
            Program.AttachParentConsole();
            var sb = new StringBuilder(); int failed = 0;
            string dir = null, service = null, user = null; SecurityIdentifier sid = null;
            bool serviceCreated = false, accountCreated = false;
            try
            {
                if (!Elevation.IsAdministrator()) throw new Exception("run this test elevated: it creates a temporary service and a temporary account");
                try { Process.EnterDebugMode(); } catch { } // lets the cleanup end the test sshd process if it does not stop
                var id = RandomHex(6);
                dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "osm-authtest-" + id);
                Acl.CreatePrivateFolder(dir);
                user = "osmtest" + id;
                var password = RandomPassword();
                CreateAccount(user, password); accountCreated = true;
                sid = Acl.SidOfAccount(user);
                if (sid == null) throw new Exception("the temporary account " + user + " has no SID");
                AddToUsers(sid); // as Settings, Computer Management and net user do; NetUserAdd alone does not
                string err;
                // A rule keeps the name in sshd's form; a name typed in capitals must give the same.
                var canonical = Accounts.Canonical(user.ToUpperInvariant(), false, out err);
                if (canonical != user) throw new Exception("account name in sshd's form: expected " + user + ", got " + (canonical ?? err));
                var usersGroup = Accounts.Canonical(new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null).Translate(typeof(NTAccount)).Value, true, out err);
                var adminsGroup = Accounts.Canonical(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null).Translate(typeof(NTAccount)).Value, true, out err);
                if (usersGroup == null || adminsGroup == null) throw new Exception("built-in group names: " + err);

                var key = KeyGen.Generate(KeyGen.Types[0], Path.Combine(dir, "id_ed25519"), "osm-authtest", null);
                var authorizedKeys = Path.Combine(dir, "authorized_keys");
                File.WriteAllText(authorizedKeys, key.PublicKey + "\n", new UTF8Encoding(false));
                // sshd accepts an authorized_keys file owned by the account, SYSTEM or Administrators (w32-sshfileperm.c).
                Acl.Restrict(authorizedKeys, null);
                var fs = File.GetAccessControl(authorizedKeys); fs.SetOwner(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null)); File.SetAccessControl(authorizedKeys, fs);

                int port = FreePort();
                var knownHosts = Path.Combine(dir, "known_hosts"); Ssh.WriteKnownHosts(knownHosts, "127.0.0.1", port);
                var cfgPath = Path.Combine(dir, "sshd_config"); var logPath = Path.Combine(dir, "sshd.log");
                service = "OSMAuthTest" + id;
                CreateTestService(service, Proc.Quote(Ssh.Exe("sshd.exe")) + " -f " + Proc.Quote(cfgPath) + " -E " + Proc.Quote(logPath));
                serviceCreated = true;

                sb.AppendLine("OpenSSH Server PN Manager " + Program.AppVersion + " login-method test");
                sb.AppendLine("temporary sshd service " + service + " on 127.0.0.1:" + port + ", configuration copied from " + Ssh.ConfigPath);
                sb.AppendLine("temporary account " + user + " (member of " + usersGroup + "), key " + key.Fingerprint);
                var cases = new List<Case>
                {
                    new Case { Name = "Windows authentication only", Global = M(true, false, false, false), Offered = "password", Password = true, Key = false, KeyAndPassword = true, WrongPassword = true },
                    new Case { Name = "Public key only", Global = M(false, true, false, false), Offered = "publickey", Password = false, Key = true, KeyAndPassword = true },
                    new Case { Name = "Windows authentication or public key", Global = M(true, true, false, false), Offered = "password,publickey", Password = true, Key = true, KeyAndPassword = true },
                    new Case { Name = "Public key and Windows authentication, both required", Global = M(true, true, false, true), Offered = "publickey", Password = false, Key = false, KeyAndPassword = true, WrongPassword = true },
                    new Case { Name = "Rule for group " + usersGroup + ": public key only (others: Windows authentication)", Global = M(true, false, false, false), Rules = { R(true, usersGroup, M(false, true, false, false)) }, Offered = "publickey", Password = false, Key = true, KeyAndPassword = true },
                    new Case { Name = "Rule for user " + canonical + ": Windows authentication only (others: public key)", Global = M(false, true, false, false), Rules = { R(false, canonical, M(true, false, false, false)) }, Offered = "password", Password = true, Key = false, KeyAndPassword = true },
                    new Case { Name = "First matching rule applies: user rule (both required) before group rule (Windows authentication only)", Global = M(true, true, false, false), Rules = { R(false, canonical, M(true, true, false, true)), R(true, usersGroup, M(true, false, false, false)) }, Offered = "publickey", Password = false, Key = false, KeyAndPassword = true },
                    new Case { Name = "Rule for another group (" + adminsGroup + ") does not apply", Global = M(true, false, false, false), Rules = { R(true, adminsGroup, M(false, true, false, false)) }, Offered = "password", Password = true, Key = false, KeyAndPassword = true },
                    new Case { Name = "Kerberos on: offered (a Kerberos login needs a domain and is not attempted)", Global = M(true, false, true, false), Offered = "gssapi-with-mic,password", Password = true, Key = false, KeyAndPassword = true },
                };
                var baseCfg = SshdConfig.Load();
                foreach (var c in cases)
                {
                    try { sb.AppendLine("PASS  " + c.Name + ": " + RunCase(c, baseCfg, cfgPath, service, port, user, password, key.PrivatePath, knownHosts, authorizedKeys)); }
                    catch (Exception ex)
                    {
                        failed++; sb.AppendLine("FAIL  " + c.Name + ": " + ex.Message.Replace(Environment.NewLine, " "));
                        try { StopTestService(service); } catch { } // sshd keeps its log file locked while it runs
                        sb.AppendLine(LogTail(logPath, 12));
                    }
                }
                // SFTP as the SFTP tab writes it, with real transfers of the temporary account (public key login).
                var sftp = new SftpRun { Dir = dir, User = user, Port = port, Key = key.PrivatePath, KnownHosts = knownHosts };
                foreach (var c in SftpCases(dir, user, sid, usersGroup))
                {
                    try
                    {
                        var cfg = new SshdConfig { Lines = baseCfg.Lines.ToList(), NewLine = baseCfg.NewLine, Path = cfgPath };
                        AuthConfig.Apply(cfg, M(false, true, false, false), new List<AuthRule>());
                        if (SftpConfig.Read(cfg).RulesProblem != null) throw new Exception("the live sshd_config has a hand-edited section of SFTP-only accounts: " + SftpConfig.Read(cfg).RulesProblem);
                        SftpConfig.Apply(cfg, c.Enabled, c.Enabled, c.Rules);
                        Serve(cfg, cfgPath, service, port, authorizedKeys);
                        sb.AppendLine("PASS  " + c.Name + ": " + c.Check(sftp));
                    }
                    catch (Exception ex)
                    {
                        failed++; sb.AppendLine("FAIL  " + c.Name + ": " + ex.Message.Replace(Environment.NewLine, " "));
                        try { StopTestService(service); } catch { }
                        sb.AppendLine(LogTail(logPath, 12));
                    }
                }
                int partnerFailures = PartnerTests(sb, dir, id, baseCfg, cfgPath, service, port, key, knownHosts, authorizedKeys);
                if (partnerFailures > 0) { failed += partnerFailures; try { StopTestService(service); } catch { } sb.AppendLine(LogTail(logPath, 20)); }
                failed += AgentTests(sb, dir, "osmta" + id);
            }
            catch (Exception ex) { failed++; sb.AppendLine("FAIL  " + ex.Message); }
            finally
            {
                if (serviceCreated)
                {
                    var e = RemoveTestService(service);
                    if (e == null) sb.AppendLine("removed the temporary service " + service); else { failed++; sb.AppendLine("FAIL  cleanup, service " + service + ": " + e); }
                }
                if (accountCreated)
                {
                    string note;
                    var e = LocalAccounts.DeleteUser(user, sid, out note);
                    if (e == null) sb.AppendLine("removed the temporary account " + user + (note != null ? "; " + note : ""));
                    else { failed++; sb.AppendLine("FAIL  cleanup, account " + user + ": " + e); }
                }
                if (dir != null)
                {
                    var e = RemoveFolder(dir);
                    if (e == null) sb.AppendLine("removed " + dir); else { failed++; sb.AppendLine("FAIL  cleanup, " + dir + ": " + e); }
                }
            }
            sb.AppendLine(failed == 0 ? "RESULT: all login-method tests passed" : "RESULT: " + failed + " login-method test(s) failed");
            Program.Report(sb.ToString(), outFile);
            return failed == 0 ? 0 : 1;
        }

        /// <summary>Serves a configuration with the test service: on 127.0.0.1 and the test port, keys from the test file, nobody else restricted.</summary>
        private static void Serve(SshdConfig cfg, string cfgPath, string service, int port, string authorizedKeys)
        {
            cfg.Set("Port", port.ToString());
            cfg.Set("ListenAddress", "127.0.0.1");
            foreach (var k in new[] { "AllowUsers", "AllowGroups", "DenyUsers", "DenyGroups" }) cfg.Set(k, "");
            cfg.Set("AuthorizedKeysFile", "\"" + authorizedKeys.Replace('\\', '/') + "\"");
            cfg.Set("PerSourcePenalties", "no");
            File.WriteAllText(cfgPath, cfg.Text, new UTF8Encoding(false));
            var t = Ssh.TestConfig(cfgPath);
            if (!t.Ok) throw new Exception("sshd -t rejected the configuration: " + t.Output);
            RestartTestService(service, port);
        }

        // ---------------- SFTP ----------------

        /// <summary>What an SFTP case needs to connect: the account, its key, the test server.</summary>
        private sealed class SftpRun
        {
            public string Dir, User, Key, KnownHosts; public int Port;

            /// <summary>
            /// sftp with a batch of commands, public key only, host key pinned. sftp -b stops at the first command that fails
            /// and exits with 1, so a batch of one command tells whether that command worked.
            /// </summary>
            public RunResult Batch(params string[] commands)
            {
                var batch = Path.Combine(Dir, "sftp-batch.txt");
                File.WriteAllText(batch, string.Join("\n", commands) + "\n", new UTF8Encoding(false));
                var args = "-F none -o StrictHostKeyChecking=yes -o UserKnownHostsFile=" + Proc.Quote(KnownHosts) + " -o GlobalKnownHostsFile=" + Proc.Quote(KnownHosts) +
                           " -o ConnectTimeout=15 -o IdentityAgent=none -o IdentitiesOnly=yes -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no -o BatchMode=yes" +
                           " -i " + Proc.Quote(Key) + " -P " + Port + " -b " + Proc.Quote(batch) + " " + Proc.Quote(User + "@127.0.0.1");
                return Proc.Run(Ssh.Exe("sftp.exe"), args, 120000, null, new Dictionary<string, string> { { "SSH_ASKPASS_REQUIRE", "never" } });
            }

            /// <summary>A command over ssh (not SFTP), public key only.</summary>
            public RunResult Command(string command)
            {
                var args = "-F none -T -o StrictHostKeyChecking=yes -o UserKnownHostsFile=" + Proc.Quote(KnownHosts) + " -o GlobalKnownHostsFile=" + Proc.Quote(KnownHosts) +
                           " -o ConnectTimeout=15 -o IdentityAgent=none -o IdentitiesOnly=yes -o PasswordAuthentication=no -o BatchMode=yes -i " + Proc.Quote(Key) +
                           " -p " + Port + " -l " + Proc.Quote(User) + " 127.0.0.1 " + command;
                return Proc.Run(Ssh.Exe("ssh.exe"), args, 90000, null, new Dictionary<string, string> { { "SSH_ASKPASS_REQUIRE", "never" } });
            }

            public void Works(RunResult r, string what) { if (!r.Ok) throw new Exception(what + " failed: " + Short(r.Output)); }
            public void Refused(RunResult r, string what) { if (r.Ok) throw new Exception(what + " worked but must be refused: " + Short(r.Output)); }

            /// <summary>A file of random content in the test folder (not in a folder the account can reach).</summary>
            public string MakeFile(string name, int size)
            {
                var p = Path.Combine(Dir, name); var b = new byte[size];
                new Random(size).NextBytes(b); File.WriteAllBytes(p, b);
                return p;
            }
        }

        private static bool SameBytes(string a, string b) { return File.Exists(a) && File.Exists(b) && File.ReadAllBytes(a).SequenceEqual(File.ReadAllBytes(b)); }
        /// <summary>A local path for an sftp batch command: forward slashes, in double quotes (sftp reads quoted arguments).</summary>
        private static string SftpPath(string p) { return "\"" + p.Replace('\\', '/') + "\""; }

        private sealed class SftpCase { public string Name; public bool Enabled = true; public List<SftpRule> Rules = new List<SftpRule>(); public Func<SftpRun, string> Check; }

        private static List<SftpCase> SftpCases(string dir, string user, SecurityIdentifier sid, string usersGroup)
        {
            var jailRoot = Path.Combine(dir, "sftp");
            var jail = Path.Combine(jailRoot, user);                 // C:\...\sftp\%u for this account
            var shared = Path.Combine(dir, "sftp-published");        // a download-only folder for the Users group
            return new List<SftpCase>
            {
                new SftpCase
                {
                    Name = "SFTP for all accounts: upload and download with the key (8 MiB, byte for byte)",
                    Check = s =>
                    {
                        var up = s.MakeFile("up.bin", 8 << 20); var back = Path.Combine(s.Dir, "back.bin");
                        s.Works(s.Batch("put " + SftpPath(up) + " osm-up.bin"), "upload");
                        s.Works(s.Batch("get osm-up.bin " + SftpPath(back)), "download");
                        if (!SameBytes(up, back)) throw new Exception("the file came back different");
                        s.Works(s.Batch("rm osm-up.bin"), "removal");
                        var cmd = s.Command("echo " + Marker);
                        if (!cmd.Ok || !cmd.StdOut.Contains(Marker)) throw new Exception("a command did not run for an account that is not SFTP-only: " + Short(cmd.Output));
                        return "upload, download, removal ok; commands still run";
                    },
                },
                new SftpCase
                {
                    Name = "SFTP-only account confined to its folder (" + SftpConfig.ExpandFolder(Path.Combine(jailRoot, "%u"), user, null) + ")",
                    Rules = { new SftpRule { Name = user, Folder = Path.Combine(jailRoot, "%u") } },
                    Check = s =>
                    {
                        var done = SftpConfig.PrepareFolder(jail, sid, false); // as Apply on the SFTP tab
                        var up = s.MakeFile("jail-up.bin", 1 << 20); var back = Path.Combine(s.Dir, "jail-back.bin");
                        s.Works(s.Batch("put " + SftpPath(up) + " in.bin"), "upload");
                        if (!SameBytes(up, Path.Combine(jail, "in.bin"))) throw new Exception("the upload is not in " + jail);
                        s.Works(s.Batch("mkdir sub", "rename in.bin sub/in.bin", "get sub/in.bin " + SftpPath(back)), "mkdir, rename and download");
                        if (!SameBytes(up, back)) throw new Exception("the file came back different");
                        var pwd = s.Batch("cd sub", "cd ..", "pwd");
                        if (!pwd.Ok || !pwd.StdOut.Contains("Remote working directory: /")) throw new Exception("pwd in the folder: " + Short(pwd.Output));
                        s.Refused(s.Batch("cd .."), "cd .. above the folder");
                        s.Refused(s.Batch("get /../../Windows/win.ini " + SftpPath(Path.Combine(s.Dir, "x1"))), "a download from outside the folder (/../..)");
                        s.Refused(s.Batch("get C:/Windows/win.ini " + SftpPath(Path.Combine(s.Dir, "x2"))), "a download by drive letter");
                        s.Refused(s.Batch("put " + SftpPath(up) + " /../escape.bin"), "an upload outside the folder");
                        if (File.Exists(Path.Combine(jailRoot, "escape.bin"))) throw new Exception("a file reached " + jailRoot);
                        var cmd = s.Command("echo " + Marker);
                        if (cmd.StdOut.Contains(Marker)) throw new Exception("a command ran for an SFTP-only account");
                        return done + "; upload, mkdir, rename, download ok; / is the folder; ../, C:/ and uploads outside refused; commands refused";
                    },
                },
                new SftpCase
                {
                    Name = "SFTP-only group " + usersGroup + ", download only, one shared folder",
                    Rules = { new SftpRule { IsGroup = true, Name = usersGroup, Folder = shared, ReadOnly = true } },
                    Check = s =>
                    {
                        SftpConfig.PrepareFolder(shared, new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null), true);
                        var published = Path.Combine(shared, "report.bin"); var src = s.MakeFile("report.bin", 256 << 10); File.Copy(src, published, true);
                        var back = Path.Combine(s.Dir, "report-back.bin");
                        s.Works(s.Batch("get report.bin " + SftpPath(back)), "download");
                        if (!SameBytes(src, back)) throw new Exception("the file came back different");
                        s.Refused(s.Batch("put " + SftpPath(src) + " new.bin"), "an upload");
                        s.Refused(s.Batch("rm report.bin"), "a removal");
                        s.Refused(s.Batch("mkdir x"), "a new folder");
                        if (!File.Exists(published) || File.Exists(Path.Combine(shared, "new.bin"))) throw new Exception("the folder changed");
                        return "download ok; upload, removal and new folder refused";
                    },
                },
                new SftpCase
                {
                    Name = "SFTP off: no transfers, commands still run",
                    Enabled = false,
                    Check = s =>
                    {
                        s.Refused(s.Batch("pwd"), "an SFTP session");
                        var cmd = s.Command("echo " + Marker);
                        if (!cmd.Ok || !cmd.StdOut.Contains(Marker)) throw new Exception("a command failed: " + Short(cmd.Output));
                        return "SFTP refused; commands run";
                    },
                },
            };
        }

        // ---------------- SFTP partners ----------------

        /// <summary>
        /// SFTP partners as the Partners tab makes them, against the test sshd, with partner groups and a keys folder of this
        /// test: a partner with a password (upload and download) and one with a key only (download only); disabling, the
        /// last day, a new password, a change of access, and removal. Partners are in their groups only, not in Users, as the
        /// tab makes them. Everything the test makes is removed at the end. Returns the number of failures.
        /// </summary>
        private static int PartnerTests(StringBuilder sb, string dir, string id, SshdConfig baseCfg, string cfgPath, string service, int port, KeyGenResult key, string knownHosts, string authorizedKeys)
        {
            int failed = 0;
            var g = new PartnerGroups { Full = "osmtest-p-" + id, ReadOnly = "osmtest-pr-" + id, KeyOnly = "osmtest-pk-" + id, KeysDir = Path.Combine(dir, "partner_keys") };
            var root = Path.Combine(dir, "partners");
            string a = "osmta" + id, b = "osmtb" + id;
            var made = new List<string>();
            var s = new SftpRun { Dir = dir, Port = port, Key = key.PrivatePath, KnownHosts = knownHosts };
            Action<string, Func<string>> step = (name, body) =>
            {
                try { sb.AppendLine("PASS  " + name + ": " + body()); }
                catch (Exception ex) { failed++; sb.AppendLine("FAIL  " + name + ": " + Short(ex.Message)); }
            };
            Func<string, PartnerAccount> find = n => Partners.List(g).FirstOrDefault(x => x.Name.Equals(n, StringComparison.OrdinalIgnoreCase));
            try
            {
                PartnerSetup.CreateGroups(g);
                Acl.CreatePrivateFolder(g.KeysDir);
                var cfg = new SshdConfig { Lines = baseCfg.Lines.ToList(), NewLine = baseCfg.NewLine, Path = cfgPath };
                AuthConfig.Apply(cfg, M(false, true, false, false), new List<AuthRule>()); // everyone else: a key only; the partner rules allow passwords
                if (SftpConfig.Read(cfg).RulesProblem != null) throw new Exception("the live sshd_config has a hand-edited section of SFTP-only accounts");
                PartnerSetup.Apply(cfg, g, root);
                var st = PartnerSetup.Check(cfg, g);
                if (!st.Complete) throw new Exception("after the setup: " + string.Join("; ", st.MissingGroups.Concat(st.Missing)));
                Serve(cfg, cfgPath, service, port, authorizedKeys);
                string pwA = null;
                step("SFTP partner with a password, upload and download (" + a + ")", () =>
                {
                    pwA = Partners.Create(g, root, a, "Test contact", "Test company", false, false, DateTime.Today.AddDays(30)); made.Add(a);
                    var p = find(a);
                    if (p == null || p.ReadOnly || p.KeyOnly || !p.Active || p.Company != "Test company" || p.FullName != "Test contact" || LocalAccounts.LastDay(p.Expires) != DateTime.Today.AddDays(30))
                        throw new Exception("listed as " + (p == null ? "missing" : p.Access + ", " + p.Login + ", " + p.Status + ", " + p.Company + ", last day " + LocalAccounts.LastDay(p.Expires)));
                    if (!Authenticated(a, port, knownHosts, null, pwA)) throw new Exception("the password was refused");
                    if (Authenticated(a, port, knownHosts, key.PrivatePath, null)) throw new Exception("a key that is not the partner's logged in");
                    var cmd = Login(a, port, knownHosts, null, pwA);
                    if (cmd.StdOut.Contains(Marker)) throw new Exception("a command ran for a partner");
                    var up = s.MakeFile("partner-up.bin", 1 << 20);
                    var r = Scp(a, port, knownHosts, pwA, up, "in.bin");
                    if (!SameBytes(up, Path.Combine(Partners.FolderOf(root, a), "in.bin"))) throw new Exception("the upload with the password is not in the partner's folder: " + Short(r.Output));
                    return "created; its password logs in, a key that is not its own does not, commands do not run; an upload (scp over SFTP) lands in " + Partners.FolderOf(root, a);
                });
                step("SFTP partner with a key only, download only (" + b + ")", () =>
                {
                    var pwB = Partners.Create(g, root, b, "", "", true, true, null); made.Add(b);
                    Keys.AddLines(Partners.EnsureKeysFile(g, b), new[] { key.PublicKey }, null, false);
                    var src = s.MakeFile("partner-report.bin", 64 << 10);
                    File.Copy(src, Path.Combine(Partners.FolderOf(root, b), "report.bin"));
                    var p = find(b);
                    if (p == null || !p.ReadOnly || !p.KeyOnly || p.KeyCount != 1) throw new Exception("listed as " + (p == null ? "missing" : p.Access + ", " + p.Login));
                    s.User = b;
                    var back = Path.Combine(dir, "partner-report-back.bin");
                    s.Works(s.Batch("get report.bin " + SftpPath(back)), "a download with the key");
                    if (!SameBytes(src, back)) throw new Exception("the file came back different");
                    s.Refused(s.Batch("put " + SftpPath(src) + " up.bin"), "an upload");
                    s.Refused(s.Batch("cd .."), "cd .. above the folder");
                    if (Authenticated(b, port, knownHosts, null, pwB)) throw new Exception("the password of a key-only partner logged in");
                    return "its key downloads; an upload, leaving the folder and its password are refused";
                });
                step("Disable and enable, the last day, a new password (" + a + ")", () =>
                {
                    Partners.SetDisabled(a, true);
                    if (Authenticated(a, port, knownHosts, null, pwA)) throw new Exception("a disabled partner logged in");
                    Partners.SetDisabled(a, false);
                    if (!Authenticated(a, port, knownHosts, null, pwA)) throw new Exception("a partner enabled again was refused");
                    LocalAccounts.SetExpiry(a, DateTime.Today.AddDays(-1));
                    if (Authenticated(a, port, knownHosts, null, pwA)) throw new Exception("a partner logged in after its last day");
                    if (find(a).Status != "expired") throw new Exception("not listed as expired: " + find(a).Status);
                    LocalAccounts.SetExpiry(a, null);
                    var pw2 = Partners.ResetPassword(a);
                    if (Authenticated(a, port, knownHosts, null, pwA)) throw new Exception("the old password still logs in");
                    if (!Authenticated(a, port, knownHosts, null, pw2)) throw new Exception("the new password was refused");
                    pwA = pw2;
                    return "refused while disabled and after its last day, back afterwards; after a new password the old one is refused";
                });
                step("Access changed to download only (" + a + ")", () =>
                {
                    var p = find(a);
                    Partners.Update(g, root, p, p.FullName, p.Company, true, false, null);
                    var folder = Partners.FolderOf(root, a);
                    var rights = Directory.GetAccessControl(folder).GetAccessRules(true, false, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().Where(x => p.Sid.Equals(x.IdentityReference)).ToList();
                    if (rights.Count != 1 || (rights[0].FileSystemRights & FileSystemRights.WriteData) != 0) throw new Exception("the folder still lets it write: " + string.Join(", ", rights.Select(x => x.FileSystemRights)));
                    var up = s.MakeFile("partner-up2.bin", 4096);
                    Scp(a, port, knownHosts, pwA, up, "in2.bin");
                    if (File.Exists(Path.Combine(folder, "in2.bin"))) throw new Exception("an upload worked after the access became download only");
                    if (!find(a).ReadOnly) throw new Exception("not listed as download only");
                    return "its upload is refused and the folder gives it read rights only";
                });
                step("Delete: the account goes, its folder stays unless asked", () =>
                {
                    string note;
                    var e = Partners.Delete(g, root, find(a), false, out note); if (e != null) throw new Exception(e);
                    made.Remove(a);
                    if (Acl.SidOfAccount(a) != null) throw new Exception("the account " + a + " still exists");
                    if (!File.Exists(Path.Combine(Partners.FolderOf(root, a), "in.bin"))) throw new Exception("the folder of " + a + " was deleted without being asked");
                    e = Partners.Delete(g, root, find(b), true, out note); if (e != null) throw new Exception(e);
                    made.Remove(b);
                    if (Directory.Exists(Partners.FolderOf(root, b))) throw new Exception("the folder of " + b + " was asked to go and is still there");
                    if (File.Exists(Partners.KeysFileOf(g, b))) throw new Exception("the keys of " + b + " are still there");
                    if (Partners.List(g).Count != 0) throw new Exception("partners are still listed");
                    return "both accounts removed, the first folder kept, the second deleted with its keys" + (note != null ? "; " + note : "");
                });
            }
            catch (Exception ex) { failed++; sb.AppendLine("FAIL  SFTP partners: " + Short(ex.Message)); }
            finally
            {
                foreach (var n in made)
                {
                    string note; var e = LocalAccounts.DeleteUser(n, Acl.SidOfAccount(n), out note);
                    try { LocalAccounts.HideFromSignIn(n, false); } catch { }
                    if (e != null) { failed++; sb.AppendLine("FAIL  cleanup, partner " + n + ": " + e); } else sb.AppendLine("removed the test partner " + n + (note != null ? "; " + note : ""));
                }
                var left = g.All.Select(x => new { Group = x, Error = LocalAccounts.DeleteGroup(x) }).Where(x => x.Error != null).ToList();
                foreach (var x in left) { failed++; sb.AppendLine("FAIL  cleanup, group " + x.Group + ": " + x.Error); }
                sb.AppendLine("removed the test groups " + string.Join(", ", g.All));
            }
            return failed;
        }

        // ---------------- The agent (Alerts tab) ----------------

        /// <summary>
        /// The agent against this computer: an address of the documentation range blocked in the firewall rule and unblocked
        /// by a Watch run when its time is up (the rule is put back as it was); the transfers of the partner test archived
        /// (in isolated storage for this test); and a uniquely named Task Scheduler probe running as SYSTEM, which reads
        /// the service/event log and writes only to its private scratch folder. Existing tasks and journals stay in place.
        /// </summary>
        private static int AgentTests(StringBuilder sb, string dir, string partner)
        {
            int failed = 0; string probeCleanup = null;
            Action<string, Func<string>> step = (name, body) =>
            {
                try { sb.AppendLine("PASS  " + name + ": " + body()); }
                catch (Exception ex) { failed++; sb.AppendLine("FAIL  " + name + ": " + Short(ex.Message)); }
            };
            step("Agent: an address is blocked after its failed logins and unblocked when its time is up", () =>
            {
                var before = Firewall.BlockedAddresses(); var serverState = ServerState.Read();
                if (!serverState.Verified) throw new Exception("the server's listener ports could not be verified: " + serverState.Error);
                var ports = serverState.FirewallPorts;
                var previousRoot = AgentStorage.RootOverride;
                const string address = "192.0.2.77"; // TEST-NET-1, never a real client
                try
                {
                    AgentStorage.RootOverride = Path.Combine(dir, "agent-expiry-state");
                    var s = new AlertSettings { OnSshdStopped = false, OnFailedLogins = false, OnUploads = false, OnDiskLow = false, MonthlyReport = false };
                    var st = new AgentState(); var now = DateTime.Now;
                    var src = new List<EventLogs.FailedSource> { new EventLogs.FailedSource { Address = address, Count = 12, First = now, Last = now } };
                    var added = Agent.Block(s, st, src, now, "test");
                    if (added.Count != 1 || !Firewall.BlockedAddresses().Contains(address)) throw new Exception("not in the block rule: " + string.Join(", ", Firewall.BlockedAddresses()));
                    if (st.Blocks[address].Until != now.AddHours(1)) throw new Exception("blocked until " + st.Blocks[address].Until);
                    st.Blocks[address].Until = now.AddSeconds(-1);
                    Agent.Watch(s, st, now);
                    if (Firewall.BlockedAddresses().Contains(address)) throw new Exception("still blocked after its time");
                    if (!st.Blocks.ContainsKey(address) || st.Blocks[address].Until != DateTime.MinValue || st.Blocks[address].Strikes != 1) throw new Exception("the strike is not remembered for a week");
                    return "blocked for 1 hour, unblocked by the Watch run when the time was up; the strike is kept for a week";
                }
                finally { AgentStorage.RootOverride = previousRoot; Firewall.SetBlockedAddresses(before, ports); }
            });
            step("Agent: the transfers of the partner test go into the archive", () =>
            {
                var old = Ssh.ConfigDirOverride; var cfgCopy = Path.Combine(dir, "agent-config");
                Directory.CreateDirectory(cfgCopy); File.Copy(Ssh.ConfigPath, Path.Combine(cfgCopy, "sshd_config"), true);
                Ssh.ConfigDirOverride = cfgCopy;
                try
                {
                    var records = Transfers.Read(DateTime.Today, DateTime.Now.AddMinutes(1), CancellationToken.None).Where(r => r.User.Equals(partner, StringComparison.OrdinalIgnoreCase)).ToList();
                    if (!records.Any(r => r.Action == TransferRecord.Upload && r.File.TrimStart('/') == "in.bin" && r.Bytes == 1 << 20)) throw new Exception("the event log has no upload of in.bin (1 MiB) by " + partner + ": " + string.Join("; ", records.Select(r => r.Action + " " + r.File + " " + r.Bytes)));
                    int n = Agent.Archive(records);
                    int again = Agent.Archive(records);
                    var back = TransferArchive.Read(DateTime.Today, DateTime.Now.AddMinutes(1));
                    int distinct = records.Select(r => r.Key).Distinct().Count(); // only the same event identity is kept once
                    if (n != distinct || again != 0 || back.Count != distinct) throw new Exception("archived " + n + " then " + again + ", read back " + back.Count + " of " + distinct);
                    if (!Acl.IsAdminOnly(TransferArchive.FileOf(DateTime.Today))) throw new Exception("the archive is readable by others");
                    return records.Count + " record(s) of " + partner + " archived once (a second run added none), readable by SYSTEM and Administrators only";
                }
                finally { Ssh.ConfigDirOverride = old; }
            });
            step("Agent: Task Scheduler runs the isolated event-log probe as SYSTEM", () =>
            {
                var probeDir = Path.Combine(Path.GetTempPath(), "pn-agent-probe-" + Guid.NewGuid().ToString("N"));
                Acl.CreatePrivateFolder(probeDir);
                var marker = Path.Combine(probeDir, "agent-probe.marker"); File.WriteAllText(marker, "OpenSSH Server PN auth-test probe"); Acl.Restrict(marker, null);
                var previousRoot = AgentStorage.RootOverride; AgentStorage.RootOverride = probeDir;
                var stateFile = AgentState.FilePath; var start = DateTime.Now;
                var task = Agent.TaskFolder + "\\Audit-" + Guid.NewGuid().ToString("N");
                var exe = System.Windows.Forms.Application.ExecutablePath;
                try
                {
                    SystemTasks.RegisterXml(task, Agent.TaskXml("OpenSSH Server PN isolated background-agent probe", exe,
                        "--agent probe:" + Convert.ToBase64String(Encoding.UTF8.GetBytes(probeDir)), false));
                    var r = Proc.Run(Path.Combine(Environment.SystemDirectory, "schtasks.exe"), "/Run /TN " + Proc.Quote(task), 30000);
                    if (!r.Ok) throw new Exception("schtasks /Run: " + r.Output);
                    var sw = Stopwatch.StartNew();
                    while (!(File.Exists(stateFile) && File.GetLastWriteTime(stateFile) >= start.AddSeconds(-1)) && sw.Elapsed.TotalSeconds < 90) Thread.Sleep(1000);
                    if (!File.Exists(stateFile) || File.GetLastWriteTime(stateFile) < start.AddSeconds(-1)) throw new Exception("the task did not write " + stateFile + " within 90 s; agent log: " + (File.Exists(Agent.LogPath) ? Short(string.Join(" | ", File.ReadAllLines(Agent.LogPath).Reverse().Take(3))) : "none"));
                    var st = AgentState.Load();
                    if (st.SshdStatus != "Running" || st.Journal.LastRecordId <= 0) throw new Exception("the state after the run: sshd " + st.SshdStatus + ", last event " + st.Journal.LastRecordId);
                    return "the task ran " + exe + " as SYSTEM; it saw sshd running and read the event log up to record " + st.Journal.LastRecordId;
                }
                finally
                {
                    Proc.Run(Path.Combine(Environment.SystemDirectory, "schtasks.exe"), "/End /TN " + Proc.Quote(task), 10000);
                    bool removed = SystemTasks.Delete(task) && !SystemTasks.Exists(task);
                    probeCleanup = removed ? "the isolated probe task was removed; the normal watcher, daily job, and recovery task were untouched" : "the isolated probe task could not be removed";
                    AgentStorage.RootOverride = previousRoot;
                    if (removed) try { Directory.Delete(probeDir, true); } catch { }
                }
            });
            step("Agent: isolated task cleanup preserves operational tasks", () =>
            {
                if (probeCleanup == null || !probeCleanup.StartsWith("the isolated probe task was removed", StringComparison.Ordinal)) throw new Exception(probeCleanup ?? "probe cleanup was not reached");
                return probeCleanup;
            });
            return failed;
        }

        /// <summary>Whether one login with only the given key, or only the given password, gets through authentication (ssh -v: "Authenticated to").</summary>
        private static bool Authenticated(string user, int port, string knownHosts, string key, string password)
        {
            var args = "-v -F none -T -o StrictHostKeyChecking=yes -o UserKnownHostsFile=" + Proc.Quote(knownHosts) + " -o GlobalKnownHostsFile=" + Proc.Quote(knownHosts) +
                       " -o ConnectTimeout=15 -o IdentityAgent=none -o IdentitiesOnly=yes -o KbdInteractiveAuthentication=no -o NumberOfPasswordPrompts=1" +
                       (key != null ? " -o PreferredAuthentications=publickey -o PasswordAuthentication=no -o BatchMode=yes -i " + Proc.Quote(key) : " -o PreferredAuthentications=password -o PubkeyAuthentication=no") +
                       " -p " + port + " -l " + Proc.Quote(user) + " 127.0.0.1 exit";
            var r = Proc.Run(Ssh.Exe("ssh.exe"), args, 90000, null, password != null ? KeyGen.PasswordAskpassEnvironment(password) : new Dictionary<string, string> { { "SSH_ASKPASS_REQUIRE", "never" } });
            return r.Output.Contains("Authenticated to 127.0.0.1");
        }

        /// <summary>An upload with scp (the SFTP protocol since OpenSSH 9) and a password: sftp -b refuses passwords, scp does not.</summary>
        private static RunResult Scp(string user, int port, string knownHosts, string password, string local, string remote)
        {
            var args = "-F none -o StrictHostKeyChecking=yes -o UserKnownHostsFile=" + Proc.Quote(knownHosts) + " -o GlobalKnownHostsFile=" + Proc.Quote(knownHosts) +
                       " -o ConnectTimeout=15 -o IdentityAgent=none -o PubkeyAuthentication=no -o KbdInteractiveAuthentication=no -o PreferredAuthentications=password -o NumberOfPasswordPrompts=1" +
                       " -P " + port + " " + Proc.Quote(local) + " " + Proc.Quote(user + "@127.0.0.1:" + remote);
            return Proc.Run(Ssh.Exe("scp.exe"), args, 90000, null, KeyGen.PasswordAskpassEnvironment(password));
        }

        private static string RunCase(Case c, SshdConfig baseCfg, string cfgPath, string service, int port, string user, string password, string key, string knownHosts, string authorizedKeys)
        {
            var cfg = new SshdConfig { Lines = baseCfg.Lines.ToList(), NewLine = baseCfg.NewLine, Path = cfgPath };
            AuthConfig.Apply(cfg, c.Global, c.Rules); // exactly what the Authentication tab writes
            Serve(cfg, cfgPath, service, port, authorizedKeys);
            string err;
            var eff = AuthConfig.EffectiveFor(user, cfgPath, port, out err);
            if (eff == null) throw new Exception(err);
            var fromConfig = string.Join(",", eff.Offered());
            if (fromConfig != c.Offered) throw new Exception("sshd -T gives " + fromConfig + " for " + user + ", expected " + c.Offered);
            var offered = AuthConfig.Probe(user, "127.0.0.1", port, out err);
            if (offered == null) throw new Exception("no list of methods from the server: " + err);
            if (string.Join(",", offered) != c.Offered) throw new Exception("the server offers " + string.Join(",", offered) + ", expected " + c.Offered);
            var notes = new List<string> { "offers " + c.Offered };
            Expect(notes, "password", Login(user, port, knownHosts, null, password), c.Password);
            Expect(notes, "key", Login(user, port, knownHosts, key, null), c.Key);
            Expect(notes, "key+password", Login(user, port, knownHosts, key, password), c.KeyAndPassword);
            if (c.WrongPassword) Expect(notes, c.Password ? "wrong password" : "key+wrong password", Login(user, port, knownHosts, c.Password ? null : key, password + "x"), false);
            return string.Join("; ", notes);
        }

        /// <summary>One login with only the given key and/or password (the password goes to ssh through SSH_ASKPASS, never on a command line).</summary>
        private static RunResult Login(string user, int port, string knownHosts, string key, string password)
        {
            var preferred = key != null && password != null ? "publickey,password" : key != null ? "publickey" : "password";
            var args = "-F none -T -o StrictHostKeyChecking=yes -o UserKnownHostsFile=" + Proc.Quote(knownHosts) + " -o GlobalKnownHostsFile=" + Proc.Quote(knownHosts) +
                       " -o ConnectTimeout=15 -o IdentityAgent=none -o IdentitiesOnly=yes -o KbdInteractiveAuthentication=no -o NumberOfPasswordPrompts=1" +
                       " -o PreferredAuthentications=" + preferred +
                       (key != null ? " -i " + Proc.Quote(key) : " -o PubkeyAuthentication=no") +
                       (password != null ? "" : " -o PasswordAuthentication=no -o BatchMode=yes") +
                       " -p " + port + " -l " + Proc.Quote(user) + " 127.0.0.1 echo " + Marker;
            return Proc.Run(Ssh.Exe("ssh.exe"), args, 90000, null, password != null ? KeyGen.PasswordAskpassEnvironment(password) : new Dictionary<string, string> { { "SSH_ASKPASS_REQUIRE", "never" } });
        }

        private static void Expect(List<string> notes, string what, RunResult r, bool mustWork)
        {
            bool ok = r.Ok && r.StdOut.Contains(Marker);
            if (ok != mustWork) throw new Exception(what + (ok ? " logged in but must be refused" : " was refused but must log in: " + Short(r.Output)));
            notes.Add(what + (ok ? " ok" : " refused"));
        }

        private static string Short(string s)
        {
            s = (s ?? "").Replace("\r", " ").Replace("\n", " ").Trim();
            return s.Length > 300 ? s.Substring(0, 300) + "..." : s;
        }

        private static void RestartTestService(string name, int port)
        {
            StopTestService(name);
            Services.Start(name, 30);
            var sw = Stopwatch.StartNew();
            while (!IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners().Any(ep => ep.Port == port))
            {
                if (Services.Status(name).Status != "Running") throw new Exception("the test sshd stopped right after it started");
                if (sw.Elapsed.TotalSeconds > 20) throw new Exception("the test sshd does not listen on port " + port);
                Thread.Sleep(200);
            }
        }

        /// <summary>Stops the test service and waits until its process has ended, so that the port is free again.</summary>
        private static void StopTestService(string name)
        {
            int pid = Services.PidOf(name);
            try { Services.Stop(name, 30); }
            finally
            {
                if (pid > 0)
                {
                    try { using (var p = Process.GetProcessById(pid)) if (!p.WaitForExit(15000)) { p.Kill(); p.WaitForExit(5000); } }
                    catch (ArgumentException) { } // already ended
                }
            }
        }

        private static void CreateTestService(string name, string commandLine)
        {
            IntPtr scm = OpenSCManager(null, null, 0x0003 /*SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE*/);
            if (scm == IntPtr.Zero) throw new Win32Exception();
            try
            {
                // LocalSystem (no account given), started on demand, own process: sshd needs SYSTEM to log other accounts on.
                IntPtr svc = CreateService(scm, name, "OpenSSH Server PN Manager login-method test (temporary)", 0xF01FF /*SERVICE_ALL_ACCESS*/, 0x10 /*SERVICE_WIN32_OWN_PROCESS*/,
                                           3 /*SERVICE_DEMAND_START*/, 1 /*SERVICE_ERROR_NORMAL*/, commandLine, null, IntPtr.Zero, null, null, null);
                if (svc == IntPtr.Zero) throw new Win32Exception();
                CloseServiceHandle(svc);
            }
            finally { CloseServiceHandle(scm); }
        }

        private static string RemoveTestService(string name)
        {
            var problems = new List<string>();
            try { StopTestService(name); } catch (Exception ex) { problems.Add("stop: " + ex.Message); }
            IntPtr scm = OpenSCManager(null, null, 0x0001 /*SC_MANAGER_CONNECT*/);
            if (scm == IntPtr.Zero) { problems.Add(new Win32Exception().Message); return string.Join("; ", problems); }
            try
            {
                IntPtr svc = OpenService(scm, name, 0x10000 /*DELETE*/);
                if (svc == IntPtr.Zero) problems.Add(new Win32Exception().Message);
                else
                {
                    try { if (!DeleteService(svc)) problems.Add(new Win32Exception().Message); }
                    finally { CloseServiceHandle(svc); }
                }
            }
            finally { CloseServiceHandle(scm); }
            return problems.Count == 0 ? null : string.Join("; ", problems);
        }

        private static void CreateAccount(string name, string password)
        {
            LocalAccounts.CreateUser(name, password, "Temporary account of OpenSSH Server PN Manager --authtest, deleted when the test ends", LocalAccounts.UF_DONT_EXPIRE_PASSWD);
        }

        private static void AddToUsers(SecurityIdentifier sid)
        {
            var users = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null).Translate(typeof(NTAccount)).Value; // BUILTIN\Users in the system language
            LocalAccounts.AddToGroup(users.Substring(users.IndexOf('\\') + 1), sid);
        }

        private static string RemoveFolder(string dir)
        {
            for (int i = 0; ; i++)
            {
                try { if (Directory.Exists(dir)) Directory.Delete(dir, true); return null; }
                catch (Exception ex) { if (i >= 20) return ex.Message; Thread.Sleep(500); }
            }
        }

        private static int FreePort()
        {
            var l = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
            l.Start();
            try { return ((IPEndPoint)l.LocalEndpoint).Port; }
            finally { l.Stop(); }
        }

        private static string RandomHex(int n)
        {
            var b = new byte[(n + 1) / 2];
            using (var rng = new System.Security.Cryptography.RNGCryptoServiceProvider()) rng.GetBytes(b);
            return string.Concat(b.Select(x => x.ToString("x2"))).Substring(0, n);
        }

        /// <summary>24 random characters with upper and lower case letters, digits and symbols (meets the Windows complexity rule).</summary>
        private static string RandomPassword()
        {
            const string upper = "ABCDEFGHJKLMNPQRSTUVWXYZ", lower = "abcdefghijkmnopqrstuvwxyz", digits = "23456789", symbols = "!#%+-.=?@_~";
            var all = upper + lower + digits + symbols;
            var b = new byte[24];
            using (var rng = new System.Security.Cryptography.RNGCryptoServiceProvider()) rng.GetBytes(b);
            var sb = new StringBuilder();
            sb.Append(upper[b[0] % upper.Length]).Append(lower[b[1] % lower.Length]).Append(digits[b[2] % digits.Length]).Append(symbols[b[3] % symbols.Length]);
            for (int i = 4; i < b.Length; i++) sb.Append(all[b[i] % all.Length]);
            return sb.ToString();
        }

        private static string LogTail(string path, int lines)
        {
            try
            {
                if (!File.Exists(path)) return "      (no sshd log)";
                string text;
                using (var f = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                using (var r = new StreamReader(f)) text = r.ReadToEnd();
                var all = text.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                return string.Join(Environment.NewLine, all.Skip(Math.Max(0, all.Length - lines)).Select(l => "      | " + l));
            }
            catch (Exception ex) { return "      (sshd log not readable: " + ex.Message + ")"; }
        }
    }
}

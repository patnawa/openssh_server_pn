// OpenSSH Server Manager for Windows: AuthTest

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

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)] private static extern int NetUserAdd(string server, int level, ref Accounts.USER_INFO_1 info, out int parmError);
        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)] private static extern int NetUserDel(string server, string user);
        [DllImport("userenv.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool DeleteProfile(string sid, string profilePath, string computer);
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

                sb.AppendLine("OpenSSH Server Manager " + Program.AppVersion + " login-method test");
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
                    var e = RemoveAccount(user, sid, out note);
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

        private static string RunCase(Case c, SshdConfig baseCfg, string cfgPath, string service, int port, string user, string password, string key, string knownHosts, string authorizedKeys)
        {
            var cfg = new SshdConfig { Lines = baseCfg.Lines.ToList(), NewLine = baseCfg.NewLine, Path = cfgPath };
            AuthConfig.Apply(cfg, c.Global, c.Rules); // exactly what the Authentication tab writes
            cfg.Set("Port", port.ToString());
            cfg.Set("ListenAddress", "127.0.0.1");
            foreach (var k in new[] { "AllowUsers", "AllowGroups", "DenyUsers", "DenyGroups" }) cfg.Set(k, "");
            cfg.Set("AuthorizedKeysFile", "\"" + authorizedKeys.Replace('\\', '/') + "\"");
            cfg.Set("PerSourcePenalties", "no");
            File.WriteAllText(cfgPath, cfg.Text, new UTF8Encoding(false));
            var t = Ssh.TestConfig(cfgPath);
            if (!t.Ok) throw new Exception("sshd -t rejected the configuration: " + t.Output);
            RestartTestService(service, port);
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
                IntPtr svc = CreateService(scm, name, "OpenSSH Server Manager login-method test (temporary)", 0xF01FF /*SERVICE_ALL_ACCESS*/, 0x10 /*SERVICE_WIN32_OWN_PROCESS*/,
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
            var info = new Accounts.USER_INFO_1
            {
                Name = name, Password = password, Priv = 1 /*USER_PRIV_USER*/,
                Comment = "Temporary account of OpenSSH Server Manager --authtest, deleted when the test ends",
                Flags = 0x0001 /*UF_SCRIPT*/ | 0x10000 /*UF_DONT_EXPIRE_PASSWD*/,
            };
            int parm;
            int rc = NetUserAdd(null, 1, ref info, out parm);
            if (rc != 0) throw new Exception("could not create the temporary account " + name + " (NetUserAdd error " + rc + (rc == 2245 ? ": the password does not meet the password policy" : "") + ")");
        }

        [StructLayout(LayoutKind.Sequential)] private struct LOCALGROUP_MEMBERS_INFO_0 { public IntPtr Sid; }
        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)] private static extern int NetLocalGroupAddMembers(string server, string group, int level, ref LOCALGROUP_MEMBERS_INFO_0 members, int count);

        private static void AddToUsers(SecurityIdentifier sid)
        {
            var users = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null).Translate(typeof(NTAccount)).Value; // BUILTIN\Users in the system language
            var bytes = new byte[sid.BinaryLength]; sid.GetBinaryForm(bytes, 0);
            var p = Marshal.AllocHGlobal(bytes.Length);
            try
            {
                Marshal.Copy(bytes, 0, p, bytes.Length);
                var m = new LOCALGROUP_MEMBERS_INFO_0 { Sid = p };
                int rc = NetLocalGroupAddMembers(null, users.Substring(users.IndexOf('\\') + 1), 0, ref m, 1);
                if (rc != 0 && rc != 1378 /*ERROR_MEMBER_IN_ALIAS*/) throw new Exception("could not add the temporary account to " + users + " (error " + rc + ")");
            }
            finally { Marshal.FreeHGlobal(p); }
        }

        /// <summary>
        /// Deletes the account and its profile. sshd loads the profile at login and never unloads it (win32_usertoken_utils.c),
        /// so Windows keeps it loaded, and undeletable, until the next restart: then a one-time startup task deletes it.
        /// </summary>
        private static string RemoveAccount(string name, SecurityIdentifier sid, out string note)
        {
            note = null;
            var problems = new List<string>();
            var profile = Accounts.ProfileDir(sid);
            bool profileGone = profile == null || DeleteProfile(sid.Value, null, null) || Accounts.ProfileDir(sid) == null;
            int rc = NetUserDel(null, name);
            if (rc != 0 && rc != 2221 /*NERR_UserNotFound*/) problems.Add("NetUserDel error " + rc);
            if (!profileGone)
            {
                try
                {
                    var task = SystemTasks.ScheduleProfileRemoval(sid, name);
                    note = "Windows keeps its profile " + profile + " loaded (sshd does not unload profiles), so the one-time task \"" + task + "\" deletes it at the next restart";
                }
                catch (Exception ex) { problems.Add("the profile " + profile + " is still loaded and its removal could not be scheduled: " + ex.Message); }
            }
            else if (profile != null) note = "its profile " + profile + " is deleted";
            return problems.Count == 0 ? null : string.Join("; ", problems);
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

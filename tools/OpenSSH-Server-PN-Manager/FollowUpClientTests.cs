using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Security.Principal;
using System.Text;
using System.Windows.Forms;

namespace OpenSSHServerPNManager
{
    /// <summary>Regressions for the client workspace (October 2026 follow-up review).</summary>
    internal static class FollowUpClientTests
    {
        private static byte[] Bytes(params object[] parts)
        {
            var result = new List<byte>();
            foreach (var part in parts) result.AddRange(part is string ? Encoding.ASCII.GetBytes((string)part) : (byte[])part);
            return result.ToArray();
        }

        internal static void Run(Action<string, Func<string>> test, string tmpDir)
        {
            var thai = new byte[] { 0xCA, 0xC7, 0xD1, 0xCA, 0xB4, 0xD5 }; // a cp874 comment, as Notepad saves it on a Thai system

            test("client launcher: a full-token desktop of the same account gets a medium, non-administrator token", () =>
            {
                if (UserProcessLauncher.Plan(false, true, false) != UserProcessLauncher.LaunchPlan.Direct || UserProcessLauncher.Plan(false, false, true) != UserProcessLauncher.LaunchPlan.Direct) throw new Exception("an unelevated caller did not start directly");
                if (UserProcessLauncher.Plan(true, false, true) != UserProcessLauncher.LaunchPlan.ShellParent || UserProcessLauncher.Plan(true, false, false) != UserProcessLauncher.LaunchPlan.ShellParent) throw new Exception("a filtered desktop token is not borrowed");
                if (UserProcessLauncher.Plan(true, true, true) != UserProcessLauncher.LaunchPlan.RestrictedSelf) throw new Exception("the built-in Administrator (or UAC off) is still refused");
                if (UserProcessLauncher.Plan(true, true, false) != UserProcessLauncher.LaunchPlan.Refuse) throw new Exception("another account's full-token desktop was accepted");
                var token = UserProcessLauncher.ReducedToken();
                try
                {
                    using (var identity = new WindowsIdentity(token))
                    using (var self = WindowsIdentity.GetCurrent())
                    {
                        if (new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator)) throw new Exception("the reduced token is an administrator: --client would restart itself");
                        if (identity.User != self.User) throw new Exception("the reduced token belongs to another account");
                    }
                    if (UserProcessLauncher.IntegrityLevel(token) != "S-1-16-8192") throw new Exception("the reduced token is not at medium integrity: " + UserProcessLauncher.IntegrityLevel(token));
                }
                finally { UserProcessLauncher.Release(token); }
                return Elevation.IsAdministrator() ? "checked from an administrator token" : null;
            });
            test("client launcher: a process started by an elevation request never requests it again", () =>
            {
                if (!Elevation.RelaunchAllowed(new[] { "manager.exe", "--server" })) throw new Exception("a first elevation request was refused");
                if (Elevation.RelaunchAllowed(new[] { "manager.exe", "--server", "--elevation-requested" }) || Elevation.RelaunchAllowed(new[] { "manager.exe", "--start-client-agent", "--ELEVATION-REQUESTED" })) throw new Exception("without UAC a relaunched process would relaunch without end");
                return null;
            });
            test("client launcher: ssh and sftp start in the user's profile folder", () =>
            {
                const string sftp = @"C:\Program Files\OpenSSH\sftp.exe", profile = @"C:\Users\alice";
                if (UserProcessLauncher.StartDirectory(profile, sftp, p => true) != profile) throw new Exception("sftp would save downloads in the program folder");
                foreach (var missing in new[] { null, "", @"C:\Users\gone" })
                    if (UserProcessLauncher.StartDirectory(missing, sftp, p => false) != @"C:\Program Files\OpenSSH") throw new Exception("a missing profile did not fall back to the program folder");
                return null;
            });
            test("client launcher: another user's desktop is refused with the Start-menu remedy", () =>
            {
                var denied = UserProcessLauncher.ShellAccessError(5);
                if (!(denied is InvalidOperationException) || !denied.Message.Contains("OpenSSH Client PN")) throw new Exception("access denied is not explained: " + denied.Message);
                var other = UserProcessLauncher.ShellAccessError(2) as Win32Exception;
                if (other == null || other.NativeErrorCode != 2) throw new Exception("other errors lost their Windows text");
                return null;
            });
            test("client launcher: a failed connection keeps its console open", () =>
            {
                const string ssh = @"C:\Program Files\OpenSSH\ssh.exe";
                var line = UserProcessLauncher.ConsoleCommandLine(ssh, "-- host1");
                if (line != "/d /s /c \"\"C:\\Program Files\\OpenSSH\\ssh.exe\" -- host1 || pause\"") throw new Exception(line);
                if (UserProcessLauncher.ConsoleCommandLine(@"C:\Program Files (x86)\OpenSSH\ssh.exe", "-- host1") == null) throw new Exception("a quoted program path with parentheses was refused");
                foreach (var name in new[] { "a%PATH%b", "a&calc", "a|b", "a^b", "a(b)", "a<b", "a>b", "a\"b", "a!b!", "web-1.example", "a+b_c" })
                {
                    var console = UserProcessLauncher.ConsoleCommandLine(ssh, "-- " + name);
                    if (name.IndexOfAny("%!^&|<>()\"".ToCharArray()) >= 0 ? console != null : console == null) throw new Exception("cmd would interpret " + name);
                }
                return null;
            });
            test("client hosts: names sftp would split are refused for Connect and SFTP", () =>
            {
                foreach (var name in new[] { "fe80::1", "web:8022", "alice@server", "[fe80::1]", "fe80::1%3" })
                {
                    var problem = SshClient.ConnectProblem(new ClientHost { Pattern = name });
                    if (problem == null || !problem.Contains("plain name") || SshClient.Connectable(new ClientHost { Pattern = name })) throw new Exception("sftp would connect to another host for " + name);
                }
                if (SshClient.ConnectProblem(new ClientHost { Pattern = "web-1.example" }) != null) throw new Exception("a plain name was refused");
                return null;
            });
            test("client files: an ANSI config loads, keeps its bytes when edited and refuses characters it cannot hold", () =>
            {
                var path = Path.Combine(tmpDir, "client-ansi");
                var original = Bytes("# ", thai, "\r\nHost web\r\n    HostName web.example\r\n");
                File.WriteAllBytes(path, original);
                var snapshot = ClientFileSnapshot.Read(path);
                var hosts = SshClient.ParseConfig(snapshot.Lines);
                if (!snapshot.NotUtf8 || hosts.Count != 1 || hosts[0].Get("HostName") != "web.example") throw new Exception("the hosts of an ANSI file were not read");
                try { snapshot.Write(SshClient.WithHost(snapshot.Lines, hosts[0], "web", new Dictionary<string, string> { { "User", "\u0e2a\u0e21" } }), ".bak", false); throw new Exception("Thai text was written into an ANSI file"); }
                catch (ConfigException ex) { if (!ex.Message.Contains("UTF-8")) throw new Exception("unclear refusal: " + ex.Message); }
                if (!File.ReadAllBytes(path).SequenceEqual(original) || File.Exists(path + ".bak")) throw new Exception("a refused edit changed the file");
                snapshot.Write(SshClient.WithHost(snapshot.Lines, hosts[0], "web", new Dictionary<string, string> { { "HostName", "web2.example" } }), ".bak", false);
                if (!File.ReadAllBytes(path).SequenceEqual(Bytes("# ", thai, "\r\nHost web\r\n    HostName web2.example\r\n"))) throw new Exception("the edit changed the bytes of other lines");
                return null;
            });
            test("client files: ANSI bytes after a UTF-8 BOM are kept, and UTF-8 and UTF-16 files still round-trip", () =>
            {
                var path = Path.Combine(tmpDir, "client-bom-ansi");
                File.WriteAllBytes(path, Bytes(new byte[] { 0xEF, 0xBB, 0xBF }, "# ", thai, "\r\nHost a\r\n"));
                var snapshot = ClientFileSnapshot.Read(path);
                var hosts = SshClient.ParseConfig(snapshot.Lines);
                if (hosts.Count != 1 || hosts[0].Pattern != "a") throw new Exception("the byte order mark hid the first line");
                snapshot.Write(SshClient.WithHost(snapshot.Lines, hosts[0], "a", new Dictionary<string, string> { { "HostName", "a.example" } }), ".bak", false);
                if (!File.ReadAllBytes(path).SequenceEqual(Bytes(new byte[] { 0xEF, 0xBB, 0xBF }, "# ", thai, "\r\nHost a\r\n    HostName a.example\r\n"))) throw new Exception("ANSI bytes behind a BOM were replaced");
                var utf8 = Path.Combine(tmpDir, "client-utf8");
                File.WriteAllBytes(utf8, new UTF8Encoding(false).GetBytes("# \u0e17\u0e14\u0e2a\u0e2d\u0e1a\nHost a\n"));
                snapshot = ClientFileSnapshot.Read(utf8);
                snapshot.Write(SshClient.WithHost(snapshot.Lines, SshClient.ParseConfig(snapshot.Lines)[0], "a", new Dictionary<string, string> { { "User", "\u0e2a\u0e21" } }), ".bak", false);
                if (snapshot.NotUtf8 || !File.ReadAllBytes(utf8).SequenceEqual(new UTF8Encoding(false).GetBytes("# \u0e17\u0e14\u0e2a\u0e2d\u0e1a\nHost a\n    User \u0e2a\u0e21\n"))) throw new Exception("UTF-8 text did not round-trip");
                var utf16 = Path.Combine(tmpDir, "client-utf16");
                File.WriteAllBytes(utf16, Bytes(new byte[] { 0xFF, 0xFE }, Encoding.Unicode.GetBytes("Host a\r\n")));
                snapshot = ClientFileSnapshot.Read(utf16);
                snapshot.Write(new[] { "Host b" }, ".bak", false);
                if (!File.ReadAllBytes(utf16).SequenceEqual(Bytes(new byte[] { 0xFF, 0xFE }, Encoding.Unicode.GetBytes("Host b\r\n")))) throw new Exception("UTF-16 did not round-trip");
                return null;
            });
            test("client files: an ANSI known_hosts loads and takes new keys", () =>
            {
                var path = Path.Combine(tmpDir, "client-ansi-known-hosts");
                var original = Bytes("# ", thai, "\nhost-a ssh-ed25519 AAAA\n");
                File.WriteAllBytes(path, original);
                if (SshClient.ReadKnownHosts(path, false).Count != 1) throw new Exception("the entries of an ANSI known_hosts were not read");
                if (SshClient.AddKnownHosts(ClientFileSnapshot.Read(path), new[] { "host-b ssh-ed25519 BBBB" }) != 1) throw new Exception("the new key was not added");
                if (!File.ReadAllBytes(path).SequenceEqual(Bytes(original, "host-b ssh-ed25519 BBBB\n"))) throw new Exception("adding a key changed other bytes");
                return null;
            });
            test("client files: one unreadable part of the Client tab is reported, not thrown", () =>
            {
                var errors = new List<string>();
                var part = typeof(MainForm).GetMethod("ClientPart", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static).MakeGenericMethod(typeof(string));
                var result = part.Invoke(null, new object[] { "known_hosts", (Func<string>)(() => { throw new UnauthorizedAccessException("denied"); }), errors });
                if (result != null || errors.Count != 1 || errors[0] != "known_hosts: denied") throw new Exception("a failed part was not reported: " + string.Join("; ", errors));
                if ((string)part.Invoke(null, new object[] { "config", (Func<string>)(() => "read"), errors }) != "read" || errors.Count != 1) throw new Exception("a readable part was lost");
                return null;
            });
            test("client files: an append between the last check and the replace is reported and kept", () =>
            {
                var path = Path.Combine(tmpDir, "client-late-append");
                File.WriteAllText(path, "host-a ssh-ed25519 AAAA\n");
                var snapshot = ClientFileSnapshot.Read(path);
                snapshot.BeforeReplace = () => File.AppendAllText(path, "host-b ssh-ed25519 BBBB\n");
                try { snapshot.Write(new[] { "host-a ssh-ed25519 AAAA", "host-c ssh-ed25519 CCCC" }, ".old", false); throw new Exception("a concurrent append was silently moved to the backup"); }
                catch (ConfigException ex) { if (!ex.Message.Contains(path + ".old")) throw new Exception("the message does not name the backup: " + ex.Message); }
                if (!File.ReadAllText(path + ".old").Contains("host-b") || !File.ReadAllText(path).Contains("host-c")) throw new Exception("the append or the edit is gone");
                return null;
            });
            test("client files: a replace that fails after another program wrote keeps the edit", () =>
            {
                var path = Path.Combine(tmpDir, "client-replace-race");
                File.WriteAllText(path, "original\n");
                var snapshot = ClientFileSnapshot.Read(path);
                FileStream held = null;
                snapshot.BeforeReplace = () => { File.WriteAllText(path, "other\n"); held = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read); };
                try { snapshot.Write(new[] { "ours" }, ".bak", false); throw new Exception("the failed replace was not reported"); }
                catch (ConfigException ex) { if (!ex.Message.Contains(path + ".unsaved")) throw new Exception("the message does not name the kept edit: " + ex.Message); }
                finally { if (held != null) held.Dispose(); }
                if (File.ReadAllText(path + ".unsaved") != "ours\n") throw new Exception("the edit was deleted");
                if (File.ReadAllText(path) != "other\n") throw new Exception("the other program's version was overwritten");
                if (Directory.GetFiles(tmpDir, ".pn-client-*.tmp").Length != 0) throw new Exception("a temporary file was left behind");
                return null;
            });
            test("client files: a failed replace never offers a backup from an earlier save as the displayed version", () =>
            {
                var path = Path.Combine(tmpDir, "client-stale-backup");
                File.WriteAllText(path + ".bak", "older\n");
                File.WriteAllText(path, "original\n");
                var snapshot = ClientFileSnapshot.Read(path);
                FileStream held = null;
                snapshot.BeforeReplace = () => { File.WriteAllText(path, "other\n"); held = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read); };
                try { snapshot.Write(new[] { "ours" }, ".bak", false); throw new Exception("the failed replace was not reported"); }
                catch (ConfigException ex)
                {
                    if (!ex.Message.Contains(path + ".unsaved")) throw new Exception("the message does not name the kept edit: " + ex.Message);
                    if (ex.Message.Contains(path + ".bak")) throw new Exception("the stale backup is offered as the displayed version: " + ex.Message);
                }
                finally { if (held != null) held.Dispose(); }
                if (File.ReadAllText(path + ".bak") != "older\n" || File.ReadAllText(path) != "other\n") throw new Exception("a file other than the edit changed");
                return null;
            });
            test("client files: a file another program holds open is reported as not replaced, not as a part-way save", () =>
            {
                var path = Path.Combine(tmpDir, "client-held-open");
                File.WriteAllText(path + ".old", "older\n");
                File.WriteAllText(path, "host-a ssh-ed25519 AAAA\n");
                var snapshot = ClientFileSnapshot.Read(path);
                FileStream writer = null;
                // As ssh opens known_hosts to append an accepted key: write access, no delete sharing.
                snapshot.BeforeReplace = () => { writer = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.ReadWrite); };
                try { snapshot.Write(new[] { "host-a ssh-ed25519 AAAA", "host-b ssh-ed25519 BBBB" }, ".old", false); throw new Exception("the failed replace was not reported"); }
                catch (ConfigException ex)
                {
                    if (!ex.Message.Contains("not replaced") || ex.Message.Contains("part-way") || ex.Message.Contains(".unsaved") || ex.Message.Contains(path + ".old")) throw new Exception("an untouched file is reported as a part-way save: " + ex.Message);
                }
                finally { if (writer != null) writer.Dispose(); }
                if (File.ReadAllText(path) != "host-a ssh-ed25519 AAAA\n" || File.ReadAllText(path + ".old") != "older\n" || File.Exists(path + ".unsaved")) throw new Exception("the files changed");
                if (Directory.GetFiles(tmpDir, ".pn-client-*.tmp").Length != 0) throw new Exception("a temporary file was left behind");
                return null;
            });
            test("known hosts: an already trusted key is still a conflict when the file changed after it was displayed", () =>
            {
                var path = Path.Combine(tmpDir, "client-trusted-stale");
                File.WriteAllText(path, "server ssh-ed25519 AAAA\n");
                var snapshot = ClientFileSnapshot.Read(path);
                File.WriteAllText(path, ""); // ssh-keygen -R server while the trust dialog is open
                try { SshClient.AddKnownHosts(snapshot, new[] { "server ssh-ed25519 AAAA" }); throw new Exception("the removed key is reported as already present"); }
                catch (ConfigException ex) { if (!ex.Message.Contains("changed after it was displayed")) throw new Exception("not a conflict: " + ex.Message); }
                if (File.ReadAllText(path) != "") throw new Exception("the file was written");
                return null;
            });
            test("client hosts: changing the key list keeps the escaped path ssh read", () =>
            {
                foreach (var raw in new[] { @"C:\Users\Jane\ Doe\.ssh\id", @"~/.ssh/id\ work" })
                {
                    var lines = new List<string> { "Host example", "    IdentityFile " + raw + " # first key" };
                    var host = SshClient.ParseConfig(lines)[0];
                    var result = SshClient.WithHost(lines, host, "example", new Dictionary<string, string> { { "IdentityFile", host.GetAll("IdentityFile")[0] + "\n~/.ssh/second" } });
                    var values = SshClient.ParseConfig(result)[0].GetAll("IdentityFile");
                    string error; var first = SshdArgs.Split(values[0], out error);
                    if (values.Count != 2 || first == null || first.Count != 1 || first[0] != raw.Replace("\\ ", " ")) throw new Exception("ssh would read another path: " + string.Join(" | ", values));
                    if (!result.Contains("    IdentityFile " + raw + " # first key")) throw new Exception("the unchanged line was rewritten");
                }
                return null;
            });
            test("client hosts: removing a host keeps the next block's header comment", () =>
            {
                var lines = new List<string> { "Host a", "    HostName a.example", "", "# Production database", "Host b", "    HostName b.example" };
                var removed = SshClient.WithoutHost(lines, SshClient.ParseConfig(lines)[0]);
                if (!removed.SequenceEqual(new[] { "# Production database", "Host b", "    HostName b.example" })) throw new Exception(string.Join("|", removed));
                lines = new List<string> { "Host a", "  User x", "# header b", "Host b" };
                removed = SshClient.WithoutHost(lines, SshClient.ParseConfig(lines)[0]);
                if (!removed.SequenceEqual(new[] { "# header b", "Host b" })) throw new Exception(string.Join("|", removed));
                return null;
            });
            test("client hosts: % in HostName is escaped and % tokens ssh cannot expand are refused", () =>
            {
                Func<string, string, List<string>> add = (k, v) => SshClient.WithHost(new string[0], null, "x", new Dictionary<string, string> { { k, v } });
                if (!add("HostName", "fe80::1%12").Contains("    HostName fe80::1%%12")) throw new Exception("an IPv6 zone was not escaped");
                if (!add("HostName", "%h.example.com").Contains("    HostName %h.example.com") || !add("HostName", "fe80::1%%12").Contains("    HostName fe80::1%%12")) throw new Exception("%h or %% was escaped again");
                foreach (var bad in new[] { new[] { "IdentityFile", "%USERPROFILE%\\.ssh\\id_ed25519" }, new[] { "IdentityFile", "C:/k/key%" }, new[] { "User", "a%b" } })
                {
                    try { add(bad[0], bad[1]); throw new Exception("ssh would stop on " + bad[1]); }
                    catch (ConfigException ex) { if (bad[1].StartsWith("%USERPROFILE%") && !ex.Message.Contains("${USERPROFILE}")) throw new Exception("no ${VAR} hint: " + ex.Message); }
                }
                if (SshClient.ParseConfig(add("IdentityFile", "~/.ssh/%r@%h\n%d/.ssh/id"))[0].GetAll("IdentityFile").Count != 2 || !add("User", "%u").Contains("    User %u")) throw new Exception("valid tokens were refused");
                var lines = new List<string> { "Host old", "    HostName old.example", "    IdentityFile %USERPROFILE%\\x" };
                var host = SshClient.ParseConfig(lines)[0];
                var edited = SshClient.WithHost(lines, host, "old", new Dictionary<string, string> { { "HostName", "new.example" }, { "User", "" }, { "Port", "" }, { "IdentityFile", "%USERPROFILE%\\x" }, { "ProxyJump", "" } });
                if (!edited.Contains("    IdentityFile %USERPROFILE%\\x")) throw new Exception("an unchanged value was checked again");
                if (SshClient.PercentProblem(host, new Dictionary<string, string> { { "IdentityFile", "%USERPROFILE%\\x\n%APPDATA%\\y" } }) == null) throw new Exception("the dialog check missed a new line");
                return null;
            });
            test("known hosts: a key trusted under a hashed name is not added again in clear text", () =>
            {
                var salt = Encoding.UTF8.GetBytes("follow-up-salt");
                string entry;
                using (var hash = new System.Security.Cryptography.HMACSHA1(salt)) entry = "|1|" + Convert.ToBase64String(salt) + "|" + Convert.ToBase64String(hash.ComputeHash(Encoding.UTF8.GetBytes("[example]:2222")));
                var path = Path.Combine(tmpDir, "client-hashed-add");
                File.WriteAllText(path, entry + " ssh-ed25519 AAAA\n");
                var before = File.ReadAllBytes(path);
                if (SshClient.AddKnownHosts(ClientFileSnapshot.Read(path), new[] { "[example]:2222 ssh-ed25519 AAAA" }) != 0 || !File.ReadAllBytes(path).SequenceEqual(before) || File.Exists(path + ".old")) throw new Exception("the hashed host name was added in clear text");
                if (SshClient.AddKnownHosts(ClientFileSnapshot.Read(path), new[] { "[example]:2222 ssh-ed25519 BBBB" }) != 1 || !File.ReadAllText(path).Contains("[example]:2222 ssh-ed25519 BBBB")) throw new Exception("a rotated key was not added");
                var wildcard = Path.Combine(tmpDir, "client-wildcard-add");
                File.WriteAllText(wildcard, "*.example ssh-ed25519 AAAA\n");
                if (SshClient.AddKnownHosts(ClientFileSnapshot.Read(wildcard), new[] { "web.example ssh-ed25519 AAAA" }) != 0) throw new Exception("a wildcard entry did not cover the host");
                return null;
            });
            test("theme: leaving high contrast restores plain text, not grey", () =>
            {
                var saved = Theme.Current;
                try
                {
                    using (var form = new Form())
                    using (var panel = new Panel())
                    using (var label = new Label { Text = "Plain" })
                    using (var group = new GroupBox { Text = "Group" })
                    {
                        panel.Controls.Add(label); form.Controls.Add(panel); form.Controls.Add(group);
                        var hc = Theme.Make(false, true);
                        Theme.Current = hc; Theme.Apply(form, null);
                        var light = Theme.Make(false, false);
                        Theme.Current = light; Theme.Apply(form, hc);
                        foreach (Control c in new Control[] { label, panel, group })
                            if (c.ForeColor.ToArgb() != light.Text.ToArgb()) throw new Exception(c.GetType().Name + " turned " + c.ForeColor + " after high contrast");
                        Theme.Current = Theme.Make(true, false); Theme.Apply(form, light);
                        if (label.ForeColor.ToArgb() != Theme.Current.Text.ToArgb()) throw new Exception("the next switch to dark kept a muted colour");
                    }
                }
                finally { Theme.Current = saved; }
                return null;
            });
        }
    }
}

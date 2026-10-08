using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace OpenSSHServerPNManager
{
    internal static class ClientRegressionTests
    {
        /// <summary>Optional differential check against a real client, using only a generated configuration.</summary>
        public static void RunWithSsh(string sshExe, string tmpDir)
        {
            foreach (bool global in new[] { false, true })
            {
                var before = global ? new[] { "User default", "Port 22", "Host existing", "HostName existing.invalid" } : new[] { "Host *", "User default", "Port 22" };
                var candidate = SshClient.WithHost(before, null, "example", new Dictionary<string, string> { { "HostName", "example.invalid" }, { "User", "alice" }, { "Port", "2222" }, { "IdentityFile", "~/.ssh/first\n~/.ssh/second" } });
                var path = Path.Combine(tmpDir, "client-effective-" + global + ".conf");
                File.WriteAllLines(path, candidate);
                var run = Proc.Run(sshExe, "-G -F " + Proc.Quote(path) + " -- example", 15000);
                if (!run.Ok) throw new Exception(run.Output);
                var output = run.StdOut.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                foreach (var expected in new[] { "hostname example.invalid", "user alice", "port 2222", "identityfile ~/.ssh/first", "identityfile ~/.ssh/second" })
                    if (!output.Contains(expected)) throw new Exception("ssh -G did not report " + expected + " (global=" + global + ")");
                run = Proc.Run(sshExe, "-G -F " + Proc.Quote(path) + " -- unrelated", 15000);
                if (!run.Ok || !run.StdOut.Contains("user default") || !run.StdOut.Contains("port 22")) throw new Exception("New profile changed unrelated host defaults");
            }
        }

        public static void Run(Action<string, Func<string>> test, string tmpDir)
        {
            test("client regression: custom client-only installs use sibling tools without redirecting server execution", () =>
            {
                const string client = @"D:\Custom Client", server = @"C:\Program Files\Other OpenSSH";
                foreach (var name in new[] { "ssh.exe", "ssh-keygen.exe", "ssh-add.exe", "ssh-agent.exe", "ssh-keyscan.exe", "scp.exe", "sftp.exe" })
                {
                    if (Ssh.ResolveExecutable(name, true, false, client, server, p => true) != Path.Combine(client, name)) throw new Exception("Sibling client tool ignored: " + name);
                    if (Ssh.ResolveExecutable(name, true, false, client, server, p => false) != Path.Combine(server, name)) throw new Exception("Missing sibling did not fall back");
                    if (Ssh.ResolveExecutable(name, true, true, client, server, p => true) != Path.Combine(server, name) ||
                        Ssh.ResolveExecutable(name, false, false, client, server, p => true) != Path.Combine(server, name)) throw new Exception("Server/elevated execution was redirected");
                }
                if (Ssh.ResolveExecutable("sshd.exe", true, false, client, server, p => true) != Path.Combine(server, "sshd.exe")) throw new Exception("Server executable redirected to client payload");
                return null;
            });
            test("client regression: stale trust selection cannot delete another host", () =>
            {
                var path = Path.Combine(tmpDir, "known_hosts");
                File.WriteAllText(path, "host-a ssh-ed25519 AAAA\nhost-b ssh-ed25519 BBBB\n");
                var selected = SshClient.ReadKnownHosts(path, false)[1];
                File.WriteAllText(path, "# inserted externally\n" + File.ReadAllText(path));
                try { SshClient.RemoveKnownHosts(path, new[] { selected }); } catch (ConfigException) { }
                if (!File.ReadAllText(path).Contains("host-a ssh-ed25519 AAAA")) throw new Exception("Deleted host-a from a stale host-b selection");
                if (!File.ReadAllText(path).Contains("host-b ssh-ed25519 BBBB")) throw new Exception("A stale selection was not rejected");
                return null;
            });
            test("client regression: editing host preserves repeated identities", () =>
            {
                var lines = new List<string> { "Host example", "    HostName old", "    IdentityFile ~/.ssh/one", "    IdentityFile ~/.ssh/two", "    ForwardAgent no" };
                var host = SshClient.ParseConfig(lines)[0];
                var values = new Dictionary<string, string> { { "HostName", "new" } };
                var result = SshClient.WithHost(lines, host, "example", values);
                if (!result.Contains("    IdentityFile ~/.ssh/one") || !result.Contains("    IdentityFile ~/.ssh/two")) throw new Exception("Editing HostName discarded an identity");
                return null;
            });
            test("client regression: new specific host precedes defaults", () =>
            {
                var result = SshClient.WithHost(new[] { "# personal hosts", "Host *", " User default", " Port 22" }, null, "example", new Dictionary<string, string> { { "User", "alice" }, { "Port", "2222" } });
                if (result.IndexOf("Host example") > result.IndexOf("Host *")) throw new Exception("Wildcard defaults override the added host");
                return null;
            });
            test("client regression: authorized-key quoted path", () =>
            {
                var path = Ssh.ResolveKeysFile("\"C:/Keys dir/%u\" .ssh/second", "alice", @"C:\Users\alice");
                if (path != @"C:\Keys dir\alice") throw new Exception(path);
                return null;
            });
            test("client regression: authorized-key percent is expanded once", () =>
            {
                var path = Ssh.ResolveKeysFile(".ssh/%%u", "alice", @"C:\Users\alice");
                if (path != @"C:\Users\alice\.ssh\%u") throw new Exception(path);
                return null;
            });
            test("client regression: stale configuration save preserves external edit", () =>
            {
                var path = Path.Combine(tmpDir, "client-conflict");
                File.WriteAllText(path, "Host example\n User before\n");
                var snapshot = ClientFileSnapshot.Read(path);
                File.WriteAllText(path, "Host external\n User changed\n");
                try { SshClient.WriteConfig(snapshot, new[] { "Host example", " User after" }); throw new Exception("stale save was accepted"); }
                catch (ConfigException) { }
                if (File.ReadAllText(path) != "Host external\n User changed\n") throw new Exception("External edits were overwritten");
                return null;
            });
            test("client regression: deleted and newly created files are conflicts", () =>
            {
                var path = Path.Combine(tmpDir, "client-create-conflict");
                var missing = ClientFileSnapshot.Read(path);
                File.WriteAllText(path, "external");
                try { missing.Write(new[] { "ours" }, ".bak", false); throw new Exception("creation conflict missed"); } catch (ConfigException) { }
                var existing = ClientFileSnapshot.Read(path);
                File.Delete(path);
                try { existing.Write(new[] { "ours" }, ".bak", false); throw new Exception("deletion conflict missed"); } catch (ConfigException) { }
                return null;
            });
            test("client regression: concurrent processes saving one snapshot produce one commit and one conflict", () =>
            {
                var path = Path.Combine(tmpDir, "client-process-conflict"); File.WriteAllText(path, "original\n");
                var snapshot = ClientFileSnapshot.Read(path);
                var worker = Path.Combine(tmpDir, "client-writer-fixture.exe");
                const string code = @"using System; using System.IO; using System.Reflection;
class Fixture { static int Main(string[] args) { try {
 var t=Assembly.LoadFrom(args[0]).GetType(""OpenSSHServerPNManager.ClientFileSnapshot"");
 var snapshot=t.GetMethod(""Read"").Invoke(null,new object[]{args[1]});
 File.WriteAllText(args[1]+"".ready"",""ready"");
 t.GetMethod(""Write"").Invoke(snapshot,new object[]{new[]{""child""},"".bak"",false}); return 0;
 } catch(TargetInvocationException ex) { if(ex.InnerException.GetType().Name==""ConfigException"") return 3; Console.Error.WriteLine(ex); return 1; }
 catch(Exception ex) { Console.Error.WriteLine(ex); return 2; } } }";
                using (var compiler = new Microsoft.CSharp.CSharpCodeProvider())
                {
                    var options = new System.CodeDom.Compiler.CompilerParameters { GenerateExecutable = true, OutputAssembly = worker };
                    if (compiler.CompileAssemblyFromSource(options, code).Errors.HasErrors) throw new Exception("Could not compile client writer fixture");
                }
                System.Diagnostics.Process child = null;
                try
                {
                    ConfigurationTransaction.Locked(path, () =>
                    {
                        child = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(worker, Proc.Quote(typeof(ClientFileSnapshot).Assembly.Location) + " " + Proc.Quote(path)) { UseShellExecute = false, CreateNoWindow = true });
                        var until = DateTime.UtcNow.AddSeconds(5);
                        while (!File.Exists(path + ".ready") && DateTime.UtcNow < until && !child.HasExited) System.Threading.Thread.Sleep(10);
                        if (!File.Exists(path + ".ready")) throw new Exception("Child did not capture the original snapshot");
                        if (child.WaitForExit(200)) throw new Exception("Another process bypassed the configuration mutex");
                        snapshot.Write(new[] { "parent" }, ".bak", false);
                        return true;
                    });
                    if (!child.WaitForExit(5000) || child.ExitCode != 3) throw new Exception("The stale competing process did not report a conflict");
                    if (File.ReadAllText(path).Trim() != "parent" || File.ReadAllText(path + ".bak") != "original\n") throw new Exception("Competing process replaced the winner or backup");
                }
                finally { if (child != null) { if (!child.HasExited) { child.Kill(); child.WaitForExit(); } child.Dispose(); } }
                return null;
            });
            test("client regression: atomic save backs up original and refuses replacement failure", () =>
            {
                var path = Path.Combine(tmpDir, "client-atomic");
                var original = System.Text.Encoding.UTF8.GetBytes("# header\r\nHost example\r\n User old\r\n");
                File.WriteAllBytes(path, original);
                ClientFileSnapshot.Read(path).Write(new[] { "Host example", " User new" }, ".bak", false);
                if (!File.ReadAllBytes(path + ".bak").SequenceEqual(original)) throw new Exception("Backup bytes changed");
                if (File.ReadAllText(path) != "Host example\r\n User new\r\n") throw new Exception("Line endings changed");
                var snapshot = ClientFileSnapshot.Read(path);
                using (var held = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
                {
                    try { snapshot.Write(new[] { "would truncate" }, ".bak", false); throw new Exception("Sharing violation ignored"); } catch (IOException) { }
                }
                if (File.ReadAllText(path) != snapshot.Text) throw new Exception("Failed replacement truncated destination");
                return null;
            });
            test("client regression: deleting a current trust entry preserves all other bytes", () =>
            {
                var path = Path.Combine(tmpDir, "known-hosts-valid");
                File.WriteAllText(path, "# keep\nhost-a ssh-ed25519 AAAA\nhost-b ssh-ed25519 BBBB\n");
                var entries = SshClient.ReadKnownHosts(path, false);
                if (SshClient.RemoveKnownHosts(path, new[] { entries[1] }) != 1) throw new Exception("Removal count");
                if (File.ReadAllText(path) != "# keep\nhost-a ssh-ed25519 AAAA\n" || !File.ReadAllText(path + ".old").Contains("host-b")) throw new Exception("Wrong entry or missing backup");
                return null;
            });
            test("client regression: all identities are editable and unchanged options stay ordered", () =>
            {
                var lines = new[] { "Host example", " IdentityFile ~/.ssh/a # first", " IdentityFile ~/.ssh/b", " ProxyCommand custom --host %h", " ForwardAgent no" };
                var host = SshClient.ParseConfig(lines)[0];
                var unchanged = SshClient.WithHost(lines, host, host.Pattern, new Dictionary<string, string> { { "IdentityFile", string.Join("\n", host.GetAll("IdentityFile")) } });
                if (!unchanged.SequenceEqual(lines)) throw new Exception("Unchanged directives were rewritten");
                var changed = SshClient.WithHost(lines, host, host.Pattern, new Dictionary<string, string> { { "IdentityFile", "~/.ssh/c\nC:/Key dir/key" } });
                if (SshClient.ParseConfig(changed)[0].GetAll("IdentityFile").Count != 2 || !changed.Contains(" ProxyCommand custom --host %h")) throw new Exception("Identity edit lost settings");
                var reduced = SshClient.WithHost(lines, host, host.Pattern, new Dictionary<string, string> { { "IdentityFile", host.Get("IdentityFile") } });
                if (SshClient.ParseConfig(reduced)[0].GetAll("IdentityFile").Count != 1) throw new Exception("Removing the second identity did not take effect");
                return null;
            });
            test("client regression: new host precedes global Include and restores global scope", () =>
            {
                var lines = SshClient.WithHost(new[] { "# keep header", "Include defaults.conf", " User fallback", "Host old", " Port 222" }, null, "new", new Dictionary<string, string> { { "User", "alice" } });
                if (lines[0] != "# keep header" || lines.IndexOf("Host new") > lines.IndexOf("Include defaults.conf") || lines[lines.IndexOf("Include defaults.conf") - 1] != "Host *") throw new Exception(string.Join("|", lines));
                return null;
            });
            test("client regression: all authorized-key paths and literal tokens", () =>
            {
                var files = Ssh.ResolveKeysFiles("\"C:/Keys dir/%u\" .ssh/%%h .ssh/%%%u .ssh/%U", "alice", @"C:\Users\alice");
                if (!files.SequenceEqual(new[] { @"C:\Keys dir\alice", @"C:\Users\alice\.ssh\%h", @"C:\Users\alice\.ssh\%alice", @"C:\Users\alice\.ssh\1" })) throw new Exception(string.Join(";", files));
                if (Ssh.ResolveKeysFiles("none", "alice", null).Count != 0) throw new Exception("none produced a file");
                try { Ssh.ResolveKeysFiles("\"unclosed path", "alice", @"C:\Users\alice"); throw new Exception("Malformed quotes accepted"); } catch (ConfigException) { }
                try { Ssh.ResolveKeysFiles(".ssh/%x", "alice", @"C:\Users\alice"); throw new Exception("Unknown token accepted"); } catch (ConfigException) { }
                return null;
            });
            test("client regression: ambiguous legacy sshd dump cannot select a key file", () =>
            {
                try { Ssh.ResolveEffectiveKeysFiles("C:/Keys dir/alice .ssh/second", "alice", @"C:\Users\alice", false); throw new Exception("Ambiguous legacy dump accepted"); } catch (ConfigException) { }
                var files = Ssh.ResolveEffectiveKeysFiles("\"C:/Keys dir/alice\" .ssh/second", "alice", @"C:\Users\alice", true);
                if (files.Count != 2 || files[0] != @"C:\Keys dir\alice") throw new Exception("Modern dump lost boundaries");
                return null;
            });
            test("client regression: trust rotation and effective preview are explicit", () =>
            {
                var path = Path.Combine(tmpDir, "client-trust-rotation");
                File.WriteAllText(path, "example ssh-ed25519 AAAA\n");
                var detail = SshClient.TrustChanges(ClientFileSnapshot.Read(path), new[] { "example ssh-ed25519 BBBB" });
                if (!detail.Contains("DIFFERENT") || !detail.Contains("retained")) throw new Exception("Trust rotation was hidden");
                var preview = SshClient.FormatEffectivePreview("hostname example.org\nuser alice\nport 2222\nidentityfile first\nidentityfile second\nproxyjump relay\nignored unimportant\n");
                if (!preview.Contains("identityfile first") || !preview.Contains("identityfile second") || !preview.Contains("proxyjump relay") || preview.Contains("unimportant")) throw new Exception("Incomplete effective settings");
                if (SshClient.Connectable(new ClientHost { Pattern = "-oProxyCommand=bad" }) || SshClient.Connectable(new ClientHost { Pattern = "*.example" })) throw new Exception("Unsafe connection name accepted");
                return null;
            });
            test("client regression: hashed and wildcard trust entries are compared", () =>
            {
                var salt = System.Text.Encoding.UTF8.GetBytes("test-salt");
                string entry;
                using (var hash = new System.Security.Cryptography.HMACSHA1(salt)) entry = "|1|" + Convert.ToBase64String(salt) + "|" + Convert.ToBase64String(hash.ComputeHash(System.Text.Encoding.UTF8.GetBytes("[example]:2222")));
                if (!SshClient.KnownHostMatches(entry, "[example]:2222") || SshClient.KnownHostMatches(entry, "example")) throw new Exception("Hashed lookup differs from OpenSSH host form");
                if (!SshClient.KnownHostMatches("*.example,!excluded.example", "web.example") || SshClient.KnownHostMatches("*.example,!excluded.example", "excluded.example")) throw new Exception("Wildcard or negated trust match");
                var path = Path.Combine(tmpDir, "client-hashed-trust");
                File.WriteAllText(path, entry + " ssh-ed25519 AAAA\n");
                if (!SshClient.TrustChanges(ClientFileSnapshot.Read(path), new[] { "[example]:2222 ssh-ed25519 BBBB" }).Contains("DIFFERENT")) throw new Exception("Hashed key rotation was hidden");
                return null;
            });
            test("client regression: malformed key-file specifications never guess a path", () =>
            {
                foreach (var value in new[] { "", "# missing", "none .ssh/key", ".ssh/%", ".ssh/%x", "\"unclosed", "\"\"", "C:drive-relative", "/drive-unspecified", ".ssh/key\nUser injected", ".ssh/key\0suffix" })
                {
                    try { Ssh.ResolveKeysFiles(value, "alice", @"C:\Users\alice"); throw new Exception("Accepted malformed specification: " + value); }
                    catch (ConfigException) { }
                }
                try { Ssh.ResolveKeysFiles(".ssh/key", "alice", null); throw new Exception("Missing home silently guessed"); } catch (ConfigException) { }
                return null;
            });
            test("client regression: 300 seeded quoted paths retain argument boundaries", () =>
            {
                var random = new Random(7432);
                const string chars = "abcXYZ019 #'_-.";
                for (int i = 0; i < 300; i++)
                {
                    var text = new System.Text.StringBuilder("key");
                    for (int j = 0, n = random.Next(1, 35); j < n; j++) text.Append(chars[random.Next(chars.Length)]);
                    text.Append("end");
                    var path = @"C:\Key dir\" + text;
                    var config = SshdArgs.Quote(path) + " .ssh/%%u";
                    var files = Ssh.ResolveKeysFiles(config, "alice", @"C:\Users\alice");
                    if (files.Count != 2 || files[0] != path || files[1] != @"C:\Users\alice\.ssh\%u") throw new Exception("Path boundaries changed: " + config);
                    var host = SshClient.WithHost(new string[0], null, "profile", new Dictionary<string, string> { { "IdentityFile", path + "\n~/.ssh/second" } });
                    var values = SshClient.ParseConfig(host)[0].GetAll("IdentityFile");
                    string error; var identity = SshdArgs.Split(values[0], out error);
                    if (values.Count != 2 || identity == null || identity.Count != 1 || identity[0] != path) throw new Exception("Edited identity boundaries changed");
                }
                return null;
            });
        }
    }
}

// OpenSSH Server Manager for Windows: KeyGen

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
    // Key pair generator: ssh-keygen with the passphrase handed over through SSH_ASKPASS, never on a command line
    // ------------------------------------------------------------------------------------------
    internal sealed class KeyTypeChoice
    {
        public string Label; public string Type; public int Bits; public string FileName; public string PublicType; public bool Experimental;
        public override string ToString() { return Label; }
    }

    internal sealed class KeyGenResult { public string PrivatePath; public string PublicPath; public string PublicKey; public string Fingerprint; public bool Encrypted; }

    internal static class KeyGen
    {
        /// <summary>Environment variable that carries the answer for the SSH_ASKPASS helper (this program started by ssh-keygen or ssh).</summary>
        public const string SecretVariable = "OSM_ASKPASS_SECRET";
        /// <summary>"password" makes the helper answer the server's password prompt instead of passphrase prompts (--authtest only).</summary>
        public const string KindVariable = "OSM_ASKPASS_KIND";
        public const int MinPassphraseLength = 8;
        public const string TestMarker = "OSM-KEY-LOGIN-OK";

        public static readonly KeyTypeChoice[] Types =
        {
            new KeyTypeChoice { Label = "Ed25519 (recommended)", Type = "ed25519", FileName = "id_ed25519", PublicType = "ssh-ed25519" },
            new KeyTypeChoice { Label = "ECDSA P-256", Type = "ecdsa", Bits = 256, FileName = "id_ecdsa", PublicType = "ecdsa-sha2-nistp256" },
            new KeyTypeChoice { Label = "ECDSA P-384", Type = "ecdsa", Bits = 384, FileName = "id_ecdsa", PublicType = "ecdsa-sha2-nistp384" },
            new KeyTypeChoice { Label = "ECDSA P-521", Type = "ecdsa", Bits = 521, FileName = "id_ecdsa", PublicType = "ecdsa-sha2-nistp521" },
            new KeyTypeChoice { Label = "RSA 3072", Type = "rsa", Bits = 3072, FileName = "id_rsa", PublicType = "ssh-rsa" },
            new KeyTypeChoice { Label = "RSA 4096", Type = "rsa", Bits = 4096, FileName = "id_rsa", PublicType = "ssh-rsa" },
            new KeyTypeChoice { Label = "ML-DSA-44 + Ed25519, post-quantum, experimental (OpenSSH 10.5 or later, enabled on server and client)", Type = "mldsa44-ed25519", FileName = "id_mldsa44_ed25519", PublicType = "ssh-mldsa44-ed25519@openssh.com", Experimental = true },
        };

        public static string SshDir { get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".ssh"); } }
        public static string DefaultPath(KeyTypeChoice t) { return Path.Combine(SshDir, t.FileName); }

        /// <summary>Login name of the current account as sshd expects it: "user" for a local account, "DOMAIN\user" otherwise.</summary>
        public static string LoginName()
        {
            var name = WindowsIdentity.GetCurrent().Name;
            int i = name.IndexOf('\\');
            if (i > 0 && string.Equals(name.Substring(0, i), Environment.MachineName, StringComparison.OrdinalIgnoreCase)) return name.Substring(i + 1);
            return name;
        }

        /// <summary>
        /// SSH_ASKPASS mode. Only passphrase prompts are answered, or only the server's password prompt when --authtest asked
        /// for that (KindVariable); any other question (host key confirmation, for example) is refused with a non-zero exit,
        /// which ssh-keygen and ssh treat as "cancelled".
        /// </summary>
        public static int AskpassMain(string[] args)
        {
            var prompt = string.Join(" ", args ?? new string[0]);
            bool passphrase = prompt.IndexOf("passphrase", StringComparison.OrdinalIgnoreCase) >= 0;
            bool password = !passphrase && prompt.TrimEnd().EndsWith("password:", StringComparison.OrdinalIgnoreCase);
            if (Environment.GetEnvironmentVariable(KindVariable) == "password" ? !password : !passphrase) return 1;
            try
            {
                using (var o = Console.OpenStandardOutput())
                {
                    var b = new UTF8Encoding(false).GetBytes((Environment.GetEnvironmentVariable(SecretVariable) ?? "") + "\n");
                    o.Write(b, 0, b.Length); o.Flush();
                }
                return 0;
            }
            catch { return 1; }
        }

        /// <summary>Environment for ssh-keygen or ssh: askpass with the secret, or no prompting at all.</summary>
        private static IDictionary<string, string> AskpassEnvironment(string secret)
        {
            if (secret == null) return new Dictionary<string, string> { { "SSH_ASKPASS_REQUIRE", "never" } };
            return new Dictionary<string, string> { { "SSH_ASKPASS", Application.ExecutablePath }, { "SSH_ASKPASS_REQUIRE", "force" }, { SecretVariable, secret } };
        }

        /// <summary>Environment for ssh that answers the server's password prompt (--authtest only, which logs in to its own test server).</summary>
        public static IDictionary<string, string> PasswordAskpassEnvironment(string password)
        {
            var env = AskpassEnvironment(password);
            env[KindVariable] = "password";
            return env;
        }

        private static RunResult Keygen(string args, string secret, int timeoutMs)
        {
            return Proc.Run(Ssh.Exe("ssh-keygen.exe"), args, timeoutMs, null, AskpassEnvironment(secret));
        }

        /// <summary>Checks the form input; throws ConfigException with a message for the user.</summary>
        public static void Validate(KeyTypeChoice type, string privatePath, string comment, string passphrase, string confirm, bool noPassphrase)
        {
            if (type == null) throw new ConfigException("Choose a key type.");
            var p = (privatePath ?? "").Trim();
            if (p.Length == 0 || !Path.IsPathRooted(p)) throw new ConfigException("Enter the full path of the private key file.");
            if (p.IndexOfAny(Path.GetInvalidPathChars()) >= 0 || p.IndexOf('"') >= 0) throw new ConfigException("The file path contains characters that are not allowed.");
            if (p.EndsWith(".pub", StringComparison.OrdinalIgnoreCase)) throw new ConfigException("Enter the private key's file name. The public key is written next to it, with .pub added.");
            if (Directory.Exists(p)) throw new ConfigException("The path is a folder. Enter a file name, for example " + Path.Combine(p, "id_ed25519") + ".");
            comment = comment ?? "";
            if (comment.Any(char.IsControl) || comment.IndexOf('"') >= 0) throw new ConfigException("The comment must be a single line without quotation marks.");
            if (comment.Length > 200) throw new ConfigException("The comment is too long (200 characters at most).");
            if (noPassphrase) return;
            if (string.IsNullOrEmpty(passphrase)) throw new ConfigException("Enter a passphrase, or tick \"No passphrase\" for a key used by unattended scripts.");
            if (passphrase != confirm) throw new ConfigException("The two passphrases do not match.");
            if (passphrase.Length < MinPassphraseLength) throw new ConfigException("The passphrase must have at least " + MinPassphraseLength + " characters.");
            if (passphrase.Any(char.IsControl)) throw new ConfigException("The passphrase cannot contain line breaks or other control characters.");
        }

        /// <summary>
        /// Creates a key pair with ssh-keygen and verifies it: the private key opens (with the passphrase) and yields
        /// exactly the saved public key, an encrypted key does not open without its passphrase, and the private key's
        /// permissions satisfy the ssh client. A key that fails any check is deleted. Existing files are never overwritten.
        /// </summary>
        /// <summary>
        /// Generate, after moving an existing key pair at the path aside under a dated name (it is never overwritten).
        /// When generation fails, the old pair goes back to its place: the user keeps a working key.
        /// </summary>
        public static KeyGenResult GenerateReplacing(KeyTypeChoice type, string privatePath, string comment, string passphrase, DateTime now)
        {
            var path = Path.GetFullPath(privatePath.Trim());
            var stamp = now.ToString("yyyyMMdd-HHmmss");
            var moved = new List<KeyValuePair<string, string>>();
            try
            {
                foreach (var f in new[] { path, path + ".pub" })
                    if (File.Exists(f)) { File.Move(f, f + ".bak-" + stamp); moved.Add(new KeyValuePair<string, string>(f, f + ".bak-" + stamp)); }
                return Generate(type, path, comment, passphrase);
            }
            catch
            {
                // Generate deletes what it created, so the original names are free again.
                foreach (var m in moved) { try { if (!File.Exists(m.Key)) File.Move(m.Value, m.Key); } catch { } }
                throw;
            }
        }

        public static KeyGenResult Generate(KeyTypeChoice type, string privatePath, string comment, string passphrase)
        {
            privatePath = Path.GetFullPath(privatePath.Trim());
            var publicPath = privatePath + ".pub";
            if (File.Exists(privatePath) || File.Exists(publicPath)) throw new ConfigException("A key already exists at\n" + privatePath + "\n\nMove it aside first or choose another file name.");
            bool encrypt = !string.IsNullOrEmpty(passphrase);
            var dir = Path.GetDirectoryName(privatePath);
            if (!Directory.Exists(dir)) Directory.CreateDirectory(dir);
            var args = "-q -t " + type.Type + (type.Bits > 0 ? " -b " + type.Bits : "") + " -C " + Proc.Quote(comment ?? "") + " -f " + Proc.Quote(privatePath) + (encrypt ? "" : " -N \"\"");
            var r = Keygen(args, encrypt ? passphrase : null, 120000);
            try
            {
                if (!r.Ok || !File.Exists(privatePath) || !File.Exists(publicPath)) throw new Exception("ssh-keygen could not create the key: " + (r.TimedOut ? "timed out" : r.Output));
                var pub = File.ReadAllText(publicPath).Trim();
                if (!pub.StartsWith(type.PublicType + " ", StringComparison.Ordinal)) throw new Exception("Unexpected public key type: " + pub.Split(' ')[0]);
                var derived = Keygen("-y -f " + Proc.Quote(privatePath), encrypt ? passphrase : null, 30000);
                if (!derived.Ok || Keys.Blob(derived.StdOut.Trim()) != Keys.Blob(pub)) throw new Exception("Verification failed: the private key does not reproduce the public key. " + derived.Output);
                if (encrypt)
                {
                    var open = Keygen("-y -P \"\" -f " + Proc.Quote(privatePath), null, 30000);
                    if (open.Ok) throw new Exception("Verification failed: the private key opens without the passphrase.");
                }
                EnsurePrivateKeyAcl(privatePath);
                return new KeyGenResult { PrivatePath = privatePath, PublicPath = publicPath, PublicKey = pub, Fingerprint = Keys.Fingerprint(pub), Encrypted = encrypt };
            }
            catch
            {
                // Never leave a half-made or unverified key behind (both files were created by this call).
                try { if (File.Exists(privatePath)) File.Delete(privatePath); } catch { }
                try { if (File.Exists(publicPath)) File.Delete(publicPath); } catch { }
                throw;
            }
        }

        /// <summary>True when the private key needs a passphrase; throws when the file is not a readable private key.</summary>
        public static bool IsEncrypted(string privatePath)
        {
            var r = Keygen("-y -P \"\" -f " + Proc.Quote(privatePath), null, 30000);
            if (r.Ok) return false;
            if (r.Output.IndexOf("passphrase", StringComparison.OrdinalIgnoreCase) >= 0) return true;
            throw new ConfigException("Not a usable private key:\n" + privatePath + "\n\n" + r.Output);
        }

        /// <summary>The ssh client's rule (w32-sshfileperm.c): owner is the user, SYSTEM or Administrators, and nobody else has an allow entry.</summary>
        public static bool PrivateKeyAclOk(string path, SecurityIdentifier user)
        {
            var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            var fs = File.GetAccessControl(path);
            var owner = (SecurityIdentifier)fs.GetOwner(typeof(SecurityIdentifier));
            if (owner != user && owner != admins && owner != system) return false;
            foreach (FileSystemAccessRule r in fs.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            {
                var sid = (SecurityIdentifier)r.IdentityReference;
                if (r.AccessControlType == AccessControlType.Allow && sid != user && sid != admins && sid != system) return false;
            }
            return true;
        }

        public static void EnsurePrivateKeyAcl(string path)
        {
            var me = WindowsIdentity.GetCurrent().User;
            if (PrivateKeyAclOk(path, me)) return;
            Acl.Restrict(path, me);
            try { var fs = File.GetAccessControl(path); fs.SetOwner(me); File.SetAccessControl(path, fs); } catch { }
            if (!PrivateKeyAclOk(path, me)) throw new Exception("Could not restrict the permissions of " + path + ".");
            Log.Info("Private key permissions restricted: " + path);
        }

        /// <summary>
        /// True when sshd accepts this public key algorithm for the current account. Experimental algorithms such as
        /// ssh-mldsa44-ed25519@openssh.com are compiled in but not in the default PubkeyAcceptedAlgorithms.
        /// </summary>
        public static bool ServerAccepts(string algorithm)
        {
            var r = Proc.Run(Ssh.Exe("sshd.exe"), "-T -C " + Proc.Quote("user=" + Accounts.AsciiLower(LoginName()) + ",host=localhost,addr=127.0.0.1"), 20000);
            var m = Regex.Match(r.StdOut, @"^pubkeyacceptedalgorithms\s+(.+?)\s*$", RegexOptions.Multiline | RegexOptions.IgnoreCase);
            return m.Success && m.Groups[1].Value.Split(',').Any(a => a.Trim().Equals(algorithm, StringComparison.OrdinalIgnoreCase));
        }

        /// <summary>
        /// The PubkeyAcceptedAlgorithms value that adds one algorithm to the current setting (null = not set), or null
        /// when the current value removes algorithms ("-list") and cannot be extended safely.
        /// </summary>
        public static string WithAlgorithm(string current, string algorithm)
        {
            current = (current ?? "").Trim();
            if (current.Length == 0) return "+" + algorithm;
            if (current.StartsWith("-")) return null;
            if (current.TrimStart('+', '^').Split(',').Any(a => a.Trim().Equals(algorithm, StringComparison.OrdinalIgnoreCase))) return current;
            return current + "," + algorithm;
        }

        public static bool IsAdminKeysFile(string path)
        {
            return string.Equals(Path.GetFullPath(path), Path.GetFullPath(Ssh.AdminKeysPath), StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Adds a public key to the authorized_keys file that sshd reads for the current account (asked from sshd -T -C,
        /// so Match blocks such as "Match Group administrators" are honoured). Returns that file.
        /// </summary>
        public static string AuthorizeForCurrentUser(string publicLine, out bool alreadyPresent)
        {
            var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var target = Ssh.AuthorizedKeysFileFor(LoginName(), home) ?? (Elevation.IsAdministrator() ? Ssh.AdminKeysPath : Keys.UserKeysPath(home));
            var r = Keys.AddLines(target, new[] { publicLine }, IsAdminKeysFile(target) ? null : WindowsIdentity.GetCurrent().User);
            alreadyPresent = r[0] == 0;
            Log.Info("Authorized key " + Keys.Blob(publicLine).Substring(0, Math.Min(16, Keys.Blob(publicLine).Length)) + "... in " + target + (alreadyPresent ? " (already present)" : ""));
            return target;
        }

        /// <summary>
        /// Logs in to this server with one private key and nothing else: public key authentication only, no agent, no
        /// config file, and the host key pinned to this server's own host keys.
        /// </summary>
        public static RunResult TestLogin(string privatePath, string passphrase, int port)
        {
            var kh = Path.Combine(Path.GetTempPath(), "osm-known_hosts-" + Guid.NewGuid().ToString("N"));
            try
            {
                Ssh.WriteKnownHosts(kh, "localhost", port);
                // The client, too, leaves the experimental ML-DSA algorithm out by default; adding it only lets the one key
                // given with -i be offered, it changes nothing for the other key types.
                var args = "-F none -T -i " + Proc.Quote(privatePath) +
                    " -o PubkeyAcceptedAlgorithms=+ssh-mldsa44-ed25519@openssh.com" +
                    " -o IdentitiesOnly=yes -o IdentityAgent=none -o PreferredAuthentications=publickey -o PasswordAuthentication=no" +
                    " -o KbdInteractiveAuthentication=no -o StrictHostKeyChecking=yes -o UserKnownHostsFile=" + Proc.Quote(kh) +
                    " -o GlobalKnownHostsFile=" + Proc.Quote(kh) + " -o ConnectTimeout=15 -o BatchMode=" + (string.IsNullOrEmpty(passphrase) ? "yes" : "no") +
                    " -p " + port + " -l " + Proc.Quote(LoginName()) + " localhost echo " + TestMarker;
                return Proc.Run(Ssh.Exe("ssh.exe"), args, 45000, null, AskpassEnvironment(string.IsNullOrEmpty(passphrase) ? null : passphrase));
            }
            finally { try { File.Delete(kh); } catch { } }
        }

        public static bool LoginOk(RunResult r) { return r != null && r.Ok && r.StdOut.Contains(TestMarker); }

        /// <summary>
        /// --keytest: for every key type, with and without a passphrase, generate a key, authorize it for the current account,
        /// log in to this server with it and remove it again; then check that a wrong passphrase and an unauthorized key are
        /// refused. The authorized_keys file (and its .bak copy) is restored byte for byte at the end.
        /// </summary>
        public static int RunKeyTest(string outFile)
        {
            Program.AttachParentConsole();
            var sb = new StringBuilder(); int failed = 0;
            var dir = Path.Combine(Path.GetTempPath(), "osm-keytest-" + Guid.NewGuid().ToString("N"));
            string target = null; var snapshots = new List<FileSnapshot>();
            try
            {
                Directory.CreateDirectory(dir);
                var user = LoginName();
                var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                target = Ssh.AuthorizedKeysFileFor(user, home) ?? Ssh.AdminKeysPath;
                snapshots.Add(FileSnapshot.Take(target)); snapshots.Add(FileSnapshot.Take(target + ".bak"));
                var owner = IsAdminKeysFile(target) ? null : WindowsIdentity.GetCurrent().User;
                int port = SshdConfig.Load().EffectivePort;
                sb.AppendLine("OpenSSH Server Manager " + Program.AppVersion + " key test, account " + user + ", port " + port);
                sb.AppendLine("authorized_keys used by sshd for this account: " + target);
                int n = 0; KeyGenResult firstEncrypted = null; string firstPass = null;
                foreach (var t in Types)
                {
                    if (t.Experimental && !ServerAccepts(t.PublicType))
                    {
                        sb.AppendLine("SKIP  " + t.Label.Split(new[] { ',', '(' })[0].Trim() + ": experimental, not enabled on this server (PubkeyAcceptedAlgorithms +" + t.PublicType + ")");
                        continue;
                    }
                    foreach (bool withPass in new[] { true, false })
                    {
                        n++;
                        var label = t.Label.Split(new[] { ',', '(' })[0].Trim() + (withPass ? ", passphrase" : ", no passphrase");
                        var pass = withPass ? "Kt-" + Guid.NewGuid().ToString("N").Substring(0, 14) : null;
                        try
                        {
                            var res = Generate(t, Path.Combine(dir, "k" + n), "osm-keytest-" + n, pass);
                            if (!PrivateKeyAclOk(res.PrivatePath, WindowsIdentity.GetCurrent().User)) throw new Exception("private key permissions too open");
                            Keys.AddLines(target, new[] { res.PublicKey }, owner);
                            try
                            {
                                var login = TestLogin(res.PrivatePath, pass, port);
                                if (!LoginOk(login)) throw new Exception("login failed: " + login.Output);
                            }
                            finally { Keys.RemoveKey(target, res.PublicKey, owner); }
                            if (withPass && firstEncrypted == null) { firstEncrypted = res; firstPass = pass; }
                            sb.AppendLine("PASS  " + label + ": generated, verified, logged in  (" + res.Fingerprint + ")");
                        }
                        catch (Exception ex) { failed++; sb.AppendLine("FAIL  " + label + ": " + ex.Message.Replace(Environment.NewLine, " ")); }
                    }
                }
                // Refusals: a wrong passphrase must not unlock the key, and a key that is not authorized must not log in.
                try
                {
                    if (firstEncrypted == null) throw new Exception("no encrypted key to test");
                    Keys.AddLines(target, new[] { firstEncrypted.PublicKey }, owner);
                    try { if (LoginOk(TestLogin(firstEncrypted.PrivatePath, firstPass + "x", port))) throw new Exception("logged in with a wrong passphrase"); }
                    finally { Keys.RemoveKey(target, firstEncrypted.PublicKey, owner); }
                    sb.AppendLine("PASS  wrong passphrase refused");
                }
                catch (Exception ex) { failed++; sb.AppendLine("FAIL  wrong passphrase: " + ex.Message); }
                try
                {
                    var stranger = Generate(Types[0], Path.Combine(dir, "unauthorized"), "osm-keytest-unauthorized", null);
                    if (LoginOk(TestLogin(stranger.PrivatePath, null, port))) throw new Exception("an unauthorized key logged in");
                    sb.AppendLine("PASS  unauthorized key refused");
                }
                catch (Exception ex) { failed++; sb.AppendLine("FAIL  unauthorized key: " + ex.Message); }
            }
            catch (Exception ex) { failed++; sb.AppendLine("FAIL  " + ex.Message); }
            finally
            {
                foreach (var s in snapshots)
                {
                    try { s.Restore(); sb.AppendLine("restored " + s.Path + (s.Existed ? "" : " (removed, it did not exist before)")); }
                    catch (Exception ex) { failed++; sb.AppendLine("FAIL  could not restore " + s.Path + ": " + ex.Message); }
                }
                try { Directory.Delete(dir, true); } catch { }
            }
            sb.AppendLine(failed == 0 ? "RESULT: all key tests passed" : "RESULT: " + failed + " key test(s) failed");
            Program.Report(sb.ToString(), outFile);
            return failed == 0 ? 0 : 1;
        }
    }

    /// <summary>Exact copy of a file's bytes and permissions (or its absence) to put back after a test.</summary>
    internal sealed class FileSnapshot
    {
        public string Path; public bool Existed; private byte[] _bytes; private FileSecurity _acl;
        public static FileSnapshot Take(string path)
        {
            var s = new FileSnapshot { Path = path, Existed = File.Exists(path) };
            if (s.Existed) { s._bytes = File.ReadAllBytes(path); s._acl = File.GetAccessControl(path); }
            return s;
        }
        public void Restore()
        {
            if (!Existed) { if (File.Exists(Path)) File.Delete(Path); return; }
            File.WriteAllBytes(Path, _bytes);
            _acl.SetAccessRuleProtection(_acl.AreAccessRulesProtected, true);
            File.SetAccessControl(Path, _acl);
        }
    }
}

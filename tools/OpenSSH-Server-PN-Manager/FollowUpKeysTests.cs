using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading;

namespace OpenSSHServerPNManager
{
    /// <summary>Regressions for keys and authorized_keys files (October 2026 follow-up review).</summary>
    internal static class FollowUpKeysTests
    {
        [DllImport("kernel32.dll", EntryPoint = "CreateHardLinkW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CreateHardLink(string newName, string existingName, IntPtr security);

        private const string Ed = "AAAAC3NzaC1lZDI1NTE5AAAAIGVkMjU1MTlzZWxmdGVzdGtleTAwMDAwMDAwMDAwMDAwMDA";
        private const string Ed2 = "AAAAC3NzaC1lZDI1NTE5AAAAIHNlY29uZGtleWZvcnRoZWZvbGxvd3VwYXVkaXQwMDAwMDA"; // the same first 20 characters
        private const string EdKey = "AAAAC3NzaC1lZDI1NTE5AAAAINFhfnIhjngEwHGzCWQanrghnwUez4F1AURuXtiqig8t"; // valid base64, unlike the two above
        private const string Rsa ="AAAAB3NzaC1yc2EAAAADAQABAAAAgQDQp8OeUP5GgBVpoj9A4BoSAZA0IN7hR2LCdwN37XAneK1YAHBWFNNt5+2eOuoiCokszgR40LbhksZ6mdOt+X92Aox20cBvDE+LHkzvEoGDKr4NSeN/w4t0VB0h/oOp6OHff5wuienepELIbHUwzTG0UUvbu4TiJo6fIertTEm0Bw==";

        private static string NewDir(string tmpDir, string name)
        {
            var dir = Path.Combine(tmpDir, name + "-" + Guid.NewGuid().ToString("N").Substring(0, 8));
            Directory.CreateDirectory(dir);
            return dir;
        }

        /// <summary>An Ed25519 key for the format tests: the private and public parts belong together as far as the files check.</summary>
        private static PrivateKeyData TestKey(string comment)
        {
            var pk = Enumerable.Range(1, 32).Select(i => (byte)i).ToArray();
            var sk = Enumerable.Range(101, 32).Select(i => (byte)i).Concat(pk).ToArray();
            return new PrivateKeyData { Type = "ssh-ed25519", PublicBlob = new SshWriter().String("ssh-ed25519").String(pk).ToArray(), Private = new SshWriter().String(pk).String(sk).ToArray(), Comment = comment };
        }

        private static bool Same(PrivateKeyData a, PrivateKeyData b)
        {
            return a.Type == b.Type && KeyFormats.Equal(a.PublicBlob, b.PublicBlob) && KeyFormats.Equal(a.Private, b.Private) && a.Comment == b.Comment;
        }

        private static string ReadShared(string path)
        {
            using (var s = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            using (var r = new StreamReader(s)) return r.ReadToEnd();
        }

        /// <summary>
        /// The key material ssh-keygen -i takes from an RFC 4716 file (do_convert_from_ssh2: header and continuation lines skipped,
        /// a header line with " END " ends the key), or null where it would take the file for a private key.
        /// </summary>
        private static string KeygenImport(string text)
        {
            var sb = new StringBuilder(); int escaped = 0;
            foreach (var line in text.Split('\n'))
            {
                if (line.EndsWith("\\", StringComparison.Ordinal)) escaped++;
                if (line.StartsWith("----", StringComparison.Ordinal) || line.Contains(": "))
                {
                    if (line.Contains("---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----")) return null;
                    if (line.Contains(" END ")) break;
                    continue;
                }
                if (escaped > 0) { escaped--; continue; }
                sb.Append(line);
            }
            return sb.ToString();
        }

        /// <summary>Checks an RFC 4716 export: lines ssh-keygen -i reads as this key, and a header that joins to the comment, quoted.</summary>
        private static void CheckRfc4716(string text, string comment, string key)
        {
            var lines = text.TrimEnd('\n').Split('\n');
            var header = new StringBuilder();
            for (int i = 1; i < lines.Length && !lines[i].StartsWith("----", StringComparison.Ordinal); i++)
            {
                if (Encoding.UTF8.GetByteCount(lines[i]) > 72) throw new Exception("line over 72 bytes: " + lines[i]);
                if (lines[i].Length > 0 && (char.IsHighSurrogate(lines[i].Last()) || char.IsLowSurrogate(lines[i][0]))) throw new Exception("a character split: " + lines[i]);
                bool continuation = i > 1 && lines[i - 1].EndsWith("\\", StringComparison.Ordinal);
                if (continuation && (lines[i].Contains(": ") || lines[i].StartsWith("----", StringComparison.Ordinal))) throw new Exception("ssh-keygen -i takes this continuation line for a header: " + lines[i]);
                if (i == 1 || continuation) header.Append(lines[i].EndsWith("\\", StringComparison.Ordinal) ? lines[i].Substring(0, lines[i].Length - 1) : lines[i]);
            }
            var value = header.ToString();
            var kept = new string(comment.Where(c => c != '"' && c != '\\').ToArray());
            if (!value.StartsWith("Comment: \"", StringComparison.Ordinal) || !value.EndsWith("\"", StringComparison.Ordinal) || value.Substring(10, value.Length - 11).IndexOf('"') >= 0) throw new Exception("not one quoted value: " + value);
            if (value.Substring(10, value.Length - 11) != kept) throw new Exception("comment: " + value);
            if (KeygenImport(text) != key) throw new Exception("key material for [" + comment + "]: " + (KeygenImport(text) ?? "read as a private key"));
        }

        internal static void Run(Action<string, Func<string>> test, string tmpDir)
        {
            var me = WindowsIdentity.GetCurrent().User;

            test("authorized_keys: a change waits for a reader that has the file open as sshd does", () =>
            {
                var dir = NewDir(tmpDir, "reader"); var file = Path.Combine(dir, "authorized_keys");
                File.WriteAllText(file, "ssh-ed25519 " + Ed + " a\nssh-ed25519 " + Ed2 + " b\n");
                var reader = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite); // win32compat fileio.c
                var release = new Thread(() => { Thread.Sleep(300); reader.Dispose(); });
                release.Start();
                try { if (Keys.RemoveKey(file, "ssh-ed25519 " + Ed, me) != 1) throw new Exception("not exactly one line removed"); }
                finally { release.Join(); reader.Dispose(); }
                var left = File.ReadAllText(file);
                if (left.Contains(" a\n") || !left.Contains(Ed2)) throw new Exception("wrong content: " + left);
                if (Directory.GetFiles(dir, "*.new-*").Length != 0) throw new Exception("a temporary file was left");
                return null;
            });
            test("authorized_keys: a reader that never lets go fails the change, naming the file, and nothing changes", () =>
            {
                var dir = NewDir(tmpDir, "held"); var file = Path.Combine(dir, "authorized_keys");
                var before = "ssh-ed25519 " + Ed + " a\nssh-ed25519 " + Ed2 + " b\n";
                File.WriteAllText(file, before);
                Exception failure = null;
                using (new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    try { Keys.RemoveKey(file, "ssh-ed25519 " + Ed, me); }
                    catch (Exception ex) { failure = ex; }
                    if (ReadShared(file) != before) throw new Exception("the file changed");
                }
                if (!(failure is IOException) || !failure.Message.Contains(file)) throw new Exception("expected an IOException naming the file, got " + (failure == null ? "success" : failure.GetType().Name + ": " + failure.Message));
                if (!File.Exists(file + ".bak") || File.ReadAllText(file + ".bak") != before) throw new Exception("no backup of the previous file");
                if (Directory.GetFiles(dir, "*.new-*").Length != 0) throw new Exception("a temporary file was left");
                return null;
            });
            test("authorized_keys: the new file and its .bak never take the folder's inherited permissions", () =>
            {
                var dir = NewDir(tmpDir, "inherit"); var file = Path.Combine(dir, "authorized_keys");
                // As in C:\ProgramData\ssh: every authenticated user may read what is created in the folder.
                var users = new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null);
                var ds = Directory.GetAccessControl(dir);
                ds.AddAccessRule(new FileSystemAccessRule(users, FileSystemRights.ReadAndExecute, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
                Directory.SetAccessControl(dir, ds);
                File.WriteAllText(file, "ssh-ed25519 " + Ed + " a\n");
                if (Keys.AddLines(file, new[] { "ssh-ed25519 " + Ed2 + " b" }, me)[0] != 1) throw new Exception("not added");
                foreach (var f in new[] { file, file + ".bak" })
                {
                    var fs = File.GetAccessControl(f);
                    var sids = fs.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().Select(r => (SecurityIdentifier)r.IdentityReference).ToList();
                    if (!fs.AreAccessRulesProtected || sids.Contains(users) || !sids.Contains(me)) throw new Exception(Path.GetFileName(f) + ": " + fs.GetSecurityDescriptorSddlForm(AccessControlSections.Access));
                }
                return null;
            });
            test("authorized_keys: a folder reached through a junction is refused, wherever the junction is", () =>
            {
                var dir = NewDir(tmpDir, "junction");
                var real = Path.Combine(dir, "real"); var sub = Path.Combine(real, "sub"); Directory.CreateDirectory(sub);
                var link = Path.Combine(dir, "link");
                var r = Proc.Run("cmd.exe", "/c mklink /J " + Proc.Quote(link) + " " + Proc.Quote(real), 30000);
                if (!r.Ok || !Directory.Exists(link)) throw new Exception("mklink /J: " + r.Output);
                foreach (var target in new[] { real, sub })
                {
                    var file = Path.Combine(target, "authorized_keys");
                    File.WriteAllText(file, "ssh-ed25519 " + Ed + " victim\n");
                    var via = Path.Combine(link, target == real ? "authorized_keys" : @"sub\authorized_keys");
                    try { Keys.AddLines(via, new[] { "ssh-ed25519 " + Ed2 + " attacker" }, me); throw new Exception("written through the junction: " + via); }
                    catch (ConfigException) { }
                    if (File.ReadAllText(file) != "ssh-ed25519 " + Ed + " victim\n" || Directory.GetFiles(target).Length != 1) throw new Exception("the folder behind the junction changed: " + target);
                }
                // The folder itself, by its own path, is written as before.
                if (Keys.AddLines(Path.Combine(real, "authorized_keys"), new[] { "ssh-ed25519 " + Ed2 + " b" }, me)[0] != 1) throw new Exception("the real folder was refused");
                return null;
            });
            test("authorized_keys: a key file or .bak with a second name (hard link) is refused, and the other file stays", () =>
            {
                var dir = NewDir(tmpDir, "hardlink"); var file = Path.Combine(dir, "authorized_keys");
                var outside = Path.Combine(NewDir(tmpDir, "outside"), "precious");
                File.WriteAllText(outside, "precious");
                File.WriteAllText(file, "ssh-ed25519 " + Ed + " a\n");
                if (!CreateHardLink(file + ".bak", outside, IntPtr.Zero)) throw new Exception("CreateHardLink: " + Marshal.GetLastWin32Error());
                try { Keys.AddLines(file, new[] { "ssh-ed25519 " + Ed2 + " b" }, me); throw new Exception("a .bak with two names was written"); }
                catch (ConfigException) { }
                if (File.ReadAllText(outside) != "precious" || File.ReadAllText(file) != "ssh-ed25519 " + Ed + " a\n") throw new Exception("a file changed");
                File.Delete(file + ".bak"); File.Delete(file);
                if (!CreateHardLink(file, outside, IntPtr.Zero)) throw new Exception("CreateHardLink: " + Marshal.GetLastWin32Error());
                try { Keys.AddLines(file, new[] { "ssh-ed25519 " + Ed2 + " b" }, me); throw new Exception("a key file with two names was written"); }
                catch (ConfigException) { }
                if (File.ReadAllText(outside) != "precious") throw new Exception("the other file changed");
                return null;
            });
            test("authorized_keys: what a change keeps is read after the folder is checked, never by name before", () =>
            {
                var dir = NewDir(tmpDir, "readfirst");
                var real = Path.Combine(dir, "real"); Directory.CreateDirectory(real);
                var link = Path.Combine(dir, "link");
                var r = Proc.Run("cmd.exe", "/c mklink /J " + Proc.Quote(link) + " " + Proc.Quote(real), 30000);
                if (!r.Ok || !Directory.Exists(link)) throw new Exception("mklink /J: " + r.Output);
                var file = Path.Combine(real, "authorized_keys");
                File.WriteAllText(file, "ssh-ed25519 " + Ed + " victim\n");
                var via = Path.Combine(link, "authorized_keys");
                // Held so that reading the file behind the junction fails with a sharing violation instead of the refusal.
                using (new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.None))
                {
                    foreach (var change in new Func<object>[] { () => Keys.AddLines(via, new[] { "ssh-ed25519 " + Ed2 + " attacker" }, me), () => Keys.RemoveKey(via, "ssh-ed25519 " + Ed, me) })
                    {
                        try { change(); throw new Exception("changed through the junction"); }
                        catch (ConfigException) { }
                        catch (IOException ex) { throw new Exception("the file behind the junction was read first: " + ex.Message); }
                    }
                }
                return null;
            });
            test("authorized_keys: a CR inside a line does not end it, as sshd reads the file", () =>
            {
                var dir = NewDir(tmpDir, "cr"); var file = Path.Combine(dir, "authorized_keys");
                File.WriteAllText(file, "ssh-ed25519 " + Ed.Substring(0, 20) + "\r" + Ed.Substring(20) + " crkey\r\nssh-ed25519 " + Ed2 + " b\n");
                var keys = Keys.Read(file);
                if (keys.Count != 2 || keys[0].Type != "ssh-ed25519" || Keys.Blob(keys[0].Line) != Ed || keys[0].Comment != "crkey") throw new Exception("read: " + string.Join(" | ", keys.Select(k => k.Type + " " + k.Comment)));
                if (Keys.RemoveKey(file, keys[0].Line, me) != 1) throw new Exception("not exactly one line removed");
                var left = File.ReadAllText(file);
                if (left != "ssh-ed25519 " + Ed2 + " b\n") throw new Exception("left: " + left);
                return null;
            });
            test("authorized_keys: Fix permissions sets the key file's own ACL, never one behind a link", () =>
            {
                var dir = NewDir(tmpDir, "restrict");
                var real = Path.Combine(dir, "real"); Directory.CreateDirectory(real);
                var link = Path.Combine(dir, "link");
                var r = Proc.Run("cmd.exe", "/c mklink /J " + Proc.Quote(link) + " " + Proc.Quote(real), 30000);
                if (!r.Ok || !Directory.Exists(link)) throw new Exception("mklink /J: " + r.Output);
                var file = Path.Combine(real, "authorized_keys");
                File.WriteAllText(file, "ssh-ed25519 " + Ed + " a\n");
                var users = new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null);
                var fs = File.GetAccessControl(file);
                fs.AddAccessRule(new FileSystemAccessRule(users, FileSystemRights.Read, AccessControlType.Allow));
                File.SetAccessControl(file, fs);
                var before = File.GetAccessControl(file).GetSecurityDescriptorSddlForm(AccessControlSections.Access);
                var second = Path.Combine(real, "second");
                if (!CreateHardLink(second, file, IntPtr.Zero)) throw new Exception("CreateHardLink: " + Marshal.GetLastWin32Error());
                foreach (var target in new[] { Path.Combine(link, "authorized_keys"), second })
                {
                    try { Keys.RestrictKeyFile(target, me); throw new Exception("set through a link: " + target); }
                    catch (ConfigException) { }
                }
                if (File.GetAccessControl(file).GetSecurityDescriptorSddlForm(AccessControlSections.Access) != before) throw new Exception("the file behind a link changed");
                File.Delete(second);
                Keys.RestrictKeyFile(file, me);
                var after = File.GetAccessControl(file);
                var sids = after.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().Select(x => (SecurityIdentifier)x.IdentityReference).ToList();
                if (!after.AreAccessRulesProtected || sids.Contains(users) || !sids.Contains(me) || sids.Count != 3) throw new Exception("ACL: " + after.GetSecurityDescriptorSddlForm(AccessControlSections.Access));
                return null;
            });
            test("authorized_keys: rsa-sha2 key names and \\v \\f \\r inside the key material are read as sshd reads them", () =>
            {
                foreach (var type in new[] { "rsa-sha2-256", "rsa-sha2-512", "rsa-sha2-256-cert-v01@openssh.com", "rsa-sha2-512-cert-v01@openssh.com" })
                {
                    var e = Keys.Parse(type + " " + Rsa + " c");
                    if (e.Type != type || Keys.Blob(e.Line) != Rsa || e.Comment != "c" || !Keys.LooksLikePublicKey(e.Line)) throw new Exception(type + ": " + e.Type + " / " + e.Comment);
                }
                foreach (var ws in new[] { "\v", "\f", "\r" })
                {
                    var line = "from=\"x\" ssh-ed25519 " + Ed.Substring(0, 20) + ws + Ed.Substring(20) + " c";
                    if (Keys.Blob(line) != Ed || Keys.Parse(line).Comment != "c") throw new Exception("blob with " + (int)ws[0] + ": " + Keys.Blob(line));
                }
                if (Keys.LooksLikePublicKey("ssh-ed25519 " + Ed + ",x c")) throw new Exception("key material sshd cannot decode was taken");
                var dir = NewDir(tmpDir, "sha2"); var file = Path.Combine(dir, "authorized_keys");
                File.WriteAllText(file, "ssh-rsa " + Rsa + " a\nrsa-sha2-512 " + Rsa + " b\nssh-ed25519 " + Ed.Substring(0, 20) + "\v" + Ed.Substring(20) + " c\nssh-ed25519 " + Ed2 + " d\n");
                if (Keys.RemoveKey(file, "ssh-rsa " + Rsa, me) != 2) throw new Exception("the rsa-sha2-512 line of the same key was kept");
                if (Keys.RemoveKey(file, "ssh-ed25519 " + Ed, me) != 1) throw new Exception("the line with \\v in its key was kept");
                var left = File.ReadAllText(file);
                if (left != "ssh-ed25519 " + Ed2 + " d\n") throw new Exception("left: " + left);
                return null;
            });
            test("partner keys: no .bak is written, and the .bak an earlier version kept goes", () =>
            {
                var dir = NewDir(tmpDir, "partner"); var file = Path.Combine(dir, "acme");
                Keys.AddLines(file, new[] { "ssh-ed25519 " + Ed + " a" }, me, backup: false);
                Keys.AddLines(file, new[] { "ssh-ed25519 " + Ed2 + " b" }, me, backup: false);
                Keys.RemoveKey(file, "ssh-ed25519 " + Ed, me, backup: false);
                if (File.Exists(file + ".bak")) throw new Exception("a .bak was written");
                // sshd would read acme.bak as the keys of a partner named acme.bak.
                File.WriteAllText(file + ".bak", "ssh-ed25519 " + Ed + " removed long ago\n");
                var name = "osm-nobody-" + Guid.NewGuid().ToString("N").Substring(0, 8);
                if (!PartnerKeysDialog.DropLegacyBackup(file, name) || File.Exists(file + ".bak") || !File.Exists(file)) throw new Exception("the earlier .bak was not deleted");
                if (PartnerKeysDialog.DropLegacyBackup(file, name)) throw new Exception("deleted twice");
                return null;
            });
            test("key files: only ssh-keygen's wrong-passphrase message counts as needing a passphrase", () =>
            {
                var cases = new Dictionary<string, bool>
                {
                    { "Load key \"C:\\\\keys\\\\passphrase-old\\\\id_rsa.pem\": invalid format", false },
                    { "WARNING: UNPROTECTED PRIVATE KEY FILE!\r\nLoad key \"C:\\\\x\\\\passphrase\\\\id\": bad permissions", false },
                    { "Load key \"C:\\\\x\\\\incorrect passphrase supplied to decrypt private key\\\\id\": invalid format", false },
                    { "Load key \"C:\\\\x\\\\id\": incorrect passphrase supplied to decrypt private key", true },
                    { "Failed to load key C:\\\\T\\\\osm-key-1\\\\key: incorrect passphrase supplied to decrypt private key\r\n", true },
                };
                foreach (var c in cases) if (KeyGen.SaysWrongPassphrase(c.Key) != c.Value) throw new Exception(c.Key);
                return null;
            });
            test("key files: a .ppk comment may hold a tab, never a line break", () =>
            {
                var k = TestKey("osm\tfixture");
                foreach (var v in new[] { 2, 3 })
                {
                    var pass = v == 2 ? "Written-pass-3" : null;
                    var back = PpkFile.Parse(Encoding.UTF8.GetBytes(PpkFile.Write(k, pass, v))).Decrypt(pass);
                    if (!Same(back, k)) throw new Exception(".ppk " + v + ": comment [" + back.Comment + "]");
                }
                foreach (var bad in new[] { "a\nb", "a\rb", "a\u0085b" })
                {
                    k.Comment = bad;
                    try { PpkFile.Write(k, null, 3); throw new Exception("written with " + (int)bad[1]); }
                    catch (ConfigException ex) { if (!ex.Message.Contains("line break")) throw new Exception(ex.Message); }
                }
                return null;
            });
            test("key files: an RFC 4716 export has the key's comment, in lines ssh-keygen -i reads", () =>
            {
                var plain = KeyGen.Rfc4716("ssh-ed25519 " + EdKey + " acme-partner-key", "acme-partner-key");
                var lines = plain.TrimEnd('\n').Split('\n');
                if (lines[0] != "---- BEGIN SSH2 PUBLIC KEY ----" || lines[1] != "Comment: \"acme-partner-key\"" || lines.Last() != "---- END SSH2 PUBLIC KEY ----" || plain.Contains("converted by")) throw new Exception(plain);
                if (KeygenImport(plain) != EdKey) throw new Exception("key material: " + KeygenImport(plain));
                if (KeyGen.Rfc4716("ssh-ed25519 " + EdKey, "").Contains("Comment")) throw new Exception("a Comment line without a comment");
                // A long comment with what the format cannot hold, what ssh-keygen -i would take for a header, and multi-byte characters.
                var comment = "a\"b\\c: d ---- e " + new string('\u00e9', 80) + " \ud83d\ude00\ud83d\ude00 -------- x: y " + new string('-', 70) + "z: " + new string('\u0e01', 30);
                var text = KeyGen.Rfc4716("rsa-sha2-512 " + Rsa + " x", comment);
                CheckRfc4716(text, comment, Rsa);
                // ssh-keygen -i reads the first line as a header: " END " there ends the key, and a private key's begin line makes it one.
                var markers = new[] { "FRONT END deploy key", "END END x","x ---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ---- y", "---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ---- END x: y", "key END " + new string('\u00e9', 40) + " END x: y" };
                var texts = new List<KeyValuePair<string, string>> { new KeyValuePair<string, string>(text, Rsa) };
                foreach (var m in markers)
                {
                    var t = KeyGen.Rfc4716("ssh-ed25519 " + EdKey + " x", m);
                    CheckRfc4716(t, m.Trim(), EdKey);
                    texts.Add(new KeyValuePair<string, string>(t, EdKey));
                }
                // The export itself, and ssh-keygen -i where it is installed.
                var dir = NewDir(tmpDir, "rfc4716"); var target = Path.Combine(dir, "acme.pub");
                KeyGen.Export(new KeyFileInfo { Path = Path.Combine(dir, "id_ed25519"), PublicLine = "ssh-ed25519 " + EdKey + " acme-partner-key", Comment = "acme-partner-key" }, KeyExportFormat.Rfc4716Public, target, null, null, DateTime.Now);
                if (File.ReadAllText(target) != plain) throw new Exception("exported: " + File.ReadAllText(target));
                var keygen = Ssh.Exe("ssh-keygen.exe");
                if (!File.Exists(keygen)) return "ssh-keygen -i not run: not installed";
                foreach (var t in texts)
                {
                    File.WriteAllText(target, t.Key, new UTF8Encoding(false));
                    var r = Proc.Run(keygen, "-i -f " + Proc.Quote(target), 30000);
                    if (!r.Ok || Keys.Blob(r.StdOut.Trim()) != t.Value) throw new Exception("ssh-keygen -i: " + r.Output + "\n" + t.Key);
                }
                return null;
            });
            test("key files: buffers that held key material are wiped when outgrown or no longer needed", () =>
            {
                var w = new SshWriter().Raw(Enumerable.Repeat((byte)0xAA, 200).ToArray());
                var field = typeof(SshWriter).GetField("_b", BindingFlags.NonPublic | BindingFlags.Instance);
                var old = (byte[])field.GetValue(w);
                w.Raw(Enumerable.Repeat((byte)0xAA, 200).ToArray());
                if (ReferenceEquals(old, field.GetValue(w)) || old.Any(b => b != 0)) throw new Exception("the outgrown buffer kept its bytes");
                if (w.ToArray().Length != 400 || w.ToArray().Any(b => b != 0xAA)) throw new Exception("the bytes written were lost");
                w.Clear();
                if (((byte[])field.GetValue(w)).Any(b => b != 0) || w.Length != 0) throw new Exception("Clear left bytes");
                var file = Path.Combine(NewDir(tmpDir, "snapshot"), "id_x");
                File.WriteAllBytes(file, Enumerable.Repeat((byte)0x55, 64).ToArray());
                var s = FileSnapshot.Take(file); s.Forget();
                if (((byte[])typeof(FileSnapshot).GetField("_bytes", BindingFlags.NonPublic | BindingFlags.Instance).GetValue(s)).Any(b => b != 0)) throw new Exception("the snapshot kept the key file's bytes");
                return null;
            });
            test("key files: a .ppk file with blank lines or a byte order mark before its first line is read", () =>
            {
                var k = TestKey("osm fixture");
                var ppk = PpkFile.Write(k, null, 3);
                var bom = new byte[] { 0xEF, 0xBB, 0xBF };
                foreach (var padded in new[] { "\r\n  \r\n" + ppk, "\n\t" + ppk })
                {
                    if (!PpkFile.IsPpk(padded)) throw new Exception("IsPpk");
                    foreach (var data in new[] { Encoding.UTF8.GetBytes(padded), bom.Concat(Encoding.UTF8.GetBytes(padded)).ToArray(), Encoding.UTF8.GetBytes("\r\n").Concat(bom).Concat(Encoding.UTF8.GetBytes(ppk)).ToArray() })
                        if (!Same(PpkFile.Parse(data).Decrypt(null), k)) throw new Exception("another key came back");
                }
                return null;
            });
            test("key files: a PEM key that others can read is inspected from a private copy", () =>
            {
                var keygen = Ssh.Exe("ssh-keygen.exe");
                if (!File.Exists(keygen)) return "not run: ssh-keygen is not installed";
                var dir = NewDir(tmpDir, "pem");
                var done = new List<string>();
                foreach (var pass in new[] { "Selftest-Pem-5", "" })
                {
                    var key = Path.Combine(dir, pass.Length > 0 ? "encrypted" : "plain");
                    var g = Proc.Run(keygen, "-q -t ecdsa -b 256 -m PEM -C pemtest -N " + Proc.Quote(pass) + " -f " + Proc.Quote(key), 60000);
                    if (!g.Ok || !File.Exists(key)) throw new Exception("ssh-keygen: " + g.Output);
                    // Readable by all users, as on a shared folder: ssh-keygen refuses to load the file itself.
                    var fs = File.GetAccessControl(key);
                    fs.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null), FileSystemRights.Read, AccessControlType.Allow));
                    File.SetAccessControl(key, fs);
                    var acl = File.GetAccessControl(key).GetSecurityDescriptorSddlForm(AccessControlSections.All); var bytes = File.ReadAllBytes(key);
                    if (pass.Length > 0)
                    {
                        try { KeyGen.Inspect(key); throw new Exception("an encrypted key was read without its passphrase"); }
                        catch (WrongPassphraseException) { }
                    }
                    else
                    {
                        var info = KeyGen.Inspect(key);
                        if (info.Format != "PEM" || info.Encrypted || Keys.Blob(info.PublicLine) != Keys.Blob(File.ReadAllText(key + ".pub").Trim())) throw new Exception("inspected: " + info.Format + " " + info.PublicLine);
                    }
                    if (File.GetAccessControl(key).GetSecurityDescriptorSddlForm(AccessControlSections.All) != acl || !File.ReadAllBytes(key).SequenceEqual(bytes)) throw new Exception("the key file was changed");
                    done.Add(pass.Length > 0 ? "encrypted" : "plain");
                }
                return string.Join(", ", done);
            });
        }
    }
}

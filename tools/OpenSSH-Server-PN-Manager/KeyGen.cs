// OpenSSH Server PN Manager: KeyGen

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
    // ------------------------------------------------------------------------------------------
    // Key pair generator: ssh-keygen with the passphrase handed over through SSH_ASKPASS, never on a command line
    // ------------------------------------------------------------------------------------------
    internal sealed class KeyTypeChoice
    {
        public string Label; public string Type; public int Bits; public string FileName; public string PublicType; public bool Experimental;
        public override string ToString() { return Label; }
    }

    internal sealed class KeyGenResult { public string PrivatePath; public string PublicPath; public string PublicKey; public string Fingerprint; public bool Encrypted; public KeyWriteResult Written; }

    /// <summary>What an export or a conversion wrote: where, the names files already there were moved to, and whether the drive keeps no permissions.</summary>
    internal sealed class KeyWriteResult { public string Path; public List<string> MovedAside = new List<string>(); public bool Unprotected; }

    /// <summary>The formats a key can be exported in: private keys for ssh and for PuTTY, public keys for other servers.</summary>
    internal enum KeyExportFormat { OpenSshPrivate, PuttyV3, PuttyV2, OpenSshPublic, Rfc4716Public }

    /// <summary>A private key file as the Key generator tab shows it (KeyGen.Inspect).</summary>
    internal sealed class KeyFileInfo
    {
        public string Path, Format, Type, Description, Fingerprint, Comment, PublicLine; public bool Encrypted, IsPutty;
        public string FileName { get { return System.IO.Path.GetFileName(Path); } }
    }

    internal static class KeyGen
    {
        /// <summary>Environment variable that carries the answer for the SSH_ASKPASS helper (this program started by ssh-keygen or ssh).</summary>
        public const string SecretVariable = "OSM_ASKPASS_SECRET";
        /// <summary>The new passphrase for ssh-keygen -p, which asks for the old one (SecretVariable) and then twice for the new one.</summary>
        public const string NewSecretVariable = "OSM_ASKPASS_NEW";
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
            var answer = AskpassAnswer(string.Join(" ", args ?? new string[0]), Environment.GetEnvironmentVariable(KindVariable), Environment.GetEnvironmentVariable(SecretVariable), Environment.GetEnvironmentVariable(NewSecretVariable));
            if (answer == null) return 1;
            try
            {
                using (var o = Console.OpenStandardOutput())
                {
                    var b = new UTF8Encoding(false).GetBytes(answer + "\n");
                    o.Write(b, 0, b.Length); o.Flush();
                }
                return 0;
            }
            catch { return 1; }
        }

        /// <summary>
        /// The answer of the askpass helper to one prompt, or null to refuse it. With a new passphrase given (ssh-keygen -p),
        /// "Enter old passphrase" gets the secret, "Enter new passphrase" and "Enter same passphrase again" the new one.
        /// </summary>
        internal static string AskpassAnswer(string prompt, string kind, string secretValue, string newSecretValue)
        {
            bool passphrase = prompt.IndexOf("passphrase", StringComparison.OrdinalIgnoreCase) >= 0;
            bool password = !passphrase && prompt.TrimEnd().EndsWith("password:", StringComparison.OrdinalIgnoreCase);
            if (kind == "password" ? !password : !passphrase) return null;
            bool asksNew = prompt.IndexOf("new passphrase", StringComparison.OrdinalIgnoreCase) >= 0 || prompt.IndexOf("same passphrase again", StringComparison.OrdinalIgnoreCase) >= 0;
            return Unwrap(newSecretValue != null && asksNew ? newSecretValue : secretValue);
        }

        // The values carry a leading "=": Windows drops an environment variable whose value is empty, and an empty
        // passphrase ("no passphrase") must still reach the helper.
        internal static string Wrap(string secret) { return "=" + secret; }
        private static string Unwrap(string value) { return value == null ? "" : value.StartsWith("=", StringComparison.Ordinal) ? value.Substring(1) : value; }

        /// <summary>
        /// Environment for ssh-keygen or ssh: askpass with the secret (and, for ssh-keygen -p, the new passphrase), or no
        /// prompting at all when neither is given.
        /// </summary>
        internal static IDictionary<string, string> AskpassEnvironment(string secret, string newSecret = null)
        {
            if (secret == null && newSecret == null) return new Dictionary<string, string> { { "SSH_ASKPASS_REQUIRE", "never" } };
            var env = new Dictionary<string, string> { { "SSH_ASKPASS", Application.ExecutablePath }, { "SSH_ASKPASS_REQUIRE", "force" }, { SecretVariable, Wrap(secret ?? "") } };
            if (newSecret != null) env[NewSecretVariable] = Wrap(newSecret);
            return env;
        }

        /// <summary>Environment for ssh that answers the server's password prompt (--authtest only, which logs in to its own test server).</summary>
        public static IDictionary<string, string> PasswordAskpassEnvironment(string password)
        {
            var env = AskpassEnvironment(password);
            env[KindVariable] = "password";
            return env;
        }

        private static RunResult Keygen(string args, string secret, int timeoutMs, string newSecret = null)
        {
            return Proc.Run(Ssh.Exe("ssh-keygen.exe"), args, timeoutMs, null, AskpassEnvironment(secret, newSecret));
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
            ValidatePassphrase(passphrase, confirm, noPassphrase);
        }

        /// <summary>Checks a new passphrase and its confirmation; throws ConfigException with a message for the user.</summary>
        public static void ValidatePassphrase(string passphrase, string confirm, bool noPassphrase)
        {
            if (noPassphrase) return;
            if (string.IsNullOrEmpty(passphrase)) throw new ConfigException("Enter a passphrase, or choose no passphrase (only for a key used by unattended scripts).");
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
            var moved = new List<KeyValuePair<string, string>>();
            try
            {
                foreach (var f in new[] { path, path + ".pub" })
                    if (File.Exists(f)) { var aside = AsideName(f, now); File.Move(f, aside); moved.Add(new KeyValuePair<string, string>(f, aside)); }
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

        // ---------------- Loading, changing the passphrase, converting and exporting keys ----------------

        public const int MaxKeyFileSize = 256 * 1024;

        private static byte[] ReadKeyFile(string path)
        {
            var fi = new FileInfo(path);
            if (!fi.Exists) throw new ConfigException("No file at\n" + path);
            if (fi.Length > MaxKeyFileSize) throw new ConfigException("This file is too large for a key file:\n" + path);
            return File.ReadAllBytes(path);
        }

        /// <summary>
        /// What the Key generator tab shows of a private key file: format, type, fingerprint, comment, whether a passphrase
        /// protects it. OpenSSH and PuTTY files are read without the passphrase (their public key is stored in the clear);
        /// a PEM file whose .pub is missing needs it (WrongPassphraseException asks for it).
        /// </summary>
        public static KeyFileInfo Inspect(string privatePath, string passphrase = null)
        {
            var path = Path.GetFullPath(privatePath.Trim());
            if (path.EndsWith(".pub", StringComparison.OrdinalIgnoreCase) && File.Exists(path.Substring(0, path.Length - 4))) path = path.Substring(0, path.Length - 4);
            var data = ReadKeyFile(path);
            var text = Encoding.UTF8.GetString(data);
            var info = new KeyFileInfo { Path = path };
            byte[] blob;
            if (PpkFile.IsPpk(text))
            {
                var f = PpkFile.Parse(data);
                info.IsPutty = true; info.Format = "PuTTY .ppk version " + f.Version; info.Encrypted = f.Encrypted; info.Comment = f.Comment; blob = f.PublicBlob;
            }
            else if (OpenSshKeyFile.IsOpenSsh(text))
            {
                var f = OpenSshKeyFile.Parse(text);
                info.Format = "OpenSSH"; info.Encrypted = f.Encrypted; blob = f.PublicBlob;
                info.Comment = CommentOfPub(path, blob);
                if (info.Comment == null && !f.Encrypted && f.CanDecrypt) { var k = f.Decrypt(null); info.Comment = k.Comment; k.Clear(); }
            }
            else if (Regex.IsMatch(text, @"-----BEGIN [A-Z ]*PRIVATE KEY-----"))
            {
                // RSA, EC and PKCS#8 files in PEM encoding, as older ssh-keygen versions and other programs write them; ssh-keygen reads them.
                info.Format = "PEM"; info.Encrypted = IsEncrypted(path);
                // A PEM file stores no public key in the clear: it is worked out from the key itself, never taken from a .pub
                // file next to it, which could belong to another key.
                if (info.Encrypted && string.IsNullOrEmpty(passphrase)) throw new WrongPassphraseException("The key is in the older PEM format and protected by a passphrase: enter it to read the key.");
                blob = Convert.FromBase64String(Keys.Blob(DerivePublic(path, info.Encrypted ? passphrase : null)));
                info.Comment = CommentOfPub(path, blob);
            }
            else if (Keys.LooksLikePublicKey(text.Trim())) throw new ConfigException("This is a public key:\n" + path + "\n\nChoose the private key file, which has the same name without .pub.");
            else throw new ConfigException("Not a private key file in a format this program knows (OpenSSH, PuTTY .ppk or PEM):\n" + path);
            info.Type = new SshReader(blob).Text();
            info.Description = KeyFormats.Describe(blob);
            info.Comment = info.Comment ?? "";
            info.PublicLine = info.Type + " " + Convert.ToBase64String(blob) + (info.Comment.Length > 0 ? " " + info.Comment : "");
            info.Fingerprint = Keys.Fingerprint(info.PublicLine);
            return info;
        }

        private static string PubLineOf(string privatePath)
        {
            try
            {
                var p = privatePath + ".pub";
                if (!File.Exists(p) || new FileInfo(p).Length > MaxKeyFileSize) return null;
                var line = File.ReadAllLines(p).Select(l => l.Trim()).FirstOrDefault(l => l.Length > 0 && !l.StartsWith("#"));
                return line != null && Keys.LooksLikePublicKey(line) ? line : null;
            }
            catch (IOException) { return null; }
            catch (UnauthorizedAccessException) { return null; }
        }

        /// <summary>The comment of the .pub file next to a private key, when that file holds the same key.</summary>
        private static string CommentOfPub(string privatePath, byte[] blob)
        {
            var line = PubLineOf(privatePath);
            return line != null && Keys.Blob(line) == Convert.ToBase64String(blob) ? Keys.Parse(line).Comment : null;
        }

        /// <summary>The public key line that ssh-keygen -y works out from a private key; a wrong passphrase gives WrongPassphraseException.</summary>
        public static string DerivePublic(string privatePath, string passphrase)
        {
            var r = Keygen("-y -f " + Proc.Quote(privatePath), passphrase, 30000);
            var line = r.StdOut.Split('\n').Select(l => l.Trim()).FirstOrDefault(Keys.LooksLikePublicKey);
            if (r.Ok && line != null) return line;
            if (r.Output.IndexOf("passphrase", StringComparison.OrdinalIgnoreCase) >= 0) throw new WrongPassphraseException(string.IsNullOrEmpty(passphrase) ? "The key is protected by a passphrase: enter it." : "Wrong passphrase.");
            throw new ConfigException("ssh-keygen cannot read the private key:\n" + privatePath + "\n\n" + (r.TimedOut ? "timed out" : r.Output));
        }

        /// <summary>
        /// Changes, adds or removes the passphrase of an OpenSSH or PEM private key with ssh-keygen -p (a PEM file is saved in
        /// the OpenSSH format). The old passphrase is checked first, the result is verified, and the file as it was comes
        /// back (bytes and permissions) when anything fails.
        /// </summary>
        public static void ChangePassphrase(string privatePath, string oldPassphrase, string newPassphrase)
        {
            var path = Path.GetFullPath(privatePath);
            if (PpkFile.IsPpk(Encoding.UTF8.GetString(ReadKeyFile(path)))) throw new ConfigException("This is a PuTTY key. Load it first: it is converted to an OpenSSH key, whose passphrase can then be changed.");
            var before = Keys.Blob(DerivePublic(path, oldPassphrase)); // a wrong old passphrase stops here, before anything is written
            var snapshot = FileSnapshot.Take(path);
            try
            {
                var r = Keygen("-p -f " + Proc.Quote(path), oldPassphrase ?? "", 60000, newPassphrase ?? "");
                if (!r.Ok) throw new Exception("ssh-keygen could not change the passphrase: " + (r.TimedOut ? "timed out" : r.Output));
                if (Keys.Blob(DerivePublic(path, newPassphrase)) != before) throw new Exception("Verification failed: with the new passphrase, the key does not give the same public key.");
                bool encrypted = IsEncrypted(path);
                if (encrypted != !string.IsNullOrEmpty(newPassphrase)) throw new Exception("Verification failed: the key " + (encrypted ? "still needs a passphrase." : "opens without a passphrase."));
                EnsurePrivateKeyAcl(path);
                Log.Info("Passphrase of " + path + (string.IsNullOrEmpty(newPassphrase) ? " removed" : string.IsNullOrEmpty(oldPassphrase) ? " set" : " changed"));
            }
            catch
            {
                try { snapshot.Restore(); } catch (Exception ex) { Log.Error("Could not put back " + path, ex, false); }
                throw;
            }
        }

        /// <summary>
        /// The private key in memory. OpenSSH and PuTTY files are decrypted here; other formats (PEM, PKCS#8, an OpenSSH key
        /// encrypted with a cipher this program does not read) through a copy that ssh-keygen rewrites in the OpenSSH format
        /// with the same passphrase, in a folder that only this account can open.
        /// </summary>
        public static PrivateKeyData ReadPrivate(string path, string passphrase)
        {
            var data = ReadKeyFile(path);
            var text = Encoding.UTF8.GetString(data);
            if (PpkFile.IsPpk(text)) return PpkFile.Parse(data).Decrypt(passphrase);
            if (OpenSshKeyFile.IsOpenSsh(text))
            {
                var f = OpenSshKeyFile.Parse(text);
                if (KeyFormats.PrivateFieldCount(f.Type) < 0) throw new ConfigException("Keys of type " + f.Type + " (" + KeyFormats.Describe(f.PublicBlob) + ") cannot be converted.");
                if (f.CanDecrypt) return f.Decrypt(passphrase);
            }
            var dir = PrivateTempFolder();
            var copy = Path.Combine(dir, "key");
            try
            {
                WritePrivateFile(copy, data);
                var r = Keygen("-p -f " + Proc.Quote(copy), passphrase ?? "", 60000, passphrase ?? "");
                if (!r.Ok)
                {
                    if (r.Output.IndexOf("passphrase", StringComparison.OrdinalIgnoreCase) >= 0) throw new WrongPassphraseException(string.IsNullOrEmpty(passphrase) ? "The key is protected by a passphrase: enter it." : "Wrong passphrase.");
                    throw new ConfigException("ssh-keygen cannot read the private key:\n" + path + "\n\n" + r.Output);
                }
                return OpenSshKeyFile.Parse(File.ReadAllText(copy)).Decrypt(passphrase);
            }
            finally
            {
                try { if (File.Exists(copy)) File.WriteAllBytes(copy, new byte[new FileInfo(copy).Length]); } catch { }
                try { Directory.Delete(dir, true); } catch { }
            }
        }

        /// <summary>A new folder under %TEMP% that only this account, SYSTEM and Administrators can open.</summary>
        private static string PrivateTempFolder()
        {
            var ds = new DirectorySecurity(); ds.SetAccessRuleProtection(true, false);
            foreach (var sid in new[] { WindowsIdentity.GetCurrent().User, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null) })
                ds.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
            var dir = Path.Combine(Path.GetTempPath(), "osm-key-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir, ds);
            return dir;
        }

        /// <summary>Creates a private key file that only this account, SYSTEM and Administrators can read from its first byte on.</summary>
        private static void WritePrivateFile(string path, byte[] content)
        {
            var fs = new FileSecurity(); fs.SetAccessRuleProtection(true, false);
            foreach (var sid in new[] { WindowsIdentity.GetCurrent().User, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null) })
                fs.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl, AccessControlType.Allow));
            using (var s = new FileStream(path, FileMode.CreateNew, FileSystemRights.WriteData | FileSystemRights.ReadAttributes | FileSystemRights.Synchronize, FileShare.None, 4096, FileOptions.None, fs))
                s.Write(content, 0, content.Length);
            EnsurePrivateKeyAcl(path);
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool GetVolumeInformation(string rootPath, StringBuilder volumeName, int volumeNameSize, out uint serial, out uint maxComponentLength, out uint flags, StringBuilder fileSystemName, int fileSystemNameSize);

        /// <summary>False for a drive that keeps no permissions (FAT32 and exFAT, as on most USB sticks): anyone who has it can read its files.</summary>
        public static bool KeepsPermissions(string path)
        {
            try
            {
                var root = Path.GetPathRoot(Path.GetFullPath(path));
                if (string.IsNullOrEmpty(root)) return true;
                if (!root.EndsWith("\\", StringComparison.Ordinal)) root += "\\";
                uint serial, max, flags;
                if (!GetVolumeInformation(root, null, 0, out serial, out max, out flags, null, 0)) return true;
                return (flags & 0x8) != 0; // FILE_PERSISTENT_ACLS
            }
            catch { return true; }
        }

        /// <summary>
        /// Writes a private key file at its place: with the permissions ssh requires from its creation, or as a plain file on
        /// a drive that keeps no permissions (then it returns false, for a warning).
        /// </summary>
        private static bool PlaceKeyFile(string path, byte[] content)
        {
            if (KeepsPermissions(path)) { WritePrivateFile(path, content); return true; }
            using (var s = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None)) s.Write(content, 0, content.Length);
            return false;
        }

        /// <summary>
        /// Checks an OpenSSH private key with ssh-keygen in a folder only this account can open (ssh-keygen refuses a key file
        /// that others can read, as on a USB stick): it gives the same public key and opens with its passphrase and not
        /// without it. With rewrite, ssh-keygen -p first gives it newPassphrase (and the OpenSSH format). Returns the
        /// checked bytes, which are then written where they go.
        /// </summary>
        private static byte[] CheckedOpenSshFile(byte[] content, string publicLine, string passphrase, bool rewrite, string newPassphrase)
        {
            var dir = PrivateTempFolder(); var p = Path.Combine(dir, "key");
            try
            {
                WritePrivateFile(p, content);
                if (rewrite) { ChangePassphrase(p, passphrase, newPassphrase); passphrase = newPassphrase; }
                if (Keys.Blob(DerivePublic(p, passphrase)) != Keys.Blob(publicLine)) throw new Exception("Verification failed: ssh-keygen reads another public key from the new file.");
                if (IsEncrypted(p) != !string.IsNullOrEmpty(passphrase)) throw new Exception("Verification failed: the new file " + (string.IsNullOrEmpty(passphrase) ? "needs a passphrase." : "opens without a passphrase."));
                return File.ReadAllBytes(p);
            }
            finally
            {
                try { if (File.Exists(p)) File.WriteAllBytes(p, new byte[new FileInfo(p).Length]); } catch { }
                try { Directory.Delete(dir, true); } catch { }
            }
        }

        /// <summary>Writes a checked OpenSSH private key and its .pub file, moving files already there aside.</summary>
        private static KeyWriteResult WriteOpenSshPair(string target, byte[] privateBytes, string publicLine, DateTime now)
        {
            var w = new KeyWriteResult { Path = target };
            w.MovedAside = ReplacingFiles(now, () =>
            {
                w.Unprotected = !PlaceKeyFile(target, privateBytes);
                File.WriteAllText(target + ".pub", publicLine + "\n", new UTF8Encoding(false));
            }, target, target + ".pub");
            return w;
        }

        /// <summary>
        /// Runs work that creates the given files, after moving files already there aside under a dated name (a key is
        /// never overwritten). When work fails, what it created is removed and the earlier files go back to their names.
        /// Returns the names the earlier files were moved to.
        /// </summary>
        private static List<string> ReplacingFiles(DateTime now, Action work, params string[] paths)
        {
            var moved = new List<KeyValuePair<string, string>>();
            var free = new HashSet<string>(paths.Where(p => !File.Exists(p)), StringComparer.OrdinalIgnoreCase);
            bool started = false;
            try
            {
                foreach (var p in paths)
                {
                    if (!File.Exists(p)) continue;
                    var aside = AsideName(p, now);
                    File.Move(p, aside); moved.Add(new KeyValuePair<string, string>(p, aside));
                }
                started = true;
                work();
                return moved.Select(m => m.Value).ToList();
            }
            catch
            {
                // Only what work created goes: a name that held a file which could not be moved aside keeps that file.
                if (started) foreach (var p in paths) { try { if ((free.Contains(p) || moved.Any(m => string.Equals(m.Key, p, StringComparison.OrdinalIgnoreCase))) && File.Exists(p)) File.Delete(p); } catch { } }
                foreach (var m in moved) { try { if (!File.Exists(m.Key)) File.Move(m.Value, m.Key); } catch { } }
                throw;
            }
        }

        /// <summary>A free name for keeping a file aside: name.bak-date-time, then with -2, -3 ... when that is taken.</summary>
        private static string AsideName(string path, DateTime now)
        {
            var aside = path + ".bak-" + now.ToString("yyyyMMdd-HHmmss");
            for (int n = 2; File.Exists(aside); n++) aside = path + ".bak-" + now.ToString("yyyyMMdd-HHmmss") + "-" + n;
            return aside;
        }

        /// <summary>
        /// Converts a PuTTY key (.ppk) to an OpenSSH private key file with its .pub, protected by newPassphrase (empty: none).
        /// The result is checked with ssh-keygen: it opens with the new passphrase only and gives the same public key.
        /// </summary>
        public static KeyGenResult ImportPuttyKey(string ppkPath, string passphrase, string target, string newPassphrase, DateTime now)
        {
            target = Path.GetFullPath(target);
            if (string.Equals(target, Path.GetFullPath(ppkPath), StringComparison.OrdinalIgnoreCase)) throw new ConfigException("Choose another file name than the PuTTY key's.");
            var dir = Path.GetDirectoryName(target);
            if (!Directory.Exists(dir)) Directory.CreateDirectory(dir);
            var k = ReadPrivate(ppkPath, passphrase);
            try
            {
                var publicLine = k.PublicLine;
                var bytes = CheckedOpenSshFile(Encoding.ASCII.GetBytes(OpenSshKeyFile.Write(k, newPassphrase)), publicLine, newPassphrase, false, null);
                var written = WriteOpenSshPair(target, bytes, publicLine, now);
                Log.Info("PuTTY key " + ppkPath + " converted to " + target);
                return new KeyGenResult { PrivatePath = target, PublicPath = target + ".pub", PublicKey = publicLine, Fingerprint = Keys.Fingerprint(publicLine), Encrypted = !string.IsNullOrEmpty(newPassphrase), Written = written };
            }
            finally { k.Clear(); }
        }

        /// <summary>The name a format suggests for an exported copy of a key.</summary>
        public static string ExportFileName(KeyFileInfo key, KeyExportFormat format)
        {
            var name = Path.GetFileName(key.Path);
            if (name.EndsWith(".ppk", StringComparison.OrdinalIgnoreCase)) name = name.Substring(0, name.Length - 4);
            switch (format)
            {
                case KeyExportFormat.OpenSshPrivate: return name + (key.IsPutty ? "" : "-copy");
                case KeyExportFormat.PuttyV3: return name + ".ppk";
                case KeyExportFormat.PuttyV2: return name + "-ppk2.ppk";
                case KeyExportFormat.OpenSshPublic: return name + "-public.pub";
                default: return name + "-rfc4716.pub";
            }
        }

        /// <summary>
        /// Writes a copy of a key in another format. For the private formats, passphrase opens the key and newPassphrase
        /// (null or empty: none) protects the copy; every private copy is checked before it is written (a .ppk file by
        /// reading it back, an OpenSSH file with ssh-keygen). Files already at the target are moved aside.
        /// </summary>
        public static KeyWriteResult Export(KeyFileInfo key, KeyExportFormat format, string target, string passphrase, string newPassphrase, DateTime now)
        {
            target = Path.GetFullPath(target);
            bool isPrivate = format == KeyExportFormat.OpenSshPrivate || format == KeyExportFormat.PuttyV2 || format == KeyExportFormat.PuttyV3;
            if (string.Equals(target, key.Path, StringComparison.OrdinalIgnoreCase) || isPrivate && string.Equals(target, key.Path + ".pub", StringComparison.OrdinalIgnoreCase))
                throw new ConfigException("Choose another file than the key itself.");
            var dir = Path.GetDirectoryName(target);
            if (!Directory.Exists(dir)) throw new ConfigException("The folder does not exist:\n" + dir);
            var w = new KeyWriteResult { Path = target };
            switch (format)
            {
                case KeyExportFormat.OpenSshPublic:
                    w.MovedAside = ReplacingFiles(now, () => File.WriteAllText(target, key.PublicLine + "\n", new UTF8Encoding(false)), target);
                    return w;
                case KeyExportFormat.Rfc4716Public:
                {
                    var tmp = Path.Combine(Path.GetTempPath(), "osm-pub-" + Guid.NewGuid().ToString("N") + ".pub");
                    try
                    {
                        File.WriteAllText(tmp, key.PublicLine + "\n", new UTF8Encoding(false));
                        var r = Proc.Run(Ssh.Exe("ssh-keygen.exe"), "-e -f " + Proc.Quote(tmp), 30000);
                        if (!r.Ok || !r.StdOut.Contains("---- BEGIN SSH2 PUBLIC KEY ----")) throw new ConfigException("ssh-keygen could not write the key in RFC 4716 format:\n\n" + r.Output);
                        w.MovedAside = ReplacingFiles(now, () => File.WriteAllText(target, r.StdOut.Replace("\r\n", "\n"), new UTF8Encoding(false)), target);
                        return w;
                    }
                    finally { try { File.Delete(tmp); } catch { } }
                }
                case KeyExportFormat.PuttyV2:
                case KeyExportFormat.PuttyV3:
                {
                    // PuTTYgen on Windows may read a passphrase in the ANSI code page: other characters would not match there.
                    if (!PpkFile.PassphraseFits(newPassphrase)) throw new ConfigException("A passphrase for a .ppk file can have ASCII letters, digits, spaces and symbols only: PuTTY and WinSCP may read other characters differently.");
                    int version = format == KeyExportFormat.PuttyV2 ? 2 : 3;
                    var k = ReadPrivate(key.Path, passphrase);
                    try
                    {
                        if (!KeyFormats.PuttyCanUse(k.Type)) throw new ConfigException("PuTTY, WinSCP and FileZilla cannot use keys of type " + KeyFormats.Describe(k.PublicBlob) + ".");
                        if (string.IsNullOrEmpty(k.Comment)) k.Comment = key.Comment;
                        var bytes = new UTF8Encoding(false).GetBytes(PpkFile.Write(k, newPassphrase, version));
                        // Read back before it is saved: the same key, opened with the new passphrase.
                        var back = PpkFile.Parse(bytes).Decrypt(newPassphrase);
                        bool same = back.Type == k.Type && KeyFormats.Equal(back.PublicBlob, k.PublicBlob) && KeyFormats.Equal(back.Private, k.Private);
                        back.Clear();
                        if (!same) throw new Exception("Verification failed: the .ppk file does not give back the same key.");
                        w.MovedAside = ReplacingFiles(now, () => w.Unprotected = !PlaceKeyFile(target, bytes), target);
                        return w;
                    }
                    finally { k.Clear(); }
                }
                default:
                {
                    if (key.IsPutty)
                    {
                        var k = ReadPrivate(key.Path, passphrase);
                        try { return WriteOpenSshPair(target, CheckedOpenSshFile(Encoding.ASCII.GetBytes(OpenSshKeyFile.Write(k, newPassphrase)), k.PublicLine, newPassphrase, false, null), k.PublicLine, now); }
                        finally { k.Clear(); }
                    }
                    // The key's file, given another passphrase with ssh-keygen -p when asked, or when it is in the PEM format
                    // (ssh-keygen -p writes the OpenSSH format).
                    bool rewrite = (passphrase ?? "") != (newPassphrase ?? "") || key.Format != "OpenSSH";
                    return WriteOpenSshPair(target, CheckedOpenSshFile(ReadKeyFile(key.Path), key.PublicLine, passphrase, rewrite, newPassphrase), key.PublicLine, now);
                }
            }
        }

        /// <summary>True when the account running this program may log in to this server with the key (its authorized_keys file, as sshd reads it).</summary>
        public static bool IsAuthorizedForMe(string publicLine)
        {
            var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var files = Ssh.AuthorizedKeysFilesFor(LoginName(), home);
            var blob = Keys.Blob(publicLine);
            return files.Any(file => Keys.Read(file).Any(k => Keys.Blob(k.Line) == blob));
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
            var files = Ssh.AuthorizedKeysFilesFor(LoginName(), home);
            if (files.Count == 0) throw new ConfigException("This account has AuthorizedKeysFile none. Enable file-based public keys before authorizing a key.");
            var blob = Keys.Blob(publicLine);
            var target = files.FirstOrDefault(file => Keys.Read(file).Any(key => Keys.Blob(key.Line) == blob));
            if (target != null) { alreadyPresent = true; return target; }
            target = files[0];
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
                target = Ssh.AuthorizedKeysFileFor(user, home);
                if (target == null) throw new ConfigException("This account has AuthorizedKeysFile none; the key test cannot authorize temporary keys.");
                snapshots.Add(FileSnapshot.Take(target)); snapshots.Add(FileSnapshot.Take(target + ".bak"));
                var owner = IsAdminKeysFile(target) ? null : WindowsIdentity.GetCurrent().User;
                int port = SshdConfig.Load().EffectivePort;
                sb.AppendLine("OpenSSH Server PN Manager " + Program.AppVersion + " key test, account " + user + ", port " + port);
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
                // Keys that went through PuTTY's format (.ppk version 3 and 2) and were converted back log in.
                foreach (var via in new[] { new KeyValuePair<KeyTypeChoice, KeyExportFormat>(Types[0], KeyExportFormat.PuttyV3), new KeyValuePair<KeyTypeChoice, KeyExportFormat>(Types.First(t => t.Type == "rsa"), KeyExportFormat.PuttyV2) })
                {
                    var label = via.Key.Label.Split(new[] { ',', '(' })[0].Trim() + " through .ppk version " + (via.Value == KeyExportFormat.PuttyV3 ? 3 : 2) + " and back";
                    try
                    {
                        var p1 = "Kt-" + Guid.NewGuid().ToString("N").Substring(0, 14); var p2 = "Kt-" + Guid.NewGuid().ToString("N").Substring(0, 14);
                        var src = Generate(via.Key, Path.Combine(dir, "ppk-" + (++n)), "osm-keytest-ppk-" + n, p1);
                        var ppk = src.PrivatePath + ".ppk";
                        Export(Inspect(src.PrivatePath), via.Value, ppk, p1, p2, DateTime.Now);
                        var back = ImportPuttyKey(ppk, p2, src.PrivatePath + "-back", p1, DateTime.Now);
                        Keys.AddLines(target, new[] { back.PublicKey }, owner);
                        try
                        {
                            var login = TestLogin(back.PrivatePath, p1, port);
                            if (!LoginOk(login)) throw new Exception("login failed: " + login.Output);
                        }
                        finally { Keys.RemoveKey(target, back.PublicKey, owner); }
                        sb.AppendLine("PASS  " + label + ": logged in  (" + back.Fingerprint + ")");
                    }
                    catch (Exception ex) { failed++; sb.AppendLine("FAIL  " + label + ": " + ex.Message.Replace(Environment.NewLine, " ")); }
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

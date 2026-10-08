// OpenSSH Server PN Manager: Keys

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
    // Authorized keys and host keys
    // ------------------------------------------------------------------------------------------
    internal sealed class KeyEntry { public string Line; public string Type; public string Comment; public string Fingerprint; public string Options; }

    internal static class Keys
    {
        public static List<KeyEntry> Read(string path)
        {
            var l = new List<KeyEntry>();
            if (!File.Exists(path)) return l;
            foreach (var raw in File.ReadAllLines(path))
            {
                var line = raw.Trim();
                if (line.Length == 0 || line.StartsWith("#")) continue;
                l.Add(Parse(line));
            }
            return l;
        }

        // Key type names: ssh-rsa, ssh-ed25519, ssh-dss, ecdsa-sha2-nistp*, the sk- (FIDO) and webauthn- variants, certificates
        // (-cert-v01@openssh.com) and the post-quantum ssh-mldsa44-ed25519@openssh.com introduced with OpenSSH 10.5.
        private const string TypePattern = @"(?:webauthn-)?(?:sk-)?(?:ssh-[a-z0-9-]+?|ecdsa-sha2-nistp\d+)(?:-cert-v01)?(?:@openssh\.com)?";
        private static readonly Regex KeyAt = new Regex(@"\G(" + TypePattern + @")[ \t]+([A-Za-z0-9+/=]+)(?:\s+(.*))?$");

        /// <summary>
        /// The key of an authorized_keys line, found as sshd finds it (auth2-pubkeyfile.c): a key at the start of the line, or
        /// else one options field followed by the key. The options field ends at the first space or tab outside double quotes,
        /// so a key type inside an option (command="exec ssh-agent bash") is never taken for the key.
        /// </summary>
        private static Match KeyLine(string line)
        {
            line = line ?? "";
            int start = 0;
            while (start < line.Length && (line[start] == ' ' || line[start] == '\t')) start++;
            var m = KeyAt.Match(line, start);
            if (m.Success) return m;
            int i = start; bool quoted = false;
            for (; i < line.Length && (quoted || (line[i] != ' ' && line[i] != '\t')); i++)
            {
                if (line[i] == '\\' && i + 1 < line.Length && line[i + 1] == '"') i++;
                else if (line[i] == '"') quoted = !quoted;
            }
            if (quoted || i == start) return Match.Empty; // sshd refuses an unterminated quote
            while (i < line.Length && (line[i] == ' ' || line[i] == '\t')) i++;
            return KeyAt.Match(line, i);
        }

        public static KeyEntry Parse(string line)
        {
            var e = new KeyEntry { Line = line };
            var m = KeyLine(line);
            if (m.Success)
            {
                e.Type = m.Groups[1].Value; e.Comment = m.Groups[3].Value.Trim();
                e.Options = line.Substring(0, m.Index).Trim();
            }
            else { e.Type = "?"; e.Comment = line.Length > 40 ? line.Substring(0, 40) + "..." : line; }
            e.Fingerprint = Fingerprint(line);
            return e;
        }

        /// <summary>The base64 key material of a public key line (ignores options and comment), or the whole line when unparsable.</summary>
        public static string Blob(string line)
        {
            var m = KeyLine(line);
            return m.Success ? m.Groups[2].Value : (line ?? "").Trim();
        }

        /// <summary>Fingerprints already worked out, by key type and material: every reload of a list used to start one ssh-keygen per key.</summary>
        private static readonly Dictionary<string, string> FingerprintCache = new Dictionary<string, string>(StringComparer.Ordinal);

        public static string Fingerprint(string keyLine)
        {
            var m0 = KeyLine(keyLine);
            var cacheKey = m0.Success ? m0.Groups[1].Value + " " + m0.Groups[2].Value : null;
            if (cacheKey != null) lock (FingerprintCache) { string fp; if (FingerprintCache.TryGetValue(cacheKey, out fp)) return fp; }
            var tmp = Path.Combine(Path.GetTempPath(), "key." + Guid.NewGuid().ToString("N") + ".pub");
            try
            {
                File.WriteAllText(tmp, keyLine + "\n");
                var r = Proc.Run(Ssh.Exe("ssh-keygen.exe"), "-lf \"" + tmp + "\"", 10000);
                var m = Regex.Match(r.StdOut, @"(SHA256:[A-Za-z0-9+/=]+)");
                var result = m.Success ? m.Groups[1].Value : (r.Ok ? r.StdOut.Trim() : "invalid key");
                if (m.Success && cacheKey != null) lock (FingerprintCache) FingerprintCache[cacheKey] = result;
                return result;
            }
            catch { return "?"; }
            finally { try { File.Delete(tmp); } catch { } }
        }

        public static bool LooksLikePublicKey(string line)
        {
            var m = KeyLine((line ?? "").Trim());
            return m.Success && m.Groups[2].Value.Length >= 20;
        }

        public static void Write(string path, IEnumerable<string> lines, SecurityIdentifier ownerSid)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path));
            if (File.Exists(path)) File.Copy(path, path + ".bak", true);
            // Replaced in one rename: a full disk or a killed process must not leave a truncated file that refuses every key.
            // The original owner is not copied (another account's SID needs SeRestorePrivilege); the ACL and owner rules
            // below are the ones every write applies anyway.
            var tmp = path + ".new-" + Guid.NewGuid().ToString("N");
            try
            {
                using (var stream = new FileStream(tmp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
                {
                    var bytes = new UTF8Encoding(false).GetBytes(string.Join("\n", lines) + "\n");
                    stream.Write(bytes, 0, bytes.Length); stream.Flush(true);
                }
                Acl.Restrict(tmp, ownerSid);
                Acl.EnsureOwner(tmp, ownerSid);
                ConfigurationTransaction.RenameReplacing(tmp, path);
            }
            finally { try { if (File.Exists(tmp)) File.Delete(tmp); } catch { } }
            Acl.Restrict(path, ownerSid);
            // sshd also checks the owner (w32-sshfileperm.c): the account itself, SYSTEM or Administrators. A file created by an
            // elevated administrator whose objects are owned by the account (not the Administrators group) would be refused.
            Acl.EnsureOwner(path, ownerSid);
        }

        /// <summary>Every line of an authorized_keys file as written, comments and blank lines included.</summary>
        public static List<string> ReadRaw(string path)
        {
            if (!File.Exists(path)) return new List<string>();
            var l = File.ReadAllText(path).Split(new[] { "\r\n", "\n" }, StringSplitOptions.None).ToList();
            while (l.Count > 0 && l[l.Count - 1].Trim().Length == 0) l.RemoveAt(l.Count - 1);
            return l;
        }

        /// <summary>
        /// Appends public key lines to an authorized_keys file, skipping keys whose material is already present and
        /// keeping every existing line (comments included). Returns the number added and the number skipped.
        /// </summary>
        public static int[] AddLines(string path, IEnumerable<string> newLines, SecurityIdentifier ownerSid)
        {
            var raw = ReadRaw(path);
            var blobs = new HashSet<string>(Read(path).Select(k => Blob(k.Line)));
            int added = 0, skipped = 0;
            foreach (var n in newLines)
            {
                var line = (n ?? "").Trim(); if (line.Length == 0 || line.StartsWith("#")) continue;
                if (line.Any(c => c != '\t' && char.IsControl(c))) throw new ConfigException("A key line contains a control character.");
                if (!LooksLikePublicKey(line)) throw new ConfigException("Not an OpenSSH public key line:\n" + line);
                if (!blobs.Add(Blob(line))) { skipped++; continue; }
                raw.Add(line); added++;
            }
            if (added > 0) Write(path, raw, ownerSid);
            return new[] { added, skipped };
        }

        /// <summary>Removes the lines that carry this key (compared by key material); every other line is kept.</summary>
        public static int RemoveKey(string path, string keyLine, SecurityIdentifier ownerSid)
        {
            var blob = Blob(keyLine);
            var raw = ReadRaw(path);
            var kept = raw.Where(l => { var t = l.Trim(); return t.Length == 0 || t.StartsWith("#") || Blob(t) != blob; }).ToList();
            int removed = raw.Count - kept.Count;
            if (removed > 0) Write(path, kept, ownerSid);
            return removed;
        }

        public static string UserKeysPath(string profileDir) { return Path.Combine(profileDir, @".ssh\authorized_keys"); }

        /// <summary>Profile folder => account SID from the ProfileList registry key (user accounts only, S-1-5-21-*).</summary>
        private static Dictionary<string, SecurityIdentifier> ProfileList()
        {
            var d = new Dictionary<string, SecurityIdentifier>(StringComparer.OrdinalIgnoreCase);
            try
            {
                using (var k = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default).OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"))
                {
                    if (k == null) return d;
                    foreach (var sidName in k.GetSubKeyNames())
                    {
                        if (!sidName.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase)) continue;
                        try
                        {
                            using (var p = k.OpenSubKey(sidName))
                            {
                                var path = p == null ? null : p.GetValue("ProfileImagePath") as string;
                                if (string.IsNullOrEmpty(path)) continue;
                                path = Environment.ExpandEnvironmentVariables(path).TrimEnd('\\');
                                if (Directory.Exists(path)) d[path] = new SecurityIdentifier(sidName);
                            }
                        }
                        catch { }
                    }
                }
            }
            catch { }
            return d;
        }

        public static List<string> UserProfiles()
        {
            var l = ProfileList().Keys.OrderBy(p => p, StringComparer.OrdinalIgnoreCase).ToList();
            if (l.Count > 0) return l;
            // Fallback when the registry is not readable: the folders next to the current profile.
            try
            {
                var root = Path.GetDirectoryName(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));
                foreach (var d in Directory.GetDirectories(root))
                {
                    var n = Path.GetFileName(d);
                    if (n.Equals("Public", StringComparison.OrdinalIgnoreCase) || n.Equals("Default", StringComparison.OrdinalIgnoreCase) || n.Equals("Default User", StringComparison.OrdinalIgnoreCase) || n.Equals("All Users", StringComparison.OrdinalIgnoreCase)) continue;
                    l.Add(d);
                }
            }
            catch { }
            return l;
        }

        /// <summary>SID of the account that owns a profile folder: from ProfileList, else by translating the folder name.</summary>
        public static SecurityIdentifier SidOfProfile(string profileDir)
        {
            SecurityIdentifier sid;
            if (ProfileList().TryGetValue((profileDir ?? "").TrimEnd('\\'), out sid)) return sid;
            var name = Path.GetFileName((profileDir ?? "").TrimEnd('\\'));
            return Acl.SidOfAccount(name) ?? Acl.SidOfAccount(Environment.MachineName + "\\" + name);
        }

        /// <summary>
        /// The keys in these authorized_keys files that sshd can log someone in with: not a cert-authority line (it needs
        /// a certificate), not DSA (this build has none), and key material ssh-keygen reads (a SHA256 fingerprint), so a
        /// truncated, mislabelled or made-up line does not count. fingerprint: for tests; ssh-keygen otherwise.
        /// </summary>
        public static int UsableCount(IEnumerable<string> files, Func<string, string> fingerprint = null)
        {
            if (fingerprint == null) fingerprint = Fingerprint;
            int n = 0;
            foreach (var file in files)
            {
                if (!File.Exists(file)) continue;
                foreach (var raw in File.ReadAllLines(file))
                {
                    var line = raw.Trim();
                    if (line.Length == 0 || line.StartsWith("#")) continue;
                    var m = KeyLine(line);
                    if (!m.Success || m.Groups[1].Value.StartsWith("ssh-dss", StringComparison.Ordinal)) continue;
                    // Options are separated by commas outside double quotes; sshd compares their names without case.
                    var options = Regex.Matches(line.Substring(0, m.Index), @"(?:""(?:\\.|[^""\\])*""|[^,""])+").Cast<Match>();
                    if (options.Any(o => o.Value.Trim().Equals("cert-authority", StringComparison.OrdinalIgnoreCase))) continue;
                    var fp = fingerprint(line);
                    if (fp != null && fp.StartsWith("SHA256:", StringComparison.Ordinal)) n++;
                }
            }
            return n;
        }
    }

    internal sealed class HostKey { public string File; public string Type; public string Fingerprint; public string Bits; }

    internal static class HostKeys
    {
        // ssh-keygen -l is only re-run for a public key file whose timestamp changed (the dashboard refreshes every 5 s).
        private static readonly Dictionary<string, KeyValuePair<DateTime, HostKey>> Cache = new Dictionary<string, KeyValuePair<DateTime, HostKey>>(StringComparer.OrdinalIgnoreCase);

        /// <summary>Parses one line of "ssh-keygen -l" output: bits, SHA256 fingerprint, type in parentheses (may contain hyphens, e.g. MLDSA44-ED25519, ED25519-SK).</summary>
        public static bool ParseKeygenOutput(string output, HostKey hk)
        {
            var m = Regex.Match(output ?? "", @"^(\d+)\s+(SHA256:\S+).*\(([\w-]+)\)\s*$", RegexOptions.Multiline);
            if (!m.Success) return false;
            hk.Bits = m.Groups[1].Value; hk.Fingerprint = m.Groups[2].Value; hk.Type = m.Groups[3].Value;
            return true;
        }

        public static List<HostKey> List()
        {
            var l = new List<HostKey>();
            try
            {
                if (!Directory.Exists(Ssh.ConfigDir)) return l;
                foreach (var pub in Directory.GetFiles(Ssh.ConfigDir, "ssh_host_*_key.pub"))
                {
                    var stamp = File.GetLastWriteTimeUtc(pub);
                    KeyValuePair<DateTime, HostKey> cached;
                    lock (Cache)
                    {
                        if (Cache.TryGetValue(pub, out cached) && cached.Key == stamp && cached.Value.Fingerprint != null && cached.Value.Fingerprint.StartsWith("SHA256:")) { l.Add(cached.Value); continue; }
                    }
                    var hk = new HostKey { File = Path.GetFileNameWithoutExtension(pub) };
                    var r = Proc.Run(Ssh.Exe("ssh-keygen.exe"), "-lf \"" + pub + "\"", 10000);
                    if (!ParseKeygenOutput(r.StdOut, hk)) { hk.Type = "?"; hk.Fingerprint = r.Output; }
                    lock (Cache) Cache[pub] = new KeyValuePair<DateTime, HostKey>(stamp, hk);
                    l.Add(hk);
                }
            }
            catch (Exception ex) { l.Add(new HostKey { File = "error", Type = "", Fingerprint = ex.Message }); }
            return l;
        }

        /// <summary>Generates any missing host keys (ssh-keygen -A) and applies the required ACL.</summary>
        public static string GenerateMissing()
        {
            Directory.CreateDirectory(Ssh.ConfigDir);
            var r = Proc.Run(Ssh.Exe("ssh-keygen.exe"), "-A", 60000, Ssh.InstallDir);
            foreach (var f in Directory.GetFiles(Ssh.ConfigDir, "ssh_host_*_key")) { try { Acl.Restrict(f, null); } catch { } }
            return r.Output;
        }
    }
}

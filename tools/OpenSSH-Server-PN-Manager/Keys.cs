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
using Microsoft.Win32.SafeHandles;

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
            foreach (var raw in ReadRaw(path)) // lines end at LF only, as sshd reads them: a lone CR stays in the line
            {
                var line = raw.Trim();
                if (line.Length == 0 || line.StartsWith("#")) continue;
                l.Add(Parse(line));
            }
            return l;
        }

        // Key type names: ssh-rsa, ssh-ed25519, ssh-dss, ecdsa-sha2-nistp*, the sk- (FIDO) and webauthn- variants, certificates
        // (-cert-v01@openssh.com) and the post-quantum ssh-mldsa44-ed25519@openssh.com introduced with OpenSSH 10.5. sshd also
        // takes an RSA key under its signature names rsa-sha2-256 and rsa-sha2-512 (and their certificate forms).
        private const string TypePattern = @"(?:webauthn-)?(?:sk-)?(?:ssh-[a-z0-9-]+?|ecdsa-sha2-nistp\d+|rsa-sha2-(?:256|512))(?:-cert-v01)?(?:@openssh\.com)?";
        // The key material is the word up to a space or tab: sshd's base64 decoder skips \v, \f and \r inside it.
        private static readonly Regex KeyAt = new Regex(@"\G(" + TypePattern + @")[ \t]+([A-Za-z0-9+/=\v\f\r]+)(?:[ \t]+(.*))?$");

        private static string Material(Match m) { return m.Groups[2].Value.Replace("\v", "").Replace("\f", "").Replace("\r", ""); }

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
            return m.Success ? Material(m) : (line ?? "").Trim();
        }

        /// <summary>Fingerprints already worked out, by key type and material: every reload of a list used to start one ssh-keygen per key.</summary>
        private static readonly Dictionary<string, string> FingerprintCache = new Dictionary<string, string>(StringComparer.Ordinal);

        public static string Fingerprint(string keyLine)
        {
            var m0 = KeyLine(keyLine);
            var cacheKey = m0.Success ? m0.Groups[1].Value + " " + Material(m0) : null;
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
            return m.Success && Material(m).Length >= 20;
        }

        /// <summary>
        /// Replaces a key file, keeping the previous one as .bak unless backup is false. Both are new files renamed into place,
        /// never written through their names: an account can turn its own .ssh folder, or a file in it, into a link to another
        /// account's file, and this program runs as administrator. A folder reached through a junction or symbolic link, and
        /// a file or .bak that is a link or has a second name (hard link), are refused.
        /// </summary>
        public static void Write(string path, IEnumerable<string> lines, SecurityIdentifier ownerSid, bool backup = true)
        {
            var l = lines.ToList();
            Update(path, previous => l, ownerSid, backup);
        }

        /// <summary>
        /// Changes a key file as Write writes it: change gets the file's lines (as ReadRaw gives them) and returns the new lines,
        /// or null to leave the file. The lines are read through the handle that was checked, inside the checked folder: read
        /// by name before the checks, they could have come from another account's file.
        /// </summary>
        private static void Update(string path, Func<List<string>, List<string>> change, SecurityIdentifier ownerSid, bool backup)
        {
            path = Path.GetFullPath(path);
            var dir = Path.GetDirectoryName(path);
            Directory.CreateDirectory(dir);
            using (OpenVerifiedFolder(dir))
            {
                var previous = ReadPlainFile(path);
                var lines = change(previous == null ? new List<string>() : Lines(Text(previous)));
                if (lines == null) return;
                if (backup) RequirePlainFile(path + ".bak");
                if (backup && previous != null)
                {
                    // A .bak someone holds open must not stop a change such as revoking a key: the backup is best effort.
                    try { Replace(path + ".bak", previous, ownerSid); }
                    catch (Exception ex) { Log.Error("Could not keep the previous " + path + " as .bak", ex, false); }
                }
                // Replaced in one rename: a full disk or a killed process must not leave a truncated file that refuses every key.
                Replace(path, new UTF8Encoding(false).GetBytes(string.Join("\n", lines) + "\n"), ownerSid);
            }
        }

        /// <summary>
        /// Gives an existing key file the permissions Write gives it, through a handle on the file after the checks Write makes:
        /// set by name, as administrator, they would follow a link the account made and grant it the file behind the link.
        /// </summary>
        public static void RestrictKeyFile(string path, SecurityIdentifier ownerSid)
        {
            path = Path.GetFullPath(path);
            using (OpenVerifiedFolder(Path.GetDirectoryName(path)))
            {
                FileInformation info;
                using (var h = OpenPlainFile(path, ReadControl | WriteDac | ReadAttributes, out info))
                {
                    if (h == null) return;
                    var sd = new RawSecurityDescriptor(KeyFileSecurity(ownerSid).GetSecurityDescriptorBinaryForm(), 0);
                    var dacl = new byte[sd.DiscretionaryAcl.BinaryLength];
                    sd.DiscretionaryAcl.GetBinaryForm(dacl, 0);
                    int error = SetSecurityInfo(h, 1, DaclSecurityInformation | ProtectedDaclSecurityInformation, IntPtr.Zero, IntPtr.Zero, dacl, IntPtr.Zero);
                    if (error != 0) { var e = new Win32Exception(error); throw new IOException("Could not set the permissions of " + path + ": " + e.Message, e); }
                }
            }
        }

        private static readonly SecurityIdentifier SystemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        private static readonly SecurityIdentifier AdminsSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);

        /// <summary>SYSTEM, Administrators and ownerSid full control, nothing inherited.</summary>
        private static FileSecurity KeyFileSecurity(SecurityIdentifier ownerSid)
        {
            var security = new FileSecurity();
            security.SetAccessRuleProtection(true, false);
            security.AddAccessRule(new FileSystemAccessRule(SystemSid, FileSystemRights.FullControl, AccessControlType.Allow));
            security.AddAccessRule(new FileSystemAccessRule(AdminsSid, FileSystemRights.FullControl, AccessControlType.Allow));
            if (ownerSid != null && ownerSid != AdminsSid && ownerSid != SystemSid) security.AddAccessRule(new FileSystemAccessRule(ownerSid, FileSystemRights.FullControl, AccessControlType.Allow));
            return security;
        }

        /// <summary>
        /// Writes a new file beside path and renames it over path. Its permissions are final from its creation (SYSTEM,
        /// Administrators and ownerSid, nothing inherited): C:\ProgramData\ssh lets every user read new files, and a reader
        /// holding the file open would make the rename fail. The original owner is not copied (another account's SID needs
        /// SeRestorePrivilege).
        /// </summary>
        private static void Replace(string path, byte[] bytes, SecurityIdentifier ownerSid)
        {
            var security = KeyFileSecurity(ownerSid);
            var tmp = path + ".new-" + Guid.NewGuid().ToString("N");
            try
            {
                using (var stream = new FileStream(tmp, FileMode.CreateNew, FileSystemRights.WriteData | FileSystemRights.ReadAttributes | FileSystemRights.Synchronize, FileShare.None, 4096, FileOptions.WriteThrough, security))
                {
                    stream.Write(bytes, 0, bytes.Length); stream.Flush(true);
                }
                // sshd also checks the owner (w32-sshfileperm.c): the account itself, SYSTEM or Administrators. A file created by an
                // elevated administrator whose objects are owned by the account (not the Administrators group) would be refused.
                Acl.EnsureOwner(tmp, ownerSid);
                ConfigurationTransaction.RenameReplacing(tmp, path);
            }
            finally { try { if (File.Exists(tmp)) File.Delete(tmp); } catch { } }
        }

        [DllImport("advapi32.dll")]
        private static extern int SetSecurityInfo(SafeFileHandle handle, int objectType, uint securityInfo, IntPtr owner, IntPtr group, byte[] dacl, IntPtr sacl);

        [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFile(string name, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);

        [DllImport("kernel32.dll", EntryPoint = "GetFinalPathNameByHandleW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int GetFinalPathNameByHandle(SafeFileHandle file, StringBuilder path, int size, uint flags);

        [DllImport("kernel32.dll", EntryPoint = "GetLongPathNameW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int GetLongPathName(string path, StringBuilder longPath, int size);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetFileInformationByHandle(SafeFileHandle file, out FileInformation info);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetFileInformationByHandleEx(SafeFileHandle file, int infoClass, out AttributeTagInformation info, int size);

        /// <summary>BY_HANDLE_FILE_INFORMATION (the FILETIME fields as two halves each).</summary>
        [StructLayout(LayoutKind.Sequential)]
        private struct FileInformation { public uint Attributes, CreatedLow, CreatedHigh, AccessedLow, AccessedHigh, WrittenLow, WrittenHigh, Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow; }

        /// <summary>FILE_ATTRIBUTE_TAG_INFO.</summary>
        [StructLayout(LayoutKind.Sequential)]
        private struct AttributeTagInformation { public uint Attributes, ReparseTag; }

        private const uint ListDirectory = 0x1, ReadAttributes = 0x80, ShareRead = 0x1, ShareWrite = 0x2, ShareDelete = 0x4, OpenExisting = 3;
        private const uint BackupSemantics = 0x02000000, OpenReparsePoint = 0x00200000;
        private const uint GenericRead = 0x80000000, ReadControl = 0x20000, WriteDac = 0x40000, DaclSecurityInformation = 0x4, ProtectedDaclSecurityInformation = 0x80000000;

        /// <summary>
        /// Opens a key file's folder and checks that it is the folder its path names, with no junction or symbolic link on the
        /// way. The handle shares no delete access, so the folder cannot be renamed and replaced by a link until it is closed.
        /// </summary>
        private static SafeFileHandle OpenVerifiedFolder(string dir)
        {
            var h = CreateFile(dir, ListDirectory | ReadAttributes, ShareRead | ShareWrite, IntPtr.Zero, OpenExisting, BackupSemantics, IntPtr.Zero);
            if (h.IsInvalid) { var e = new Win32Exception(Marshal.GetLastWin32Error()); throw new IOException("Could not open " + dir + ": " + e.Message, e); }
            try
            {
                var final = new StringBuilder(1024);
                int n = GetFinalPathNameByHandle(h, final, final.Capacity, 0);
                if (n >= final.Capacity) { final = new StringBuilder(n + 1); n = GetFinalPathNameByHandle(h, final, final.Capacity, 0); }
                if (n <= 0 || n >= final.Capacity) { var e = new Win32Exception(Marshal.GetLastWin32Error()); throw new IOException("Could not find where " + dir + " leads: " + e.Message, e); }
                var actual = final.ToString();
                if (actual.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase)) actual = @"\" + actual.Substring(7);
                else if (actual.StartsWith(@"\\?\", StringComparison.Ordinal)) actual = actual.Substring(4);
                // Short (8.3) names, as in a TEMP path, are not links.
                var expected = new StringBuilder(1024);
                int m = GetLongPathName(dir, expected, expected.Capacity);
                var named = m > 0 && m < expected.Capacity ? expected.ToString() : dir;
                if (!string.Equals(actual.TrimEnd('\\'), named.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase))
                    throw new ConfigException("Key files are not written through a junction or symbolic link:\n" + dir + "\nleads to\n" + actual);
                return h;
            }
            catch { h.Dispose(); throw; }
        }

        /// <summary>
        /// Opens a key file (or its .bak) itself, never what a link leads to, and refuses one that is a link, a folder, or a file
        /// with a second name (a hard link). Null when there is no such file.
        /// </summary>
        private static SafeFileHandle OpenPlainFile(string path, uint access, out FileInformation info)
        {
            info = new FileInformation();
            var h = CreateFile(path, access, ShareRead | ShareWrite | ShareDelete, IntPtr.Zero, OpenExisting, BackupSemantics | OpenReparsePoint, IntPtr.Zero);
            if (h.IsInvalid)
            {
                int error = Marshal.GetLastWin32Error(); h.Dispose();
                if (error == 2) return null; // not there (yet)
                var e = new Win32Exception(error); throw new IOException("Could not open " + path + ": " + e.Message, e);
            }
            try
            {
                AttributeTagInformation tag;
                if (!GetFileInformationByHandle(h, out info) || !GetFileInformationByHandleEx(h, 9, out tag, Marshal.SizeOf(typeof(AttributeTagInformation))))
                { var e = new Win32Exception(Marshal.GetLastWin32Error()); throw new IOException("Could not check " + path + ": " + e.Message, e); }
                // Name surrogates (symbolic links, junctions) lead elsewhere; other reparse points (deduplication, cloud files) do not.
                if ((info.Attributes & 0x10) != 0 || (info.Attributes & 0x400) != 0 && (tag.ReparseTag & 0x20000000) != 0)
                    throw new ConfigException(path + " is a link or a folder, not a file. Key files are not written through links.");
                if (info.Links > 1) throw new ConfigException(path + " has " + info.Links + " names (hard links). Key files are not written through links.");
                return h;
            }
            catch { h.Dispose(); throw; }
        }

        private static void RequirePlainFile(string path)
        {
            FileInformation info;
            using (OpenPlainFile(path, ReadAttributes, out info)) { }
        }

        /// <summary>A key file's bytes, read through a handle OpenPlainFile checked; null when there is no file.</summary>
        private static byte[] ReadPlainFile(string path)
        {
            FileInformation info;
            var h = OpenPlainFile(path, GenericRead, out info);
            if (h == null) return null;
            try
            {
                if ((info.Attributes & 0x400) != 0)
                {
                    // A deduplicated or cloud file's data comes through its filter, which this handle bypasses: the same file
                    // again by name, known by its file ID.
                    var data = CreateFile(path, GenericRead, ShareRead | ShareWrite | ShareDelete, IntPtr.Zero, OpenExisting, 0, IntPtr.Zero);
                    FileInformation same;
                    if (data.IsInvalid || !GetFileInformationByHandle(data, out same) || same.Volume != info.Volume || same.IndexHigh != info.IndexHigh || same.IndexLow != info.IndexLow)
                    { data.Dispose(); throw new IOException("Could not read " + path + " as the file that was checked."); }
                    h.Dispose(); h = data;
                }
                // Shared like sshd's own reads, so that a login at this moment does not make the change fail.
                using (var s = new FileStream(h, FileAccess.Read))
                using (var m = new MemoryStream()) { s.CopyTo(m); return m.ToArray(); }
            }
            finally { h.Dispose(); }
        }

        /// <summary>Text as File.ReadAllText decodes it: UTF-8 unless a byte order mark says otherwise.</summary>
        private static string Text(byte[] bytes)
        {
            using (var r = new StreamReader(new MemoryStream(bytes), Encoding.UTF8, true)) return r.ReadToEnd();
        }

        /// <summary>Every line of an authorized_keys file as written, comments and blank lines included.</summary>
        public static List<string> ReadRaw(string path)
        {
            return File.Exists(path) ? Lines(File.ReadAllText(path)) : new List<string>();
        }

        /// <summary>Lines as sshd reads them: ended by LF (a CR before it is dropped, one elsewhere kept), trailing blank lines left out.</summary>
        private static List<string> Lines(string text)
        {
            var l = text.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None).ToList();
            while (l.Count > 0 && l[l.Count - 1].Trim().Length == 0) l.RemoveAt(l.Count - 1);
            return l;
        }

        /// <summary>
        /// Appends public key lines to an authorized_keys file, skipping keys whose material is already present and
        /// keeping every existing line (comments included). Returns the number added and the number skipped.
        /// </summary>
        public static int[] AddLines(string path, IEnumerable<string> newLines, SecurityIdentifier ownerSid, bool backup = true)
        {
            var lines = new List<string>();
            foreach (var n in newLines)
            {
                var line = (n ?? "").Trim(); if (line.Length == 0 || line.StartsWith("#")) continue;
                if (line.Any(c => c != '\t' && char.IsControl(c))) throw new ConfigException("A key line contains a control character.");
                if (!LooksLikePublicKey(line)) throw new ConfigException("Not an OpenSSH public key line:\n" + line);
                lines.Add(line);
            }
            int added = 0, skipped = 0;
            if (lines.Count > 0) Update(path, raw =>
            {
                var blobs = new HashSet<string>(raw.Select(l => l.Trim()).Where(t => t.Length > 0 && !t.StartsWith("#")).Select(t => Blob(t)));
                foreach (var line in lines)
                {
                    if (!blobs.Add(Blob(line))) { skipped++; continue; }
                    raw.Add(line); added++;
                }
                return added > 0 ? raw : null;
            }, ownerSid, backup);
            return new[] { added, skipped };
        }

        /// <summary>Removes the lines that carry this key (compared by key material); every other line is kept.</summary>
        public static int RemoveKey(string path, string keyLine, SecurityIdentifier ownerSid, bool backup = true)
        {
            var blob = Blob(keyLine);
            int removed = 0;
            if (File.Exists(path)) Update(path, raw =>
            {
                var kept = raw.Where(l => { var t = l.Trim(); return t.Length == 0 || t.StartsWith("#") || Blob(t) != blob; }).ToList();
                removed = raw.Count - kept.Count;
                return removed > 0 ? kept : null;
            }, ownerSid, backup);
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

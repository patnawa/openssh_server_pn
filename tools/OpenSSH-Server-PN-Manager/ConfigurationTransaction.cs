using System;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading;

namespace OpenSSHServerPNManager
{
    /// <summary>
    /// The configuration lock stayed taken by another process, so nothing was done. While a change awaits recovery that is
    /// normally a restore in progress (the recovery task, or a window), not a failure of one.
    /// </summary>
    internal sealed class ConfigurationBusyException : ConfigException { public ConfigurationBusyException(string m) : base(m) { } }

    /// <summary>Validation, conflict detection, backup and atomic commit share one transaction for every server editor.</summary>
    internal static class ConfigurationTransaction
    {
        /// <summary>How long Locked waits for another configuration operation (tests shorten it).</summary>
        internal static int LockWaitMilliseconds = 15000;

        internal static T Locked<T>(string path, Func<T> action)
        {
            string name;
            using (var sha = System.Security.Cryptography.SHA256.Create())
                name = "Global\\OpenSSHServerPNManager.Config." + BitConverter.ToString(sha.ComputeHash(Encoding.UTF8.GetBytes(Path.GetFullPath(path).ToUpperInvariant()))).Replace("-", "");
            var security = new MutexSecurity();
            foreach (var type in new[] { WellKnownSidType.LocalSystemSid, WellKnownSidType.BuiltinAdministratorsSid })
                security.AddAccessRule(new MutexAccessRule(new SecurityIdentifier(type, null), MutexRights.FullControl, AccessControlType.Allow));
            using (var identity = WindowsIdentity.GetCurrent()) security.AddAccessRule(new MutexAccessRule(identity.User, MutexRights.FullControl, AccessControlType.Allow));
            bool created;
            using (var mutex = new Mutex(false, name, out created, security))
            {
                bool acquired = false;
                try
                {
                    try { acquired = mutex.WaitOne(LockWaitMilliseconds); } catch (AbandonedMutexException) { acquired = true; }
                    if (!acquired) throw new ConfigurationBusyException("Another configuration operation is still running. Try again when it finishes.");
                    return action();
                }
                finally { if (acquired) mutex.ReleaseMutex(); }
            }
        }

        public static string Save(SshdConfig candidate, bool overwrite)
        {
            var refusal = SshdConfig.NonUtf8Refusal(candidate, File.Exists(candidate.Path) ? File.ReadAllBytes(candidate.Path) : null);
            if (refusal != null) throw new ConfigException(refusal);
            var bytes = candidate.ExactBytes ?? new UTF8Encoding(false).GetBytes(candidate.Text);
            // Keep the validation fixture beside its destination, under the same protected directory.
            Directory.CreateDirectory(Path.GetDirectoryName(candidate.Path));
            var tmp = candidate.Path + ".candidate-" + Guid.NewGuid().ToString("N");
            File.WriteAllBytes(tmp, bytes);
            try
            {
                if (candidate.LoadedDependencies != null) candidate.LoadedDependencies.RequireUnchanged();
                var candidateDependencies = ConfigurationDependencies.Capture(candidate.Lines);
                var dependencies = ConfigurationDependencies.Combine(candidate.LoadedDependencies, candidateDependencies);
                var result = Ssh.TestConfig(tmp);
                if (!result.Ok) throw new ConfigException("The configuration was NOT saved because sshd rejected it:\n\n" + result.Output.Replace(tmp, "sshd_config"));
                return Locked(candidate.Path, () =>
                {
                    ConfigurationRecovery.RequireNoPending(candidate.Path);
                    dependencies.RequireUnchanged();
                    var originalHash = SshdConfig.FileHash(candidate.Path);
                    if (!overwrite && candidate.LoadedHash != null && originalHash != candidate.LoadedHash)
                        throw new ConfigChangedException(candidate.Path + " was changed by another program after this window read it.");
                    dependencies = ConfigurationDependencies.Combine(dependencies, ConfigurationDependencies.Capture(File.Exists(candidate.Path) ? File.ReadAllLines(candidate.Path) : new string[0]));
                    string backup = null;
                    if (File.Exists(candidate.Path))
                    {
                        backup = SshdConfig.NewBackupPath(candidate.Path, DateTime.Now);
                        File.Copy(candidate.Path, backup, false);
                        if (SshdConfig.FileHash(backup) != originalHash) throw new ConfigChangedException("The configuration changed while its backup was being created. Reload before saving.");
                    }
                    // Persist the previous bytes and the validated Include graph before replacing the live root.
                    ConfigurationRecovery.OpenForPath(candidate.Path).Prepare(backup, bytes, dependencies);
                    dependencies.RequireUnchanged();
                    if (SshdConfig.FileHash(candidate.Path) != originalHash) throw new ConfigChangedException("The configuration changed before its atomic replacement. No changes were saved.");
                    AtomicBytes(candidate.Path, bytes);
                    candidate.LoadedHash = SshdConfig.FileHash(candidate.Path);
                    candidate.LoadedDependencies = candidateDependencies;
                    Log.Info("Saved " + candidate.Path + (backup == null ? "" : " (backup " + backup + ")"));
                    try { SshdConfig.PruneBackups(candidate.Path, SshdConfig.KeepBackups); } catch (Exception ex) { Log.Error("Pruning old backups", ex, false); }
                    return backup;
                });
            }
            finally { try { File.Delete(tmp); } catch { } }
        }

        public static void AtomicWrite(string path, string text) { AtomicWrite(path, text, null); }

        internal static void AtomicWrite(string path, string text, Action<string, string> replace)
        { AtomicBytes(path, new UTF8Encoding(false).GetBytes(text), replace); }

        internal static void AtomicBytes(string path, byte[] bytes, Action<string, string> replace = null, Action<string> secureTemporary = null)
        {
            var tmp = path + ".new-" + Guid.NewGuid().ToString("N");
            try
            {
                const AccessControlSections sections = AccessControlSections.Owner | AccessControlSections.Group | AccessControlSections.Access;
                var originalSecurity = File.Exists(path) ? File.GetAccessControl(path, sections) : null;
                var attributes = originalSecurity == null ? FileAttributes.Normal : File.GetAttributes(path);
                var created = originalSecurity == null ? DateTime.MinValue : File.GetCreationTimeUtc(path);
                if ((attributes & (FileAttributes.ReadOnly | FileAttributes.ReparsePoint | FileAttributes.Directory | FileAttributes.Device)) != 0)
                    throw new IOException("Atomic replacement requires a writable regular file, without a reparse point.");
                // Establish security while empty, before staging either the original or replacement bytes.
                using (new FileStream(tmp, FileMode.CreateNew, FileAccess.Write, FileShare.None)) { }
                if (secureTemporary != null) secureTemporary(tmp);
                if (originalSecurity != null)
                {
                    CopyExactSecurity(tmp, originalSecurity);
                    // Keep alternate data streams, extended/resource attributes and encryption/compression metadata.
                    // Copy into the already secured temporary file; never request a decrypted fallback.
                    if (!CopyFileEx(path, tmp, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 0)) throw new Win32Exception(Marshal.GetLastWin32Error());
                    CopyExactSecurity(tmp, originalSecurity);
                    File.SetAttributes(tmp, attributes);
                    if (File.GetAttributes(tmp) != attributes) throw new IOException("The temporary copy did not preserve the original file attributes.");
                }
                using (var stream = new FileStream(tmp, FileMode.Truncate, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
                {
                    stream.Write(bytes, 0, bytes.Length); stream.Flush(true);
                }
                if (File.Exists(path))
                {
                    if (originalSecurity == null || !SameFileSecurity(originalSecurity, File.GetAccessControl(path, sections)))
                        throw new IOException("The destination security changed before atomic replacement.");
                    if (File.GetAttributes(path) != attributes || File.GetCreationTimeUtc(path) != created)
                        throw new IOException("The destination metadata changed before atomic replacement.");
                    File.SetCreationTimeUtc(tmp, created); File.SetAttributes(tmp, attributes);
                    if (replace != null) replace(tmp, path);
                    // Same directory, same volume: no copy/delete fallback. Unlike ReplaceFile, rename does not
                    // merge legacy inherited ACEs into new explicit entries on Windows Server 2022.
                    else if (!MoveFileEx(tmp, path, 1 | 8)) throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                else
                {
                    if (originalSecurity != null) throw new IOException("The destination disappeared before atomic replacement.");
                    File.Move(tmp, path);
                }
            }
            catch (Exception ex) { throw new IOException("Atomic write failed; the existing file was not overwritten in place: " + path, ex); }
            finally { try { if (File.Exists(tmp)) File.Delete(tmp); } catch { } }
        }

        [DllImport("advapi32.dll", EntryPoint = "SetFileSecurityW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool SetFileSecurity(string path, uint information, byte[] descriptor);

        [DllImport("kernel32.dll", EntryPoint = "CopyFileExW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CopyFileEx(string source, string destination, IntPtr progress, IntPtr data, IntPtr cancel, uint flags);

        [DllImport("kernel32.dll", EntryPoint = "MoveFileExW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool MoveFileEx(string source, string destination, uint flags);

        /// <summary>
        /// Same-directory rename over the destination (or to a new name), with no copy/delete fallback. Any open handle on
        /// the destination refuses the rename, even one that shares delete; sshd opens authorized_keys for every key login,
        /// so a refusal while the destination exists is retried for about 3 s.
        /// </summary>
        internal static void RenameReplacing(string source, string destination)
        {
            int start = Environment.TickCount;
            while (!MoveFileEx(source, destination, 1 | 8))
            {
                int error = Marshal.GetLastWin32Error();
                if ((error == 5 || error == 32) && unchecked(Environment.TickCount - start) < 3000 && File.Exists(destination)) { Thread.Sleep(100); continue; }
                var reason = new Win32Exception(error);
                throw new IOException("Could not replace " + destination + ": " + reason.Message.TrimEnd('.', ' ') + "." + (error == 5 ? " It may be open in another program; try again." : ""), reason);
            }
        }

        private static void CopyExactSecurity(string path, FileSecurity security)
        {
            var raw = new RawSecurityDescriptor(security.GetSecurityDescriptorBinaryForm(), 0);
            if ((raw.ControlFlags & ControlFlags.DiscretionaryAclAutoInherited) != 0)
            {
                var copied = new FileSecurity(); copied.SetSecurityDescriptorBinaryForm(security.GetSecurityDescriptorBinaryForm(), AccessControlSections.Owner | AccessControlSections.Group | AccessControlSections.Access);
                File.SetAccessControl(path, copied);
            }
            // The legacy setter preserves legacy inherited ACEs without auto-inheritance conversion, but clears AI.
            // Use the matching API for each original descriptor, then verify every ACE and control flag.
            else if (!SetFileSecurity(path, 1 | 2 | 4, security.GetSecurityDescriptorBinaryForm())) throw new Win32Exception(Marshal.GetLastWin32Error());
            var actual = File.GetAccessControl(path, AccessControlSections.Owner | AccessControlSections.Group | AccessControlSections.Access);
            if (!SameFileSecurity(security, actual))
                throw new IOException("The temporary file could not retain the destination security. Before=" + security.GetSecurityDescriptorSddlForm(AccessControlSections.All) + "; Temporary=" + actual.GetSecurityDescriptorSddlForm(AccessControlSections.All));
        }

        internal static bool SameFileSecurity(FileSecurity before, FileSecurity after)
        {
            var a = new RawSecurityDescriptor(before.GetSecurityDescriptorBinaryForm(), 0);
            var b = new RawSecurityDescriptor(after.GetSecurityDescriptorBinaryForm(), 0);
            const ControlFlags significant = ControlFlags.DiscretionaryAclPresent | ControlFlags.DiscretionaryAclProtected |
                ControlFlags.DiscretionaryAclAutoInherited | ControlFlags.DiscretionaryAclAutoInheritRequired;
            if (a.Owner != b.Owner || a.Group != b.Group || (a.ControlFlags & significant) != (b.ControlFlags & significant)) return false;
            if (a.DiscretionaryAcl == null || b.DiscretionaryAcl == null) return a.DiscretionaryAcl == b.DiscretionaryAcl;
            // Compare every ordered ACE, including its inherited flag, and all DACL inheritance control flags.
            // Effective access today is insufficient: explicit duplicates would change future inheritance behavior.
            if (a.DiscretionaryAcl.Count != b.DiscretionaryAcl.Count) return false;
            for (int i = 0; i < a.DiscretionaryAcl.Count; i++)
            {
                var left = new byte[a.DiscretionaryAcl[i].BinaryLength]; var right = new byte[b.DiscretionaryAcl[i].BinaryLength];
                a.DiscretionaryAcl[i].GetBinaryForm(left, 0); b.DiscretionaryAcl[i].GetBinaryForm(right, 0);
                if (!left.SequenceEqual(right)) return false;
            }
            return true;
        }
    }
}

using System;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading;

namespace OpenSSHServerPNManager
{
    /// <summary>Validation, conflict detection, backup and atomic commit share one transaction for every server editor.</summary>
    internal static class ConfigurationTransaction
    {
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
                    try { acquired = mutex.WaitOne(15000); } catch (AbandonedMutexException) { acquired = true; }
                    if (!acquired) throw new ConfigException("Another configuration operation is still running. Try again when it finishes.");
                    return action();
                }
                finally { if (acquired) mutex.ReleaseMutex(); }
            }
        }

        public static string Save(SshdConfig candidate, bool overwrite)
        {
            // Keep the validation fixture beside its destination, under the same protected directory.
            Directory.CreateDirectory(Path.GetDirectoryName(candidate.Path));
            var tmp = candidate.Path + ".candidate-" + Guid.NewGuid().ToString("N");
            File.WriteAllText(tmp, candidate.Text, new UTF8Encoding(false));
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
                    ConfigurationRecovery.OpenForPath(candidate.Path).Prepare(backup, new UTF8Encoding(false).GetBytes(candidate.Text), dependencies);
                    dependencies.RequireUnchanged();
                    if (SshdConfig.FileHash(candidate.Path) != originalHash) throw new ConfigChangedException("The configuration changed before its atomic replacement. No changes were saved.");
                    AtomicWrite(candidate.Path, candidate.Text);
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
                // Establish security while the temporary file is empty. ReplaceFile preserves the destination DACL,
                // but takes the replacement file's owner and primary group, so those must be copied before commit.
                using (new FileStream(tmp, FileMode.CreateNew, FileAccess.Write, FileShare.None)) { }
                if (secureTemporary != null) secureTemporary(tmp);
                if (originalSecurity != null)
                {
                    var copiedSecurity = new FileSecurity();
                    copiedSecurity.SetSecurityDescriptorBinaryForm(originalSecurity.GetSecurityDescriptorBinaryForm(), sections);
                    File.SetAccessControl(tmp, copiedSecurity);
                    if (!SameFileSecurity(originalSecurity, File.GetAccessControl(tmp, sections)))
                        throw new IOException("The temporary file could not retain the destination owner, group and DACL.");
                }
                using (var stream = new FileStream(tmp, FileMode.Open, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
                {
                    stream.Write(bytes, 0, bytes.Length); stream.Flush(true);
                }
                if (File.Exists(path))
                {
                    if (originalSecurity == null || !SameFileSecurity(originalSecurity, File.GetAccessControl(path, sections)))
                        throw new IOException("The destination security changed before atomic replacement.");
                    if (replace != null) replace(tmp, path); else File.Replace(tmp, path, null);
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

        internal static bool SameFileSecurity(FileSecurity before, FileSecurity after)
        {
            var a = new RawSecurityDescriptor(before.GetSecurityDescriptorBinaryForm(), 0);
            var b = new RawSecurityDescriptor(after.GetSecurityDescriptorBinaryForm(), 0);
            const ControlFlags significant = ControlFlags.DiscretionaryAclPresent | ControlFlags.DiscretionaryAclProtected;
            if (a.Owner != b.Owner || a.Group != b.Group || (a.ControlFlags & significant) != (b.ControlFlags & significant)) return false;
            if (a.DiscretionaryAcl == null || b.DiscretionaryAcl == null) return a.DiscretionaryAcl == b.DiscretionaryAcl;
            // AUTO_INHERITED is bookkeeping that Windows may normalize; compare every ordered ACE, including its
            // inherited flag, plus inheritance protection. Do not discard or reorder access rules.
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

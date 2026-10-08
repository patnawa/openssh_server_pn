using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace OpenSSHServerPNManager
{
    internal interface IRecoveryHost
    {
        void Schedule(DateTime dueUtc);
        void Disarm();
        void RestoreFirewall(FirewallRule before);
        void Restart();
    }

    /// <summary>Durable commit-confirmed recovery. The journal is authoritative, including after a crash in a recovery step.</summary>
    internal sealed class ConfigurationRecoveryTransaction
    {
        private readonly string _dir, _live;
        private readonly IRecoveryHost _host;
        private readonly bool _trustedStorage;
        private string RecordPath { get { return Path.Combine(_dir, "pending.ini"); } }
        private string BeforePath { get { return Path.Combine(_dir, "previous.config"); } }

        public ConfigurationRecoveryTransaction(string directory, string livePath, IRecoveryHost host)
            : this(directory, livePath, host, false) { }

        public ConfigurationRecoveryTransaction(string directory, string livePath, IRecoveryHost host, bool trustedStorage)
        { _dir = directory; _live = livePath; _host = host; _trustedStorage = trustedStorage; }

        private void CheckStorage()
        {
            if (!_trustedStorage) return;
            ConfigurationRecovery.RequireTrustedPath(_dir);
            foreach (var path in new[] { RecordPath, BeforePath })
                if (File.Exists(path) || Directory.Exists(path)) ConfigurationRecovery.RequireTrustedPath(path);
        }

        private Dictionary<string, string> Read()
        {
            CheckStorage();
            var values = new Dictionary<string, string>(StringComparer.Ordinal);
            if (!File.Exists(RecordPath)) return values;
            foreach (var line in File.ReadAllLines(RecordPath))
            {
                int at = line.IndexOf('='); if (at <= 0) throw new ConfigException("The recovery journal is damaged; manual recovery is required.");
                values.Add(line.Substring(0, at), Encoding.UTF8.GetString(Convert.FromBase64String(line.Substring(at + 1))));
            }
            if (!values.ContainsKey("status") || !values.ContainsKey("id")) throw new ConfigException("The recovery journal is incomplete.");
            if (!values.ContainsKey("version") || values["version"] != "2" || !values.ContainsKey("live") || !string.Equals(values["live"], Path.GetFullPath(_live), StringComparison.OrdinalIgnoreCase))
                throw new ConfigException("The recovery journal version or configuration path does not match. Inspect the recovery record before making another change.");
            return values;
        }

        private void Write(IDictionary<string, string> values)
        {
            CheckStorage();
            WriteBytes(RecordPath, Encoding.UTF8.GetBytes(string.Join("\n", values.OrderBy(kv => kv.Key, StringComparer.Ordinal)
                .Select(kv => kv.Key + "=" + Convert.ToBase64String(Encoding.UTF8.GetBytes(kv.Value ?? "")))) + "\n"));
        }

        private void WriteBytes(string path, byte[] bytes)
        { ConfigurationTransaction.AtomicBytes(path, bytes, null, _trustedStorage ? (Action<string>)ConfigurationRecovery.ProtectFile : null); }

        public bool Pending { get { var r = Read(); return r.ContainsKey("status") && r["status"] == "pending"; } }

        /// <summary>A save-only change has a durable recovery seed, but no task is armed until a restart is requested.</summary>
        public void Prepare(string backupPath, byte[] appliedBytes, ConfigurationDependencies dependencies)
        {
            ConfigurationTransaction.Locked(_live, () =>
            {
                if (Pending) throw new ConfigException("Confirm or restore the pending configuration before saving another change.");
                var values = NewRecord(backupPath, ConfigurationDependencies.Hash(appliedBytes));
                (dependencies ?? ConfigurationDependencies.Capture(new string[0])).Store(values);
                Write(values); return true;
            });
        }

        private Dictionary<string, string> NewRecord(string backupPath, string appliedHash)
        {
            var values = new Dictionary<string, string> {
                { "version", "2" }, { "id", Guid.NewGuid().ToString("N") }, { "status", "prepared" }, { "phase", "applied" },
                { "live", Path.GetFullPath(_live) }, { "backup.path", backupPath == null ? "" : Path.GetFullPath(backupPath) },
                { "applied", appliedHash }, { "previous", backupPath == null ? "0" : "1" }, { "firewall", "0" }, { "error", "" }
            };
            if (backupPath != null)
            {
                CheckStorage();
                WriteBytes(BeforePath, File.ReadAllBytes(backupPath));
                values["before"] = SshdConfig.FileHash(BeforePath);
            }
            return values;
        }

        public string Arm(string backupPath, FirewallRule firewallBefore, DateTime dueUtc)
        {
            return ConfigurationTransaction.Locked(_live, () =>
            {
                if (Pending) throw new ConfigException("Confirm or restore the pending configuration before making another change.");
                var values = Read();
                if (values.ContainsKey("status") && values["status"] == "prepared")
                {
                    var expectedBackup = backupPath == null ? "" : Path.GetFullPath(backupPath);
                    if (!string.Equals(values["backup.path"], expectedBackup, StringComparison.OrdinalIgnoreCase)) throw new ConfigChangedException("A different configuration was saved before this restart was requested. Reload before restarting.");
                    if (SshdConfig.FileHash(_live) != values["applied"]) throw new ConfigChangedException("The saved configuration changed before recovery could be armed. No firewall or service changes were made.");
                }
                else
                {
                    values = NewRecord(backupPath, SshdConfig.FileHash(_live));
                    var dependencies = ConfigurationDependencies.Capture(File.Exists(_live) ? File.ReadAllLines(_live) : new string[0]);
                    if (backupPath != null) dependencies = ConfigurationDependencies.Combine(dependencies, ConfigurationDependencies.Capture(File.ReadAllLines(backupPath)));
                    dependencies.Store(values);
                }
                ConfigurationDependencies.Read(values).RequireUnchanged();
                values["deadline"] = dueUtc.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);
                values["firewall"] = firewallBefore == null ? "0" : "1";
                if (firewallBefore != null)
                    firewallBefore.Store(values, "fw.");
                Write(values);
                try
                {
                    // The task must exist before pending becomes authoritative and before the caller changes the server.
                    _host.Schedule(dueUtc);
                    values["status"] = "pending"; Write(values);
                }
                catch (Exception ex) { values["status"] = "prepared"; values["error"] = ex.Message; Write(values); throw; }
                return values["id"];
            });
        }

        public void Confirm(string id)
        { Confirm(id, DateTime.UtcNow); }

        internal void Confirm(string id, DateTime nowUtc)
        {
            ConfigurationTransaction.Locked(_live, () =>
            {
                var r = Read();
                if (!r.ContainsKey("status") || r["status"] != "pending" || r["id"] != id)
                    throw new ConfigException("This configuration is no longer awaiting confirmation. Reload the server state.");
                if (SshdConfig.FileHash(_live) != r["applied"]) throw new ConfigChangedException("The configuration changed during confirmation; it was not committed.");
                ConfigurationDependencies.Read(r).RequireUnchanged();
                if (nowUtc.ToUniversalTime() >= DateTime.ParseExact(r["deadline"], "O", CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind))
                    throw new ConfigException("The confirmation deadline has passed. Recovery remains armed; reload the server state.");
                r["status"] = "confirmed"; Write(r); // journal first: a task that runs before deletion now does nothing
                DisarmInactive();
                return true;
            });
        }

        /// <summary>
        /// Reserve the cross-process mutex on a worker while an asynchronous final firewall update runs on its caller's
        /// context. A timely Keep cannot race the recovery task; a crashed process releases the abandoned mutex.
        /// The callback must not start another configuration transaction on this same file.
        /// </summary>
        public async Task ConfirmAsync(string id, Func<Task> keep)
        {
            var ready = new TaskCompletionSource<bool>();
            var finished = new TaskCompletionSource<bool>();
            var worker = Task.Factory.StartNew(() =>
            {
                try
                {
                    ConfigurationTransaction.Locked(_live, () =>
                    {
                        var r = Read();
                        if (!r.ContainsKey("status") || r["status"] != "pending" || r["id"] != id) throw new ConfigException("This configuration is no longer awaiting confirmation.");
                        if (DateTime.UtcNow >= DateTime.ParseExact(r["deadline"], "O", CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind)) throw new ConfigException("The confirmation deadline has passed. Recovery remains armed.");
                        if (SshdConfig.FileHash(_live) != r["applied"]) throw new ConfigChangedException("The configuration changed before confirmation.");
                        ConfigurationDependencies.Read(r).RequireUnchanged();
                        ready.TrySetResult(true);
                        finished.Task.GetAwaiter().GetResult();
                        if (SshdConfig.FileHash(_live) != r["applied"]) throw new ConfigChangedException("The configuration changed while confirmation was being finalized.");
                        ConfigurationDependencies.Read(r).RequireUnchanged();
                        r["status"] = "confirmed"; Write(r); DisarmInactive(); return true;
                    });
                }
                catch (Exception ex) { ready.TrySetException(ex); throw; }
            }, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
            bool entered = false;
            try { await ready.Task; entered = true; if (keep != null) await keep(); finished.TrySetResult(true); }
            catch (Exception ex) { if (entered) finished.TrySetException(ex); else finished.TrySetCanceled(); }
            await worker;
        }

        private void DisarmInactive()
        {
            try { _host.Disarm(); }
            catch (Exception ex) { Log.Error("The inactive recovery task could not be removed; its journal prevents further changes", ex, false); }
        }

        public void SetDeadline(string id, DateTime dueUtc)
        {
            ConfigurationTransaction.Locked(_live, () =>
            {
                var r = Read();
                if (!r.ContainsKey("status") || r["status"] != "pending" || r["id"] != id) throw new ConfigException("The pending settings were already restored.");
                if (DateTime.UtcNow >= DateTime.ParseExact(r["deadline"], "O", CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind)) throw new ConfigException("The existing recovery deadline has passed and cannot be extended.");
                // If registration fails, the old journal deadline and task stay authoritative.
                _host.Schedule(dueUtc);
                r["deadline"] = dueUtc.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture); Write(r);
                return true;
            });
        }

        public bool Recover(DateTime nowUtc, bool force = false)
        {
            return ConfigurationTransaction.Locked(_live, () =>
            {
                var r = Read();
                if (!r.ContainsKey("status") || r["status"] != "pending") return false;
                if (!force && nowUtc.ToUniversalTime() < DateTime.ParseExact(r["deadline"], "O", CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind)) return false;
                bool existed = r["previous"] == "1";
                string beforeHash = existed ? r["before"] : "";
                string current = SshdConfig.FileHash(_live);
                if (current != r["applied"] && current != beforeHash)
                {
                    r["error"] = "The configuration changed outside the pending transaction. Recovery will not overwrite that change.";
                    Write(r); throw new ConfigChangedException(r["error"]);
                }
                try
                {
                    ConfigurationDependencies.Read(r).RequireUnchanged();
                    if (current != beforeHash)
                    {
                        if (existed)
                        {
                            if (SshdConfig.FileHash(BeforePath) != beforeHash) throw new ConfigException("The recovery backup failed its integrity check.");
                            ConfigurationTransaction.AtomicBytes(_live, File.ReadAllBytes(BeforePath));
                        }
                        else File.Delete(_live);
                    }
                    if (r["phase"] == "applied") { r["phase"] = "configuration-restored"; Write(r); }
                    if (r["phase"] == "configuration-restored")
                    {
                        if (r["firewall"] == "1") _host.RestoreFirewall(FirewallRule.Read(r, "fw."));
                        r["phase"] = "firewall-restored"; Write(r);
                    }
                    _host.Restart();
                    r["status"] = "restored"; r["error"] = ""; Write(r);
                    DisarmInactive();
                    return true;
                }
                catch (Exception ex) { r["error"] = ex.Message; Write(r); throw; }
            });
        }
    }

    internal static class ConfigurationRecovery
    {
        internal const string TaskName = "OpenSSH Server PN Manager\\Configuration recovery";
        private static string DirectoryFor(string live)
        {
            var directory = Path.Combine(Path.GetDirectoryName(live), "manager", "recovery");
            return Path.GetFileName(live).Equals("sshd_config", StringComparison.OrdinalIgnoreCase) ? directory :
                Path.Combine(directory, "config-" + ConfigurationDependencies.Hash(Encoding.UTF8.GetBytes(Path.GetFullPath(live).ToUpperInvariant())).Substring(0, 20));
        }

        public static void RequireNoPending(string live)
        {
            var dir = DirectoryFor(live);
            if (Directory.Exists(dir) && new ConfigurationRecoveryTransaction(dir, live, null).Pending)
                throw new ConfigException("Confirm or restore the pending server configuration before saving another change.");
        }

        public static ConfigurationRecoveryTransaction Open()
        {
            var error = ServerState.ServiceDefinitionError();
            if (error != null) throw new ConfigException(error);
            return OpenForPath(Ssh.ConfigPath);
        }

        internal static ConfigurationRecoveryTransaction OpenForPath(string live)
        {
            var dir = DirectoryFor(live);
            if (Program.Unattended && Ssh.ConfigDirOverride != null && Path.GetFullPath(live).StartsWith(Path.GetFullPath(Ssh.ConfigDirOverride).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            {
                Directory.CreateDirectory(dir);
                return new ConfigurationRecoveryTransaction(dir, live, new FixtureRecoveryHost());
            }
            var manager = Path.Combine(Path.GetDirectoryName(live), "manager");
            RequireTrustedAncestors(Path.GetDirectoryName(live));
            foreach (var path in new[] { manager, Path.Combine(manager, "recovery"), dir }.Distinct(StringComparer.OrdinalIgnoreCase))
            {
                if (!Directory.Exists(path)) Acl.CreatePrivateFolder(path);
                RequireTrustedPath(path);
            }
            return new ConfigurationRecoveryTransaction(dir, live, new WindowsRecoveryHost(dir), true);
        }

        private static readonly SecurityIdentifier Administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        private static readonly SecurityIdentifier LocalSystem = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        private static readonly SecurityIdentifier TrustedInstaller = new SecurityIdentifier("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");

        internal static bool TrustedSecurity(FileSystemSecurity security, bool privateObject)
        {
            var owner = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
            if (owner != Administrators && owner != LocalSystem && (privateObject || owner != TrustedInstaller)) return false;
            if (privateObject && !security.AreAccessRulesProtected) return false;
            const FileSystemRights destructive = FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership;
            foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            {
                if (rule.AccessControlType != AccessControlType.Allow || (rule.PropagationFlags & PropagationFlags.InheritOnly) != 0) continue;
                var sid = (SecurityIdentifier)rule.IdentityReference;
                if (sid == Administrators || sid == LocalSystem || (!privateObject && sid == TrustedInstaller)) continue;
                if (privateObject || (rule.FileSystemRights & destructive) != 0 || (((int)rule.FileSystemRights & 0x10000000) != 0)) return false;
            }
            return true;
        }

        internal static void RequireTrustedPath(string path)
        {
            if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0 || !TrustedSecurity(File.GetAccessControl(path), true))
                throw new ConfigException("Recovery storage must be owned by and accessible only to SYSTEM or Administrators, with no reparse points: " + path);
        }

        private static void RequireTrustedAncestors(string path)
        {
            for (var directory = new DirectoryInfo(path); directory != null; directory = directory.Parent)
                if ((directory.Attributes & FileAttributes.ReparsePoint) != 0 || !TrustedSecurity(directory.GetAccessControl(), false))
                    throw new ConfigException("A recovery storage ancestor can be replaced or controlled by an untrusted account: " + directory.FullName);
        }

        internal static void ProtectFile(string path)
        {
            var security = new FileSecurity();
            security.SetAccessRuleProtection(true, false);
            security.SetOwner(Administrators);
            security.AddAccessRule(new FileSystemAccessRule(Administrators, FileSystemRights.FullControl, AccessControlType.Allow));
            security.AddAccessRule(new FileSystemAccessRule(LocalSystem, FileSystemRights.FullControl, AccessControlType.Allow));
            File.SetAccessControl(path, security);
        }

        private sealed class FixtureRecoveryHost : IRecoveryHost
        {
            public void Schedule(DateTime dueUtc) { throw new ConfigException("A test configuration cannot register a live recovery task."); }
            public void Disarm() { }
            public void RestoreFirewall(FirewallRule before) { throw new ConfigException("A test configuration cannot change the live firewall."); }
            public void Restart() { throw new ConfigException("A test configuration cannot restart the live service."); }
        }

        public static int Run()
        {
            try { bool restored = Open().Recover(DateTime.UtcNow); if (restored) Log.Info("Unconfirmed server settings restored by the recovery task."); return 0; }
            catch (Exception ex) { Log.Error("Configuration recovery failed; the task will retry", ex, false); return 1; }
        }

        internal static string TaskXml(string exe, DateTime dueUtc)
        {
            return "<?xml version=\"1.0\" encoding=\"UTF-16\"?><Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">" +
                "<RegistrationInfo><Description>Restores SSH settings unless the administrator confirms the change.</Description></RegistrationInfo>" +
                "<Triggers><TimeTrigger><StartBoundary>" + dueUtc.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture) +
                "</StartBoundary><Enabled>true</Enabled><Repetition><Interval>PT1M</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition></TimeTrigger>" +
                "<BootTrigger><Enabled>true</Enabled><Delay>PT10S</Delay></BootTrigger></Triggers>" +
                "<Principals><Principal id=\"System\"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>" +
                "<Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>" +
                "<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><StartWhenAvailable>true</StartWhenAvailable><AllowStartOnDemand>true</AllowStartOnDemand>" +
                "<Enabled>true</Enabled><ExecutionTimeLimit>PT5M</ExecutionTimeLimit></Settings><Actions Context=\"System\"><Exec><Command>" + SecurityElement.Escape(exe) +
                "</Command><Arguments>--recover-configuration</Arguments></Exec></Actions></Task>";
        }

        private sealed class WindowsRecoveryHost : IRecoveryHost
        {
            private readonly string _dir;
            public WindowsRecoveryHost(string dir) { _dir = dir; }
            public void Schedule(DateTime dueUtc)
            {
                var source = Assembly.GetExecutingAssembly().Location;
                var sourceBytes = File.ReadAllBytes(source);
                var configBytes = File.Exists(source + ".config") ? File.ReadAllBytes(source + ".config") : new byte[0];
                var digest = ConfigurationDependencies.Hash(sourceBytes.Concat(configBytes).ToArray());
                var runnerRoot = Path.Combine(_dir, "runner");
                if (!Directory.Exists(runnerRoot)) Acl.CreatePrivateFolder(runnerRoot);
                RequireTrustedPath(runnerRoot);
                var runner = Path.Combine(runnerRoot, digest);
                if (!Directory.Exists(runner)) Acl.CreatePrivateFolder(runner);
                RequireTrustedPath(runner);
                var exe = Path.Combine(runner, "OpenSSHServerPNManager.exe");
                EnsureRunnerFile(exe, sourceBytes, true);
                if (configBytes.Length > 0) EnsureRunnerFile(exe + ".config", configBytes, true);
                else if (File.Exists(exe + ".config")) throw new ConfigException("An unexpected recovery runner configuration file exists.");
                SystemTasks.RegisterXml(TaskName, TaskXml(exe, dueUtc));
            }
            public void Disarm() { if (!SystemTasks.Delete(TaskName)) Log.Info("The inactive recovery task could not be removed; its journal prevents further changes."); }
            public void RestoreFirewall(FirewallRule before) { Firewall.Restore(before); }
            public void Restart()
            {
                var error = ServerState.ServiceDefinitionError();
                if (error != null) throw new ConfigException(error);
                Services.Restart("sshd");
            }
        }

        internal static void EnsureRunnerFile(string path, byte[] bytes, bool trustedStorage = false)
        {
            // Immutable versioned runners can be reused even while another invocation is executing them.
            if (File.Exists(path))
            {
                if (trustedStorage) RequireTrustedPath(path);
                if (SshdConfig.FileHash(path) != ConfigurationDependencies.Hash(bytes)) throw new ConfigException("The recovery runner failed its integrity check: " + path);
                return;
            }
            ConfigurationTransaction.AtomicBytes(path, bytes, null, trustedStorage ? (Action<string>)ProtectFile : null);
        }
    }
}

using System;
using System.Collections.Generic;
using System.Diagnostics;
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

    /// <summary>
    /// Optional for a recovery host: identifies the running sshd process. Save-only changes keep the file that process
    /// loaded as their rollback target until it restarts; without an identity every save starts a new record.
    /// </summary>
    internal interface IRecoveryServerIdentity
    {
        /// <summary>PID and start time of the running sshd, or "" when it is not running or cannot be identified.</summary>
        string ServerIdentity();
        /// <summary>True when the file was written after the running sshd started, so that sshd does not run it.</summary>
        bool ChangedSinceStart(string path);
    }

    /// <summary>A pending (or unreadable) recovery record, as a refusal and the resolution dialog describe it.</summary>
    internal sealed class RecoveryRecordInfo
    {
        public string Id = "", Phase = "", Error = "", JournalPath = "";
        public DateTime DeadlineUtc = DateTime.MinValue;
        public bool Damaged;

        /// <summary>
        /// Nothing completes it by itself: the journal cannot be read, or the deadline passed and the recovery task
        /// recorded an error or has not run for two minutes. Within its deadline a record belongs to a running change,
        /// perhaps in another window, and is never offered for resolution.
        /// </summary>
        public bool Stuck(DateTime nowUtc)
        {
            return Damaged || (nowUtc.ToUniversalTime() >= DeadlineUtc && (Error.Length > 0 || nowUtc.ToUniversalTime() >= DeadlineUtc.AddMinutes(2)));
        }
    }

    /// <summary>
    /// A save or restart refused while an earlier change awaits confirmation or recovery. Not a ConfigChangedException:
    /// "save anyway" cannot get past it.
    /// </summary>
    internal sealed class PendingRecoveryException : ConfigException
    {
        public readonly RecoveryRecordInfo Record;
        public PendingRecoveryException(RecoveryRecordInfo record) : base(Describe(record, DateTime.UtcNow)) { Record = record; }

        internal static string Describe(RecoveryRecordInfo r, DateTime nowUtc)
        {
            if (r.Damaged)
                return "The recovery record of an earlier configuration change cannot be read, so no other change can be saved until it is resolved: " + r.Error +
                       "\n\nRecovery record: " + r.JournalPath + "\nThe manager offers to set it aside when it starts.";
            if (r.Stuck(nowUtc))
                return "An earlier configuration change was not kept, and its previous settings could not be restored automatically. No other change can be saved until this is resolved." +
                       "\n\nRecorded error: " + (r.Error.Length > 0 ? r.Error : "none; the recovery task has not run") + "\nRecovery record: " + r.JournalPath +
                       "\nThe manager offers to restore the previous settings, or to keep the files as they are, when it starts.";
            return "Another configuration change is waiting to be kept or restored (until " + r.DeadlineUtc.ToLocalTime().ToString("HH:mm:ss", CultureInfo.InvariantCulture) +
                   "), perhaps in another manager window. Nothing was changed; try again after that." + (r.Error.Length > 0 ? "\n\nLast recovery error: " + r.Error : "");
        }
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
                try { values.Add(line.Substring(0, at), Encoding.UTF8.GetString(Convert.FromBase64String(line.Substring(at + 1)))); }
                catch (FormatException) { throw new ConfigException("The recovery journal is damaged; manual recovery is required."); }
                catch (ArgumentException) { throw new ConfigException("The recovery journal is damaged; manual recovery is required."); }
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

        /// <summary>The record, read without changing it (the restart decision and the startup check).</summary>
        internal Dictionary<string, string> ReadRecord() { return Read(); }

        /// <summary>The pending record, or one that cannot be read (Damaged), or null when nothing is pending.</summary>
        internal RecoveryRecordInfo PendingRecord()
        {
            Dictionary<string, string> r;
            try { r = Read(); }
            catch (ConfigException ex) { return new RecoveryRecordInfo { Damaged = true, Error = ex.Message, JournalPath = RecordPath }; }
            return r.ContainsKey("status") && r["status"] == "pending" ? Info(r) : null;
        }

        private RecoveryRecordInfo Info(Dictionary<string, string> r)
        {
            string value; DateTime deadline;
            var info = new RecoveryRecordInfo { Id = r["id"], JournalPath = RecordPath };
            if (r.TryGetValue("phase", out value)) info.Phase = value;
            if (r.TryGetValue("error", out value)) info.Error = value;
            if (r.TryGetValue("deadline", out value) && DateTime.TryParseExact(value, "O", CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out deadline)) info.DeadlineUtc = deadline.ToUniversalTime();
            return info;
        }

        private void RequireNotPending(Dictionary<string, string> r)
        {
            if (r.ContainsKey("status") && r["status"] == "pending") throw new PendingRecoveryException(Info(r));
        }

        private string ServerIdentity(bool requireLiveLoaded)
        {
            var identity = _host as IRecoveryServerIdentity;
            if (identity == null) return "";
            try { return requireLiveLoaded && identity.ChangedSinceStart(_live) ? "" : identity.ServerIdentity() ?? ""; }
            catch (Exception) { return ""; }
        }

        /// <summary>A save-only change has a durable recovery seed, but no task is armed until a restart is requested.</summary>
        public void Prepare(string backupPath, byte[] appliedBytes, ConfigurationDependencies dependencies)
        {
            ConfigurationTransaction.Locked(_live, () =>
            {
                var existing = Read();
                RequireNotPending(existing);
                var appliedHash = ConfigurationDependencies.Hash(appliedBytes);
                dependencies = dependencies ?? ConfigurationDependencies.Capture(new string[0]);
                ConfigurationDependencies kept;
                var values = ContinuedRecord(existing, backupPath, appliedHash, out kept);
                if (values != null) ConfigurationDependencies.Union(kept, dependencies).Store(values);
                else
                {
                    values = NewRecord(backupPath, appliedHash);
                    // Only a file the running sshd loaded can be its rollback target in a later save.
                    values["server"] = ServerIdentity(true);
                    dependencies.Store(values);
                }
                Write(values); return true;
            });
        }

        /// <summary>
        /// Another save-only change while the same sshd process runs: the record keeps the file that process loaded, not
        /// the one saved in between, which sshd never ran. Null starts a new record: sshd restarted or stopped, the file
        /// changed outside the chain, or an Include changed so that the older file cannot come back as it ran.
        /// </summary>
        private Dictionary<string, string> ContinuedRecord(Dictionary<string, string> r, string backupPath, string appliedHash, out ConfigurationDependencies kept)
        {
            kept = null;
            string server, applied, previous, before = null;
            if (!r.ContainsKey("status") || r["status"] != "prepared" || !r.TryGetValue("server", out server) || server.Length == 0 || server != ServerIdentity(false)) return null;
            if (!r.TryGetValue("applied", out applied) || applied != SshdConfig.FileHash(_live) || !r.TryGetValue("previous", out previous)) return null;
            if (previous == "1" && (!r.TryGetValue("before", out before) || SshdConfig.FileHash(BeforePath) != before)) return null;
            try { kept = ConfigurationDependencies.Read(r); kept.RequireUnchanged(); }
            catch (Exception) { kept = null; return null; }
            var values = RecordValues(backupPath, appliedHash, previous == "1");
            if (before != null) values["before"] = before;
            values["server"] = server;
            return values;
        }

        private Dictionary<string, string> NewRecord(string backupPath, string appliedHash)
        {
            var values = RecordValues(backupPath, appliedHash, backupPath != null);
            if (backupPath != null)
            {
                CheckStorage();
                WriteBytes(BeforePath, File.ReadAllBytes(backupPath));
                values["before"] = SshdConfig.FileHash(BeforePath);
            }
            return values;
        }

        private Dictionary<string, string> RecordValues(string backupPath, string appliedHash, bool previous)
        {
            return new Dictionary<string, string> {
                { "version", "2" }, { "id", Guid.NewGuid().ToString("N") }, { "status", "prepared" }, { "phase", "applied" },
                { "live", Path.GetFullPath(_live) }, { "backup.path", backupPath == null ? "" : Path.GetFullPath(backupPath) },
                { "applied", appliedHash }, { "previous", previous ? "1" : "0" }, { "firewall", "0" }, { "error", "" }
            };
        }

        public string Arm(string backupPath, FirewallRule firewallBefore, DateTime dueUtc)
        { return ArmRecord(backupPath, firewallBefore, dueUtc, true); }

        /// <summary>
        /// Arms recovery for a restart that applies a file saved earlier (the Dashboard Restart), with a new record for
        /// this backup: an existing save-only record may describe an older chain.
        /// </summary>
        public string ArmFresh(string backupPath, FirewallRule firewallBefore, DateTime dueUtc)
        { return ArmRecord(backupPath, firewallBefore, dueUtc, false); }

        private string ArmRecord(string backupPath, FirewallRule firewallBefore, DateTime dueUtc, bool usePrepared)
        {
            return ConfigurationTransaction.Locked(_live, () =>
            {
                var values = Read();
                RequireNotPending(values);
                if (usePrepared && values.ContainsKey("status") && values["status"] == "prepared")
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

        /// <summary>
        /// An administrator's decision for a recovery that cannot complete: keep the files, firewall and service as they
        /// are now. Nothing is restored; the journal is written before the task is removed, as in Confirm.
        /// </summary>
        public void Abandon(string id, string reason)
        {
            ConfigurationTransaction.Locked(_live, () =>
            {
                var r = Read();
                if (!r.ContainsKey("status") || r["status"] != "pending" || r["id"] != id) throw new ConfigException("This recovery is no longer pending. Reload the server state.");
                r["status"] = "abandoned"; r["error"] = reason ?? ""; Write(r);
                DisarmInactive();
                return true;
            });
        }

        /// <summary>Sets an unreadable journal aside, beside it for inspection, and removes the task. A readable one is refused.</summary>
        public string SetAsideDamaged()
        {
            return ConfigurationTransaction.Locked(_live, () =>
            {
                CheckStorage();
                bool readable = true;
                try { Read(); } catch (ConfigException) { readable = false; }
                if (readable) throw new ConfigException("The recovery record can be read; restore or keep the settings instead.");
                var aside = RecordPath + ".damaged-" + DateTime.Now.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture);
                File.Move(RecordPath, aside);
                DisarmInactive();
                return aside;
            });
        }

        /// <summary>
        /// Records a failed run of the recovery task. True only when this error text was not reported before, so that the
        /// logs get one entry per problem instead of one every minute.
        /// </summary>
        internal bool ReportFailure(string error)
        {
            return ConfigurationTransaction.Locked(_live, () =>
            {
                var r = Read();
                if (!r.ContainsKey("status")) return true;
                string reported;
                if (r.TryGetValue("error.reported", out reported) && reported == error) return false;
                r["error.reported"] = error;
                // An error found before Recover ran (the service definition) is shown by the manager too.
                if (r["status"] == "pending") r["error"] = error;
                Write(r);
                return true;
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
            var info = PendingInfo(live);
            if (info != null) throw new PendingRecoveryException(info);
        }

        /// <summary>The pending record of a configuration, read only and without creating folders, or null when none is pending.</summary>
        internal static RecoveryRecordInfo PendingInfo(string live)
        {
            var dir = DirectoryFor(live);
            return Directory.Exists(dir) ? new ConfigurationRecoveryTransaction(dir, live, null).PendingRecord() : null;
        }

        /// <summary>How a plain restart applies the saved file: the backup recovery is armed with.</summary>
        internal sealed class RestartRollback { public string Backup; public bool FromRecord; }

        /// <summary>
        /// A plain restart applies a file sshd has not run when a save-only record of this very sshd process exists (its
        /// rollback target is the file that process loaded) or the file changed after sshd started (then the newest backup
        /// is the best known previous file). Null: sshd runs the saved file, so a plain restart changes nothing.
        /// </summary>
        internal static RestartRollback RestartRollbackFor(IDictionary<string, string> record, string liveHash, string identity, bool changedSinceStart, string newestBackup)
        {
            string value, backup;
            if (record != null && record.TryGetValue("status", out value) && value == "prepared" && record.TryGetValue("applied", out value) && value == liveHash &&
                record.TryGetValue("server", out value) && value.Length > 0 && value == identity && record.TryGetValue("backup.path", out backup) && backup.Length > 0)
                return new RestartRollback { Backup = backup, FromRecord = true };
            if (changedSinceStart && newestBackup != null) return new RestartRollback { Backup = newestBackup };
            return null;
        }

        internal static RestartRollback RestartRollbackFor(string live)
        {
            var dir = DirectoryFor(live);
            IDictionary<string, string> record = null;
            if (Directory.Exists(dir)) { try { record = new ConfigurationRecoveryTransaction(dir, live, null).ReadRecord(); } catch (ConfigException) { } }
            return RestartRollbackFor(record, SshdConfig.FileHash(live), RunningServerIdentity(), Services.ChangedSinceStart(Services.Status("sshd"), live), SshdConfig.ListBackups(live).FirstOrDefault());
        }

        /// <summary>PID and start time of the running sshd: a restart changes it. "" when sshd does not run.</summary>
        internal static string RunningServerIdentity()
        {
            try
            {
                int pid = Services.PidOf("sshd");
                if (pid <= 0) return "";
                using (var p = Process.GetProcessById(pid))
                    return pid.ToString(CultureInfo.InvariantCulture) + "@" + p.StartTime.ToUniversalTime().Ticks.ToString(CultureInfo.InvariantCulture);
            }
            catch (Exception) { return ""; }
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
            ConfigurationRecoveryTransaction txn = null;
            try
            {
                txn = OpenForPath(Ssh.ConfigPath);
                var error = ServerState.ServiceDefinitionError();
                if (error != null) throw new ConfigException(error);
                if (txn.Recover(DateTime.UtcNow))
                {
                    Log.Info("Unconfirmed server settings restored by the recovery task.");
                    Agent.Note("Configuration recovery: unconfirmed server settings were restored and sshd restarted.");
                }
                return 0;
            }
            catch (Exception ex)
            {
                // Logged once per distinct error: the task runs every minute until it succeeds or an administrator resolves it.
                bool first = true;
                try { if (txn != null) first = txn.ReportFailure(ex.Message); } catch (Exception) { }
                if (first)
                {
                    Log.Error("Configuration recovery failed; the task will retry", ex, false);
                    Agent.Note("Configuration recovery failed; the task retries every minute and logs again only when the error changes. Open the manager to restore the previous settings or keep the files as they are. " + ex.Message);
                }
                return 1;
            }
        }

        internal static string TaskXml(string exe, DateTime dueUtc)
        {
            // Rounded up to a whole second: a run started before the stored deadline finds nothing due and waits a minute.
            var due = dueUtc.ToUniversalTime();
            var start = new DateTime(due.Ticks - due.Ticks % TimeSpan.TicksPerSecond, DateTimeKind.Utc);
            if (start < due) start = start.AddSeconds(1);
            return "<?xml version=\"1.0\" encoding=\"UTF-16\"?><Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">" +
                "<RegistrationInfo><Description>Restores SSH settings unless the administrator confirms the change.</Description></RegistrationInfo>" +
                "<Triggers><TimeTrigger><StartBoundary>" + start.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture) +
                "</StartBoundary><Enabled>true</Enabled><Repetition><Interval>PT1M</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition></TimeTrigger>" +
                "<BootTrigger><Enabled>true</Enabled><Delay>PT10S</Delay></BootTrigger></Triggers>" +
                "<Principals><Principal id=\"System\"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>" +
                "<Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>" +
                "<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><StartWhenAvailable>true</StartWhenAvailable><AllowStartOnDemand>true</AllowStartOnDemand>" +
                "<Enabled>true</Enabled><ExecutionTimeLimit>PT5M</ExecutionTimeLimit></Settings><Actions Context=\"System\"><Exec><Command>" + SecurityElement.Escape(exe) +
                "</Command><Arguments>--recover-configuration</Arguments></Exec></Actions></Task>";
        }

        private sealed class WindowsRecoveryHost : IRecoveryHost, IRecoveryServerIdentity
        {
            private readonly string _dir;
            public WindowsRecoveryHost(string dir) { _dir = dir; }
            public string ServerIdentity() { return RunningServerIdentity(); }
            public bool ChangedSinceStart(string path) { return Services.ChangedSinceStart(Services.Status("sshd"), path); }
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

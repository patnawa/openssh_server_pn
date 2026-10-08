using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace OpenSSHServerPNManager
{
    /// <summary>Regressions for configuration transactions and recovery (October 2026 follow-up review).</summary>
    internal static class FollowUpConfigTests
    {
        private const BindingFlags Private = BindingFlags.Instance | BindingFlags.NonPublic;

        /// <summary>A recovery host whose sshd identity the test sets: a restart is a new identity.</summary>
        private sealed class Host : IRecoveryHost, IRecoveryServerIdentity
        {
            internal int Restarts, Schedules, Disarms; internal FirewallRule Firewall; internal bool FailRestart, Changed;
            internal string Identity = ""; internal Action OnDisarm;
            public void Schedule(DateTime dueUtc) { Schedules++; }
            public void Disarm() { Disarms++; if (OnDisarm != null) OnDisarm(); }
            public void RestoreFirewall(FirewallRule before) { Firewall = before; }
            public void Restart() { Restarts++; if (FailRestart) throw new IOException("restart interrupted"); }
            public string ServerIdentity() { return Identity; }
            public bool ChangedSinceStart(string path) { return Changed; }
        }

        /// <summary>sshd_config with its recovery folder where ConfigurationRecovery looks for it (manager\recovery beside it).</summary>
        private sealed class Fixture
        {
            internal string Root, Dir, Live, Backup;
            internal byte[] Before = Encoding.UTF8.GetBytes("Port 22\n");
            internal DateTime Due = DateTime.UtcNow.AddMinutes(5);
            internal Fixture(string tmpDir)
            {
                Root = Path.Combine(tmpDir, "config-" + Guid.NewGuid().ToString("N")); Dir = Path.Combine(Root, "manager", "recovery"); Directory.CreateDirectory(Dir);
                Live = Path.Combine(Root, "sshd_config"); Backup = Live + ".bak.20261008-120000"; File.WriteAllBytes(Backup, Before); File.WriteAllText(Live, "new settings");
            }
            internal ConfigurationRecoveryTransaction Open(Host host) { return new ConfigurationRecoveryTransaction(Dir, Live, host); }
        }

        /// <summary>A save as ConfigurationTransaction.Save makes it: backup, record, then the new bytes. Returns the backup.</summary>
        private static string Save(Fixture f, ConfigurationRecoveryTransaction txn, string text, ConfigurationDependencies dependencies = null)
        {
            var backup = SshdConfig.NewBackupPath(f.Live, DateTime.Now); File.Copy(f.Live, backup);
            var bytes = Encoding.UTF8.GetBytes(text);
            txn.Prepare(backup, bytes, dependencies ?? ConfigurationDependencies.Capture(new string[0]));
            File.WriteAllBytes(f.Live, bytes);
            return backup;
        }

        /// <summary>The server tools replaced by a compiled sshd.exe that exits with sshdExit, on a scratch configuration folder.</summary>
        private static void WithFakeServer(string tmpDir, int sshdExit, Action<string> body)
        {
            var dir = Path.Combine(tmpDir, "server-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(dir);
            using (var compiler = new Microsoft.CSharp.CSharpCodeProvider())
            {
                var options = new System.CodeDom.Compiler.CompilerParameters { GenerateExecutable = true, OutputAssembly = Path.Combine(dir, "sshd.exe") };
                var result = compiler.CompileAssemblyFromSource(options, "class Fixture { static int Main() { return " + sshdExit + "; } }");
                if (result.Errors.HasErrors) throw new Exception("Could not compile the sshd fixture");
            }
            var install = typeof(Ssh).GetField("_installDir", BindingFlags.Static | BindingFlags.NonPublic);
            var oldInstall = install.GetValue(null); var oldConfig = Ssh.ConfigDirOverride; bool oldUnattended = Program.Unattended;
            try { install.SetValue(null, dir); Ssh.ConfigDirOverride = dir; Program.Unattended = true; body(dir); }
            finally { install.SetValue(null, oldInstall); Ssh.ConfigDirOverride = oldConfig; Program.Unattended = oldUnattended; }
        }

        /// <summary>Runs body while another thread holds the configuration lock of live, with lock waits shortened to 100 ms.</summary>
        private static void WhileLocked(string live, Action body)
        {
            var held = new System.Threading.ManualResetEventSlim(); var release = new System.Threading.ManualResetEventSlim();
            var holder = Task.Factory.StartNew(() => ConfigurationTransaction.Locked(live, () => { held.Set(); release.Wait(); return true; }), TaskCreationOptions.LongRunning);
            var wait = ConfigurationTransaction.LockWaitMilliseconds;
            try
            {
                if (!held.Wait(20000)) throw new Exception("The lock holder did not start");
                ConfigurationTransaction.LockWaitMilliseconds = 100;
                body();
            }
            finally { ConfigurationTransaction.LockWaitMilliseconds = wait; release.Set(); holder.Wait(20000); }
        }

        internal static void Run(Action<string, Func<string>> test, string tmpDir)
        {
            test("recovery task: the start time is rounded up, so the first run at the deadline restores", () =>
            {
                Func<DateTime, DateTime> start = due =>
                {
                    var xml = ConfigurationRecovery.TaskXml(@"C:\Program Files\OpenSSH\manager.exe", due);
                    int at = xml.IndexOf("<StartBoundary>", StringComparison.Ordinal) + "<StartBoundary>".Length;
                    return DateTime.Parse(xml.Substring(at, xml.IndexOf("</StartBoundary>", StringComparison.Ordinal) - at), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind).ToUniversalTime();
                };
                var fractional = new DateTime(2026, 10, 8, 12, 5, 0, 734, DateTimeKind.Utc);
                if (start(fractional) != new DateTime(2026, 10, 8, 12, 5, 1, DateTimeKind.Utc)) throw new Exception("A deadline of 12:05:00.734 starts the task at " + start(fractional).ToString("O"));
                var whole = new DateTime(2026, 10, 8, 12, 5, 0, DateTimeKind.Utc);
                if (start(whole) != whole) throw new Exception("A whole-second deadline moved to " + start(whole).ToString("O"));
                var f = new Fixture(tmpDir); var host = new Host(); var txn = f.Open(host);
                var due = DateTime.UtcNow.AddMinutes(5); due = due.AddTicks(TimeSpan.TicksPerSecond / 2 - due.Ticks % TimeSpan.TicksPerSecond + 1);
                txn.Arm(f.Backup, null, due);
                if (!txn.Recover(start(due))) throw new Exception("The first scheduled run found nothing due and waits another minute");
                return null;
            });
            test("recovery: save-only changes keep the file the running sshd loaded, and only while it runs", () =>
            {
                var f = new Fixture(tmpDir); File.WriteAllText(f.Live, "Port 22\n"); var host = new Host { Identity = "100@1" }; var txn = f.Open(host);
                Save(f, txn, "Port 2200\n"); var backup = Save(f, txn, "Port 2300\n");
                txn.Arm(backup, null, f.Due); txn.Recover(f.Due);
                if (File.ReadAllText(f.Live) != "Port 22\n") throw new Exception("Rollback restored " + File.ReadAllText(f.Live).Trim() + ", a file sshd never ran");
                // sshd restarted between the saves: it runs the first save, which is the target.
                f = new Fixture(tmpDir); File.WriteAllText(f.Live, "Port 22\n"); host = new Host { Identity = "100@1" }; txn = f.Open(host);
                Save(f, txn, "Port 2200\n"); host.Identity = "200@2"; backup = Save(f, txn, "Port 2300\n");
                txn.Arm(backup, null, f.Due); txn.Recover(f.Due);
                if (File.ReadAllText(f.Live) != "Port 2200\n") throw new Exception("After a restart, rollback restored " + File.ReadAllText(f.Live).Trim());
                // Edited outside the chain: today's rule, the file before the latest save.
                f = new Fixture(tmpDir); File.WriteAllText(f.Live, "Port 22\n"); host = new Host { Identity = "100@1" }; txn = f.Open(host);
                Save(f, txn, "Port 2200\n"); File.WriteAllText(f.Live, "Port 2201\n"); backup = Save(f, txn, "Port 2300\n");
                txn.Arm(backup, null, f.Due); txn.Recover(f.Due);
                if (File.ReadAllText(f.Live) != "Port 2201\n") throw new Exception("A foreign edit between saves was skipped: " + File.ReadAllText(f.Live).Trim());
                // The file was edited after sshd started: the first save's previous file is not what sshd runs either.
                f = new Fixture(tmpDir); File.WriteAllText(f.Live, "Port 22\n"); host = new Host { Identity = "100@1", Changed = true }; txn = f.Open(host);
                Save(f, txn, "Port 2200\n"); host.Changed = false; backup = Save(f, txn, "Port 2300\n");
                txn.Arm(backup, null, f.Due); txn.Recover(f.Due);
                if (File.ReadAllText(f.Live) != "Port 2200\n") throw new Exception("A file sshd did not load was kept as the target");
                // An Include changed between the saves: the first file cannot come back as it ran; no save may be refused for it.
                f = new Fixture(tmpDir); File.WriteAllText(f.Live, "Port 22\n"); host = new Host { Identity = "100@1" }; txn = f.Open(host);
                var include = Path.Combine(f.Root, "extra.conf"); File.WriteAllText(include, "MaxAuthTries 3\n");
                var line = "Include " + SshdArgs.Quote(include);
                Save(f, txn, line + "\nPort 2200\n", ConfigurationDependencies.Capture(new[] { line }));
                File.WriteAllText(include, "MaxAuthTries 4\n");
                backup = Save(f, txn, line + "\nPort 2300\n", ConfigurationDependencies.Capture(new[] { line }));
                txn.Arm(backup, null, f.Due); txn.Recover(f.Due);
                if (File.ReadAllText(f.Live) != line + "\nPort 2200\n") throw new Exception("The Include fallback did not restore the file before the latest save");
                return null;
            });
            test("recovery: Abandon ends a conflicting recovery without touching files or service, and saves work again", () =>
            {
                var f = new Fixture(tmpDir); var host = new Host(); var txn = f.Open(host); var id = txn.Arm(f.Backup, null, f.Due);
                File.WriteAllText(f.Live, "external edit");
                try { txn.Recover(f.Due); throw new Exception("external edit overwritten"); } catch (ConfigChangedException) { }
                if (!txn.Pending) throw new Exception("The conflict did not leave the record pending (fixture)");
                try { ConfigurationRecovery.RequireNoPending(f.Live); throw new Exception("A save was accepted while the record was pending"); }
                catch (PendingRecoveryException ex)
                {
                    if (ex.Record.Error.Length == 0 || !ex.Message.Contains(ex.Record.Error) || !ex.Record.Stuck(f.Due)) throw new Exception("The refusal does not carry the recorded error: " + ex.Message);
                    if (typeof(ConfigChangedException).IsInstanceOfType(ex)) throw new Exception("A pending record would be offered \"save anyway\"");
                }
                try { txn.Abandon("another-id", "test"); throw new Exception("A stale id abandoned the record"); } catch (ConfigException) { }
                bool pendingAtDisarm = true; host.OnDisarm = () => pendingAtDisarm = new ConfigurationRecoveryTransaction(f.Dir, f.Live, null).Pending;
                txn.Abandon(id, "kept by the administrator");
                if (txn.Pending || pendingAtDisarm || host.Disarms != 1) throw new Exception("The task was removed before the journal recorded the decision");
                if (File.ReadAllText(f.Live) != "external edit" || host.Restarts != 0 || host.Firewall != null) throw new Exception("Abandon changed the files or the service");
                ConfigurationRecovery.RequireNoPending(f.Live);
                txn.Prepare(f.Backup, Encoding.UTF8.GetBytes("next"), ConfigurationDependencies.Capture(new string[0]));
                File.WriteAllText(f.Live, "next"); txn.Arm(f.Backup, null, f.Due);
                return null;
            });
            test("recovery: Abandon after a failed restore leaves the restored file", () =>
            {
                var f = new Fixture(tmpDir); var host = new Host { FailRestart = true }; var txn = f.Open(host); var id = txn.Arm(f.Backup, null, f.Due);
                try { txn.Recover(f.Due, true); throw new Exception("restart error swallowed"); } catch (IOException) { }
                var info = ConfigurationRecovery.PendingInfo(f.Live);
                if (info == null || info.Phase != "firewall-restored" || info.Error != "restart interrupted") throw new Exception("The startup check cannot describe the stuck record");
                txn.Abandon(id, "restart sshd later");
                if (txn.Pending || !File.ReadAllBytes(f.Live).SequenceEqual(f.Before)) throw new Exception("Abandon undid the restored file");
                return null;
            });
            test("recovery: only a record that cannot complete by itself is offered for resolution", () =>
            {
                var due = new DateTime(2026, 10, 8, 12, 0, 0, DateTimeKind.Utc);
                var running = new RecoveryRecordInfo { DeadlineUtc = due };
                if (running.Stuck(due.AddSeconds(-1)) || running.Stuck(due.AddSeconds(30))) throw new Exception("A change within its deadline, or one the task is about to restore, was offered");
                if (!running.Stuck(due.AddMinutes(3))) throw new Exception("An overdue record that no task restores was not offered");
                if (!new RecoveryRecordInfo { DeadlineUtc = due, Error = "restart failed" }.Stuck(due.AddSeconds(1))) throw new Exception("A failed recovery was not offered");
                if (new RecoveryRecordInfo { DeadlineUtc = due, Error = "restart failed" }.Stuck(due.AddSeconds(-1))) throw new Exception("A failure before the deadline was offered");
                if (!PendingRecoveryException.Describe(running, due.AddSeconds(-30)).Contains("waiting")) throw new Exception("A running change is not described as waiting");
                return null;
            });
            test("recovery: an unreadable journal is reported and can be set aside", () =>
            {
                var f = new Fixture(tmpDir); var host = new Host(); var txn = f.Open(host); txn.Arm(f.Backup, null, f.Due);
                File.WriteAllText(Path.Combine(f.Dir, "pending.ini"), "status=!!not base64!!\n");
                var info = ConfigurationRecovery.PendingInfo(f.Live);
                if (info == null || !info.Damaged || !info.Stuck(DateTime.UtcNow)) throw new Exception("A damaged journal was not reported");
                try { ConfigurationRecovery.RequireNoPending(f.Live); throw new Exception("A save was accepted"); } catch (PendingRecoveryException) { }
                var aside = txn.SetAsideDamaged();
                if (!File.Exists(aside) || ConfigurationRecovery.PendingInfo(f.Live) != null || host.Disarms != 1) throw new Exception("The damaged journal still blocks saves");
                txn.Arm(f.Backup, null, f.Due);
                try { txn.SetAsideDamaged(); throw new Exception("A readable record was set aside"); } catch (ConfigException) { }
                return null;
            });
            test("recovery task: a repeated failure is logged once per distinct error, also without a readable journal", () =>
            {
                var f = new Fixture(tmpDir); var host = new Host(); var state = Path.Combine(f.Root, "recovery-failure.txt");
                int reported = 0, restored = 0;
                Func<Func<ConfigurationRecoveryTransaction>, string, int> run = (open, serviceError) => ConfigurationRecovery.Run(open, () => serviceError, state, ex => reported++, () => restored++);
                Func<ConfigurationRecoveryTransaction> fixture = () => f.Open(host);
                // The storage cannot be opened (an ancestor ACL): no journal to remember the error in.
                for (int i = 0; i < 3; i++) if (run(() => { throw new ConfigException("A recovery storage ancestor can be replaced or controlled by an untrusted account: C:\\ProgramData"); }, null) != 1) throw new Exception("An unopened storage counted as success");
                if (reported != 1) throw new Exception("An unopened storage was logged " + reported + " times in three runs");
                // An unreadable journal.
                var txn = f.Open(host); var due = DateTime.UtcNow.AddMinutes(-1); txn.Arm(f.Backup, null, due);
                File.WriteAllText(Path.Combine(f.Dir, "pending.ini"), "status=!!not base64!!\n");
                for (int i = 0; i < 3; i++) run(fixture, null);
                if (reported != 2) throw new Exception("A damaged journal was logged " + (reported - 1) + " times in three runs");
                txn.SetAsideDamaged();
                // An error found before Recover ran is logged once and shown by the manager.
                File.WriteAllText(f.Live, "new settings"); txn.Arm(f.Backup, null, due);
                const string definition = "The SSH service runs a different executable";
                for (int i = 0; i < 3; i++) run(fixture, definition);
                var info = ConfigurationRecovery.PendingInfo(f.Live);
                if (reported != 3 || info == null || info.Error != definition) throw new Exception("The service definition error was logged " + (reported - 2) + " times or not recorded");
                // A configuration lock held elsewhere (a window restoring) is no failure.
                WhileLocked(f.Live, () => { if (run(fixture, null) != 0) throw new Exception("A busy lock counted as a failure"); });
                if (reported != 3 || !txn.Pending) throw new Exception("A busy lock was logged or recovered");
                // Success forgets the error, so that it is logged again when it comes back.
                if (run(fixture, null) != 0 || restored != 1 || txn.Pending || File.Exists(state)) throw new Exception("The recovery did not complete or its last error was kept");
                File.WriteAllText(f.Live, "new settings"); txn.Arm(f.Backup, null, due);
                run(fixture, definition);
                if (reported != 4) throw new Exception("A failure that came back after a success was not logged");
                return null;
            });
            test("restart with rollback: a failure after arming restores at once and says so", () =>
            {
                AsyncUiTest.Wait(async () =>
                {
                    Func<Func<RestoreResult>, Task<RestoreResult>> inline = work => Task.FromResult(work());
                    var f = new Fixture(tmpDir); var host = new Host(); var txn = f.Open(host);
                    var id = txn.Arm(f.Backup, new FirewallRule { Name = "test", Enabled = true, Profiles = 3, Ports = "22" }, f.Due);
                    try { await MainForm.RecoverOnFailure(txn, id, async () => { await Task.Delay(1); throw new IOException("firewall apply failed"); }, inline, "The firewall could not be prepared."); throw new Exception("The failed step was ignored"); }
                    catch (ConfigException ex) { if (!ex.Message.Contains("previous settings were restored") || !ex.Message.Contains("firewall apply failed")) throw new Exception("Untruthful message: " + ex.Message); }
                    if (txn.Pending || !File.ReadAllBytes(f.Live).SequenceEqual(f.Before) || host.Restarts != 1 || host.Firewall == null || host.Firewall.Ports != "22") throw new Exception("The previous settings were not restored at once");
                    ConfigurationRecovery.RequireNoPending(f.Live);
                    // Keep fails after the person clicked Keep: not kept, restored now, not a minute later by the task.
                    f = new Fixture(tmpDir); host = new Host(); txn = f.Open(host); id = txn.Arm(f.Backup, null, f.Due); var keeping = txn; var keptId = id;
                    try { await MainForm.RecoverOnFailure(txn, id, () => keeping.ConfirmAsync(keptId, async () => { await Task.Delay(1); throw new ConfigException("listeners could not be verified"); }), inline, "The new settings could not be finalized, so they were NOT kept."); throw new Exception("The failed Keep was ignored"); }
                    catch (ConfigException ex) { if (!ex.Message.Contains("NOT kept") || !ex.Message.Contains("previous settings were restored")) throw new Exception("Untruthful message: " + ex.Message); }
                    if (txn.Pending || !File.ReadAllBytes(f.Live).SequenceEqual(f.Before)) throw new Exception("A failed Keep left the new settings armed");
                    // A closed window leaves recovery to the task.
                    f = new Fixture(tmpDir); host = new Host(); txn = f.Open(host); id = txn.Arm(f.Backup, null, f.Due);
                    try { await MainForm.RecoverOnFailure(txn, id, () => { throw new OperationCanceledException(); }, inline, "x"); throw new Exception("Cancellation was swallowed"); }
                    catch (OperationCanceledException) { }
                    if (!txn.Pending || host.Restarts != 0) throw new Exception("A cancelled step restored the settings");
                });
                return null;
            });
            test("restart with rollback: a restore the recovery task got to first is reported as restored, a held lock as a restore in progress", () =>
            {
                // The Keep dialog timed out at the deadline and the task restored first.
                var f = new Fixture(tmpDir); var host = new Host(); var txn = f.Open(host); var id = txn.Arm(f.Backup, null, f.Due);
                txn.Recover(f.Due);
                var result = txn.RestoreNow(id, DateTime.UtcNow); var text = MainForm.RestoreText(result);
                if (result.Outcome != RestoreOutcome.RestoredElsewhere || !result.Restored || !text.Contains("previous settings were restored") || text.Contains("kept")) throw new Exception("A restore by the task reads as: " + text);
                // A failed step after arming, with the task first: restored, not "restored or kept elsewhere".
                f = new Fixture(tmpDir); txn = f.Open(host); id = txn.Arm(f.Backup, null, f.Due); var first = txn;
                ConfigException error = null;
                AsyncUiTest.Wait(async () =>
                {
                    try { await MainForm.RecoverOnFailure(first, id, async () => { await Task.Delay(1); first.Recover(f.Due); throw new IOException("listeners could not be verified"); }, work => Task.FromResult(work()), "The new settings were NOT kept."); }
                    catch (ConfigException ex) { error = ex; }
                });
                if (error == null || !error.Message.Contains("previous settings were restored") || error.Message.Contains("kept elsewhere")) throw new Exception("Ambiguous message: " + (error == null ? "none" : error.Message));
                // The task holds the lock while it restores: in progress, not a failed restore, and nothing is touched meanwhile.
                f = new Fixture(tmpDir); host = new Host(); txn = f.Open(host); id = txn.Arm(f.Backup, null, f.Due); var busy = txn; var busyId = id;
                WhileLocked(f.Live, () => result = busy.RestoreNow(busyId, DateTime.UtcNow));
                if (result.Outcome != RestoreOutcome.InProgressElsewhere || result.Restored || !txn.Pending || host.Restarts != 0) throw new Exception("A held lock was reported as " + result.Outcome);
                if (!MainForm.RestoreText(result).Contains("restoring")) throw new Exception(MainForm.RestoreText(result));
                // Another change's record is never restored in place of this one.
                if (txn.RestoreNow("another-id", DateTime.UtcNow).Outcome != RestoreOutcome.ResolvedElsewhere || !txn.Pending) throw new Exception("A stale id restored the pending change");
                result = txn.RestoreNow(id, DateTime.UtcNow);
                if (result.Outcome != RestoreOutcome.Restored || txn.Pending || !File.ReadAllBytes(f.Live).SequenceEqual(f.Before) || result.SavedMeanwhile != null) throw new Exception("The window's restore did not run");
                return null;
            });
            test("restart with rollback: a rollback past a file saved without a restart says where that file is kept", () =>
            {
                var f = new Fixture(tmpDir); File.WriteAllText(f.Live, "Port 22\n"); var host = new Host { Identity = "100@1" }; var txn = f.Open(host);
                Save(f, txn, "Port 2200\n"); var backup = Save(f, txn, "Port 2300\n");
                var result = txn.RestoreNow(txn.Arm(backup, null, f.Due), DateTime.UtcNow);
                if (File.ReadAllText(f.Live) != "Port 22\n" || result.SavedMeanwhile == null || Path.GetFullPath(result.SavedMeanwhile) != Path.GetFullPath(backup) || File.ReadAllText(backup) != "Port 2200\n")
                    throw new Exception("The file saved without a restart is not reported: " + result.SavedMeanwhile);
                var text = MainForm.RestoreText(result);
                if (!text.Contains(Path.GetFileName(backup)) || !text.Contains("never ran")) throw new Exception(text);
                // Restored by the task: the same note.
                f = new Fixture(tmpDir); File.WriteAllText(f.Live, "Port 22\n"); txn = f.Open(host);
                Save(f, txn, "Port 2200\n"); backup = Save(f, txn, "Port 2300\n");
                var id = txn.Arm(backup, null, f.Due); txn.Recover(f.Due);
                result = txn.RestoreNow(id, DateTime.UtcNow);
                if (result.Outcome != RestoreOutcome.RestoredElsewhere || result.SavedMeanwhile == null) throw new Exception("The task's restore lost the note");
                // A single save restores the backup it took: nothing else to say.
                f = new Fixture(tmpDir); File.WriteAllText(f.Live, "Port 22\n"); txn = f.Open(host);
                backup = Save(f, txn, "Port 2200\n");
                result = txn.RestoreNow(txn.Arm(backup, null, f.Due), DateTime.UtcNow);
                if (result.SavedMeanwhile != null || MainForm.RestoreText(result).Contains("kept as")) throw new Exception("A plain rollback mentions a set-aside file");
                return null;
            });
            test("restart: a restart without recovery is offered only when recovery itself is unavailable", () =>
            {
                if (!MainForm.RestartWithoutRecoveryAllowed(new ConfigException("The SSH service has an unsupported runtime option (-p).")) || !MainForm.RestartWithoutRecoveryAllowed(new IOException("schtasks failed")))
                    throw new Exception("An unavailable recovery refuses the Restart button outright");
                foreach (var refusal in new Exception[] { new PendingRecoveryException(new RecoveryRecordInfo()), new ConfigChangedException("changed"), new ConfigurationBusyException("busy") })
                    if (MainForm.RestartWithoutRecoveryAllowed(refusal)) throw new Exception("A journal refusal offers a restart without recovery: " + refusal.GetType().Name);
                return null;
            });
            test("restart: a plain restart arms recovery only when sshd does not run the saved file", () =>
            {
                const string first = @"C:\ssh\sshd_config.bak.20261008-110000", newest = @"C:\ssh\sshd_config.bak.20261008-120000";
                var record = new Dictionary<string, string> { { "status", "prepared" }, { "applied", "H" }, { "server", "100@1" }, { "backup.path", first } };
                var r = ConfigurationRecovery.RestartRollbackFor(record, "H", "100@1", true, newest);
                if (r == null || !r.FromRecord || r.Backup != first) throw new Exception("A save-only change of the running sshd was restarted without its rollback target");
                r = ConfigurationRecovery.RestartRollbackFor(record, "H", "200@2", true, newest);
                if (r == null || r.FromRecord || r.Backup != newest) throw new Exception("The record of an earlier sshd process was used");
                if (ConfigurationRecovery.RestartRollbackFor(record, "H", "200@2", false, newest) != null) throw new Exception("A restart that changes nothing was armed");
                r = ConfigurationRecovery.RestartRollbackFor(record, "edited", "100@1", true, newest);
                if (r == null || r.FromRecord || r.Backup != newest) throw new Exception("A file edited after the save was restarted without recovery");
                if (ConfigurationRecovery.RestartRollbackFor(null, "H", "", true, null) != null) throw new Exception("Recovery was armed without any previous file");
                // A stale save-only record must not block the restart's own record.
                var f = new Fixture(tmpDir); File.WriteAllText(f.Live, "Port 22\n"); var host = new Host { Identity = "100@1" }; var txn = f.Open(host);
                var backup = Save(f, txn, "Port 2200\n"); File.WriteAllText(f.Live, "Port 2201\n");
                try { txn.Arm(backup, null, f.Due); throw new Exception("A stale prepared record was armed"); } catch (ConfigChangedException) { }
                txn.ArmFresh(backup, null, f.Due); txn.Recover(f.Due);
                if (File.ReadAllText(f.Live) != "Port 22\n") throw new Exception("The restart's rollback did not restore its backup");
                return null;
            });
            test("sshd_config encoding: text that is not UTF-8 is found by line and a save refuses to destroy it", () =>
            {
                var p = Path.Combine(tmpDir, "ansi-" + Guid.NewGuid().ToString("N"));
                var ansi = new byte[] { 0x23, 0x20, 0xE9, 0x0D, 0x0A, 0x50, 0x6F, 0x72, 0x74, 0x20, 0x32, 0x32, 0x0D, 0x0A };
                File.WriteAllBytes(p, ansi);
                var c = SshdConfig.Load(p);
                if (!c.InvalidUtf8Lines.SequenceEqual(new[] { 1 }) || c.Get("Port") != "22") throw new Exception("Lines not UTF-8: " + string.Join(",", c.InvalidUtf8Lines));
                var cand = c.Copy(); cand.Set("MaxAuthTries", "3");
                var refusal = SshdConfig.NonUtf8Refusal(cand, ansi);
                if (refusal == null || !refusal.Contains("line 1") || !refusal.Contains("NOT saved")) throw new Exception("An edited copy would be saved with U+FFFD: " + refusal);
                try { ConfigurationTransaction.Save(cand, false); throw new Exception("The save went ahead"); } catch (ConfigException) { }
                if (!File.ReadAllBytes(p).SequenceEqual(ansi) || Directory.GetFiles(tmpDir).Any(x => Path.GetFileName(x).StartsWith(Path.GetFileName(p) + ".", StringComparison.OrdinalIgnoreCase))) throw new Exception("The refused save changed or staged files");
                // The text tab builds its candidate from the editor: the file on disk tells.
                var editor = new SshdConfig { Path = p, Lines = new List<string> { "# \uFFFD", "Port 2222" } };
                if (SshdConfig.NonUtf8Refusal(editor, ansi) == null) throw new Exception("An editor text with U+FFFD would be saved over ANSI text");
                // UTF-8 (Thai, with and without BOM) is untouched, and a restored backup is written as it is.
                var thai = Encoding.UTF8.GetBytes("# \u0e17\u0e14\u0e2a\u0e2d\u0e1a\r\nPort 22\r\n");
                foreach (var bytes in new[] { thai, new byte[] { 0xEF, 0xBB, 0xBF }.Concat(thai).ToArray() })
                {
                    File.WriteAllBytes(p, bytes); var u = SshdConfig.Load(p);
                    if (u.InvalidUtf8Lines.Count != 0 || SshdConfig.NonUtf8Refusal(u, bytes) != null || !new UTF8Encoding(false).GetBytes(u.Text).SequenceEqual(thai)) throw new Exception("Valid UTF-8 was flagged or changed");
                }
                File.WriteAllBytes(p, ansi);
                if (SshdConfig.NonUtf8Refusal(SshdConfig.LoadExact(p), thai) != null) throw new Exception("A byte-exact restore was refused");
                return null;
            });
            test("sshd_config encoding: restoring a backup writes its exact bytes", () =>
            {
                WithFakeServer(tmpDir, 0, dir =>
                {
                    var bytes = new byte[] { 0xEF, 0xBB, 0xBF, 0x23, 0x20, 0xE9, 0x0D, 0x0A, 0x50, 0x6F, 0x72, 0x74, 0x20, 0x32, 0x32, 0x0D, 0x0A };
                    var backup = Path.Combine(dir, "kept-backup"); File.WriteAllBytes(backup, bytes);
                    File.WriteAllText(Ssh.ConfigPath, "Port 2222\n");
                    var cand = SshdConfig.LoadExact(backup); cand.Path = Ssh.ConfigPath; cand.LoadedHash = SshdConfig.FileHash(Ssh.ConfigPath);
                    ConfigurationTransaction.Save(cand, false);
                    if (!File.ReadAllBytes(Ssh.ConfigPath).SequenceEqual(bytes)) throw new Exception("Backups... restore re-encoded the backup");
                    File.WriteAllText(Ssh.ConfigPath, "Port 2222\n");
                    typeof(MainForm).GetMethod("RestoreFile", BindingFlags.Static | BindingFlags.NonPublic).Invoke(null, new object[] { backup });
                    if (!File.ReadAllBytes(Ssh.ConfigPath).SequenceEqual(bytes)) throw new Exception("The rollback fallback re-encoded the backup");
                });
                return null;
            });
            test("GUI settings: a shell-only save leaves sshd_config, its backups and recovery alone", () =>
            {
                // sshd -t rejects everything here: before, the unrelated registry change could not be saved at all.
                WithFakeServer(tmpDir, 1, dir =>
                {
                    File.WriteAllText(Ssh.ConfigPath, "Port 22\r\n");
                    var written = DateTime.UtcNow.AddHours(-1); File.SetLastWriteTimeUtc(Ssh.ConfigPath, written);
                    var hash = SshdConfig.FileHash(Ssh.ConfigPath);
                    string actual = null, error = null;
                    using (var f = new MainForm())
                    {
                        var handle = f.Handle; // No Show: nothing live is loaded.
                        try
                        {
                            typeof(MainForm).GetField("_cfg", Private).SetValue(f, SshdConfig.Load());
                            AsyncUiTest.Wait(() => (Task)typeof(MainForm).GetMethod("LoadSettings", Private).Invoke(f, new object[] { false }));
                            typeof(MainForm).GetField("_writeDefaultShell", Private).SetValue(f, (Action<string, string>)((shell, option) => actual = option));
                            var optionBox = (TextBox)typeof(MainForm).GetField("_txtShellOption", Private).GetValue(f);
                            var wanted = optionBox.Text == "-config-test" ? "-other-config-test" : "-config-test";
                            optionBox.Text = wanted;
                            error = f.SaveSettingsForTest();
                            if (actual != wanted) throw new Exception("The shell option was not written");
                        }
                        finally { f.Close(); }
                    }
                    if (error != null) throw new Exception("A shell-only save ran the sshd_config save: " + error);
                    if (File.GetLastWriteTimeUtc(Ssh.ConfigPath) != written || SshdConfig.FileHash(Ssh.ConfigPath) != hash || SshdConfig.ListBackups(Ssh.ConfigPath).Count != 0 ||
                        File.Exists(Path.Combine(dir, "manager", "recovery", "pending.ini"))) throw new Exception("sshd_config was rewritten, backed up or given a recovery record");
                });
                return null;
            });
            test("GUI settings: errors after the save never read as not saved, and only port changes or a restart check the firewall", () =>
            {
                var status = MainForm.ConfigErrorStatus(new ConfigException("Settings were saved, but the firewall rule could not be updated: access denied\n\ndetails"));
                if (status.IndexOf("not saved", StringComparison.OrdinalIgnoreCase) >= 0 || !status.Contains("Settings were saved") || status.Contains("details")) throw new Exception(status);
                if (!MainForm.ConfigErrorStatus(new ConfigException("The configuration was NOT saved because sshd rejected it:\n\nline 3")).Contains("NOT saved")) throw new Exception("A refused save no longer says so");
                Func<string, SshdConfig> config = text => new SshdConfig { Lines = text.Split('\n').ToList() };
                if (MainForm.EndpointsChanged(config("Port 22\nMaxAuthTries 3"), config("Port 22\nMaxAuthTries 4"))) throw new Exception("A save without a port change checks the firewall");
                if (!MainForm.EndpointsChanged(config("Port 22"), config("Port 2222")) || !MainForm.EndpointsChanged(config("Port 22"), config("Port 22\nListenAddress 10.0.0.1:2222")))
                    throw new Exception("A port or listen address change skips the firewall");
                // A port saved earlier without a restart (firewall declined then) takes effect with the next Save and restart.
                if (!MainForm.ChecksFirewall(config("Port 2222\nMaxAuthTries 3"), config("Port 2222\nMaxAuthTries 4"), true)) throw new Exception("Save and restart skips the firewall offer");
                if (MainForm.ChecksFirewall(config("Port 2222\nMaxAuthTries 3"), config("Port 2222\nMaxAuthTries 4"), false)) throw new Exception("A save-only change without a port change checks the firewall");
                return null;
            });
            test("service path: an unquoted ImagePath with spaces is read as InstallDir reads it", () =>
            {
                const string executable = @"C:\Program Files\OpenSSH\sshd.exe", config = @"C:\ProgramData\ssh\sshd_config";
                Func<string, bool> none = path => false;
                foreach (var command in new[] { executable, executable + " -f " + config, executable + " -f \"" + config + "\" -E C:\\logs\\sshd.log", " " + executable + " " })
                {
                    var error = ServerState.ServiceDefinitionError(command, executable, config, none);
                    if (error != null) throw new Exception("Rejected [" + command + "]: " + error);
                }
                var shadowed = ServerState.ServiceDefinitionError(executable, executable, config, path => path.Equals(@"C:\Program.exe", StringComparison.OrdinalIgnoreCase));
                if (shadowed == null || !shadowed.Contains(@"C:\Program.exe")) throw new Exception("A program Windows would start first was ignored");
                if (ServerState.ServiceDefinitionError(executable + " -p 2222", executable, config, none) == null) throw new Exception("An override was accepted unquoted");
                if (ServerState.ServiceDefinitionError(@"C:\Program Files\Other\sshd.exe -f " + config, executable, config, none) == null) throw new Exception("Another executable was accepted");
                if (Services.ParseImagePath(executable + " -f " + config) != executable || Services.ParseImagePath("\"" + executable + "\" -D") != executable || Services.ParseImagePath(@"C:\x.exec\sshd.exe") != @"C:\x.exec\sshd.exe")
                    throw new Exception("The shared ImagePath reading differs");
                return null;
            });
            test("system tasks: definitions are staged under ProgramData, never in the user's TEMP", () =>
            {
                var dir = Path.GetFullPath(SystemTasks.StagingDir(Guid.NewGuid().ToString("N")));
                var data = Path.GetFullPath(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)).TrimEnd('\\') + "\\";
                if (!dir.StartsWith(data, StringComparison.OrdinalIgnoreCase) || dir.StartsWith(Path.GetFullPath(Path.GetTempPath()), StringComparison.OrdinalIgnoreCase)) throw new Exception(dir);
                return null;
            });
            test("system tasks: a profile-removal task is unique per account SID and fits partners", () =>
            {
                var first = new SecurityIdentifier("S-1-5-21-1-2-3-1001"); var second = new SecurityIdentifier("S-1-5-21-1-2-3-1002");
                var a = SystemTasks.ProfileRemovalTaskName(first, "alice"); var b = SystemTasks.ProfileRemovalTaskName(second, "Alice");
                if (string.Equals(a, b, StringComparison.OrdinalIgnoreCase) || !a.Contains(first.Value)) throw new Exception("A re-created account replaces the task of the first one: " + a);
                var description = SystemTasks.ProfileRemovalDescription(first, "alice");
                if (description.Contains("temporary test account") || !description.Contains("SFTP partner") || !description.Contains(first.Value)) throw new Exception(description);
                if (!SystemTasks.ProfileRemovalScript(first.Value, a).Contains("'" + a + "'")) throw new Exception("The task cannot remove itself by its new name");
                return null;
            });
        }
    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.IO;

namespace OpenSSHServerPNManager
{
    internal static class AuditAgentTests
    {
        internal static void Run(Action<string, Func<string>> test)
        {
            test("partners: drive-root setup keeps absolute account folders", PartnerDriveRoot);
            test("partners: reserved device names cannot become account folders", ReservedNames);
            test("webhooks: all JSON control characters are escaped", HookControlChars);
            test("agent: watch and daily serialize their state transactions", StateTransactions);
            test("agent: failed service alert persists and retries only the undelivered destination", () => Isolated(() =>
            {
                var settings = new AlertSettings { SmtpHost = "smtp.example.com", From = "server@example.com", AdminTo = "admin@example.com", Webhook = "https://example.com/hook" };
                var st = new AgentState { SshdStatus = "Running" };
                Agent.ObserveStatus(settings, st, "Stopped", DateTime.Now, "fixture"); st.Save();
                int mail = 0, hook = 0; bool lockFree = false;
                NotificationOutbox.Drain(item =>
                {
                    // Another worker must be able to collect events while delivery is in progress.
                    var worker = new Thread(() => { lockFree = Agent.WithStateLock(Agent.StateLockName, 0, () => { }); });
                    worker.Start(); worker.Join();
                    if (item.Destination == "mail") mail++; else { hook++; throw new IOException("fixture delivery unavailable"); }
                });
                st = AgentState.Load();
                Agent.ObserveStatus(settings, st, "Stopped", DateTime.Now, "fixture"); st.Save();
                var health = AgentHealth.From(st);
                if (!lockFree || mail != 1 || hook != 1 || st.Notifications.Count != 2 || health.PendingNotifications != 1 || health.FailedNotifications != 1 || health.PendingByDestination["webhook"] != 1)
                    throw new Exception("partial delivery was consumed, duplicated, or held the agent state lock");
                var pending = st.Notifications.Single(n => !n.Delivered); pending.NextUtc = DateTime.UtcNow.AddSeconds(-1); st.Save();
                NotificationOutbox.Drain(item => { if (item.Destination == "mail") mail++; else hook++; });
                st = AgentState.Load();
                if (mail != 1 || hook != 2 || st.Notifications.Any(n => !n.Delivered)) throw new Exception("retry duplicated the successful destination or lost the failed one");
                return null;
            }));
            test("agent: delivery leases recover and retries stop visibly at the configured bound", () =>
            {
                var st = new AgentState(); var now = DateTime.UtcNow;
                NotificationOutbox.Enqueue(st, new AlertSettings { Webhook = "https://example.com/hook" }, "fixture", "subject", "body", null, new List<string>(), null, null, now);
                var first = NotificationOutbox.Claim(st, now); var staleLease = first.Lease;
                if (NotificationOutbox.Claim(st, now.AddMinutes(1)) != null) throw new Exception("overlapping worker claimed an active lease");
                var recovered = NotificationOutbox.Claim(st, now.AddMinutes(4));
                if (recovered == null || recovered.Lease == staleLease) throw new Exception("expired lease was not recovered");
                NotificationOutbox.Complete(st, first.Id, staleLease, now.AddMinutes(4), null);
                if (first.Delivered) throw new Exception("stale worker overwrote a newer claim");
                for (int i = 0; i < NotificationOutbox.MaxAttempts; i++)
                {
                    var claim = i == 0 ? recovered : NotificationOutbox.Claim(st, now.AddDays(i + 1));
                    NotificationOutbox.Complete(st, claim.Id, claim.Lease, now.AddDays(i + 1), "fixture unavailable");
                }
                if (NotificationOutbox.Claim(st, now.AddDays(100)) != null || AgentHealth.From(st).ExhaustedNotifications != 1)
                    throw new Exception("exhausted delivery did not stop with a visible failure");
                return null;
            });
        }

        private static string Isolated(Func<string> body)
        {
            var previous = Ssh.ConfigDirOverride;
            var directory = Path.Combine(Path.GetTempPath(), "pn-outbox-test-" + Guid.NewGuid().ToString("N"));
            try { Ssh.ConfigDirOverride = directory; using (new ScratchStorage(directory)) return body(); }
            finally { Ssh.ConfigDirOverride = previous; if (Directory.Exists(directory)) Directory.Delete(directory, true); }
        }

        internal sealed class ScratchStorage : AgentStorage.PermissionPolicy, IDisposable
        {
            private readonly string root;
            private readonly AgentStorage.PermissionPolicy previous;
            private readonly string previousLock;
            internal ScratchStorage(string directory)
            {
                root = Path.GetFullPath(directory).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
                if (!root.StartsWith(Path.GetFullPath(Path.GetTempPath()).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException("Agent fixture storage must stay inside the temporary directory.");
                previous = AgentStorage.Permissions; AgentStorage.Permissions = this;
                // The installed agent takes the machine-wide lock every minute: a fixture must neither wait for it nor block it.
                previousLock = Agent.StateLockName; Agent.StateLockName = "Local\\pn-agent-test-" + Guid.NewGuid().ToString("N");
            }
            private void Check(string path)
            {
                if (!(Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar).StartsWith(root, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException("An agent fixture attempted to access storage outside its scratch directory.");
            }
            public void CreateFolder(string path) { Check(path); Directory.CreateDirectory(path); }
            public void RestrictFile(string path) { Check(path); }
            public void Dispose() { AgentStorage.Permissions = previous; Agent.StateLockName = previousLock; }
        }

        public static string PartnerDriveRoot()
        {
            foreach (var root in new[] { @"C:\", @"D:\Partners" })
            {
                var cfg = new SshdConfig(); var groups = new PartnerGroups();
                PartnerSetup.Apply(cfg, groups, root);
                var actual = PartnerSetup.Check(cfg, groups).Root;
                if (actual != root) throw new Exception("setup changed root " + root + " to " + actual);
                if (Partners.FolderOf(actual, "auditpartner") != root.TrimEnd('\\') + @"\auditpartner")
                    throw new Exception("account folder is not under the configured absolute root");
            }
            return null;
        }

        public static string ReservedNames()
        {
            foreach (var name in new[] { "CON", "con.csv", "NUL", "nul.log", "PRN", "AUX", "COM1", "com9.txt", "LPT1", "lpt9.txt" })
                if (Partners.NameError(name) == null) throw new Exception("accepted Windows device name " + name);
            return null;
        }

        public static string HookControlChars()
        {
            var controls = new string(Enumerable.Range(0, 32).Select(i => (char)i).ToArray());
            foreach (bool teams in new[] { false, true })
            {
                var body = Agent.HookBody(teams, "subject" + controls, "body" + controls);
                if (body.Any(c => c < 32)) throw new Exception("webhook JSON contains a raw control character");
            }
            return null;
        }

        public static string StateTransactions()
        {
            var name = "Local\\osm-audit-" + Guid.NewGuid().ToString("N");
            int state = 0; Exception workerError = null;
            using (var entered = new ManualResetEvent(false))
            using (var release = new ManualResetEvent(false))
            {
                var worker = new Thread(() =>
                {
                    try { Agent.WithStateLock(name, 1000, () => { int saved = state; entered.Set(); if (!release.WaitOne(5000)) throw new Exception("test timed out"); state = saved + 1; }); }
                    catch (Exception ex) { workerError = ex; }
                });
                worker.Start();
                bool overlap = false;
                try
                {
                    if (!entered.WaitOne(5000)) throw new Exception("first state transaction did not start" + (workerError == null ? "" : ": " + workerError));
                    overlap = Agent.WithStateLock(name, 0, () => state++);
                }
                finally { release.Set(); worker.Join(); }
                if (workerError != null) throw workerError;
                if (overlap) throw new Exception("a second job entered while the first held stale state");
                if (!Agent.WithStateLock(name, 1000, () => state++) || state != 2) throw new Exception("later transaction did not preserve both updates");
            }
            try { Agent.WithStateLock(name, 1000, () => { throw new InvalidOperationException("fixture"); }); }
            catch (InvalidOperationException) { }
            bool afterException = false; Exception retryError = null;
            var retry = new Thread(() =>
            {
                try { afterException = Agent.WithStateLock(name, 1000, () => { }); }
                catch (Exception ex) { retryError = ex; }
            });
            retry.Start(); retry.Join();
            if (retryError != null) throw retryError;
            if (!afterException) throw new Exception("an exception left the mutex locked");
            // Keep a handle alive so the named mutex remains abandoned when its owner thread exits.
            using (var keepAlive = new Mutex(false, name))
            {
                var abandoned = new Thread(() => { using (var owner = Mutex.OpenExisting(name)) owner.WaitOne(); });
                abandoned.Start(); abandoned.Join();
                if (!Agent.WithStateLock(name, 1000, () => { })) throw new Exception("an abandoned mutex blocked recovery");
            }
            return null;
        }
    }
}

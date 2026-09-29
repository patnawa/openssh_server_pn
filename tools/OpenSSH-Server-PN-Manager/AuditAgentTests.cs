using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;

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

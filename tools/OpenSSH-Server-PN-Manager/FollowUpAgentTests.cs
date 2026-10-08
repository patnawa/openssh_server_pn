using System;
using System.Collections.Generic;
using System.Dynamic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace OpenSSHServerPNManager
{
    /// <summary>Regressions for the background agent, blocking and alerts (October 2026 follow-up review).</summary>
    internal static class FollowUpAgentTests
    {
        internal static void Run(Action<string, Func<string>> test, string tmpDir)
        {
            test("agent state: a reader of the file delays the agent's replace instead of failing it", () => Isolated(dir =>
            {
                var path = Path.Combine(dir, "state.ini");
                Ini.Write(path, new Dictionary<string, string> { { "a", "1" } });
                // As Ini.Read opens it: shared for reading only, never for delete.
                using (var opened = new ManualResetEvent(false))
                {
                    var reader = new Thread(() =>
                    {
                        using (new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read)) { opened.Set(); Thread.Sleep(700); }
                    });
                    reader.Start();
                    try
                    {
                        if (!opened.WaitOne(5000)) throw new Exception("the fixture reader did not open the file");
                        Ini.Write(path, new Dictionary<string, string> { { "a", "2" } });
                    }
                    finally { reader.Join(); }
                }
                if (Ini.Read(path)["a"] != "2") throw new Exception("the new value was not written");
                if (Directory.GetFiles(dir, "*.new").Length != 0) throw new Exception("a temporary file was left");
                return null;
            }));
            test("agent state: a replace that removed the file without putting the new one in place loses nothing", () => Isolated(dir =>
            {
                var path = Path.Combine(dir, "state.ini");
                File.WriteAllText(path, "x=old\r\n");
                // ERROR_UNABLE_TO_MOVE_REPLACEMENT without a backup name: the replaced file is gone, the new one still has its temporary name.
                Ini.WriteReplacing(path, w => w.Write("x=new\r\n"), (from, to) => { File.Delete(to); throw new IOException("fixture: unable to move the replacement"); });
                if (Ini.Read(path)["x"] != "new") throw new Exception("the retried replace did not put the new file in place");
                try { Ini.WriteReplacing(path, w => w.Write("x=newer\r\n"), (from, to) => { File.Delete(to); throw new InvalidOperationException("fixture"); }); throw new Exception("the failure was not reported"); }
                catch (InvalidOperationException) { }
                if (!File.Exists(path) || Ini.Read(path)["x"] != "newer") throw new Exception("the only copy of the new contents was deleted");
                var fresh = Path.Combine(dir, "fresh.ini");
                try { Ini.WriteReplacing(fresh, w => { w.Write("x=partial"); throw new IOException("fixture: disk full"); }); }
                catch (IOException) { }
                if (File.Exists(fresh)) throw new Exception("a partly written file took the place of a missing one");
                if (Directory.GetFiles(dir, "*.new").Length != 0) throw new Exception("a temporary file was left");
                return null;
            }));
            test("transfer archive: readers wait out the agent's replace, and what they cannot read is reported", () => Isolated(dir =>
            {
                var t = new DateTime(2026, 9, 14, 10, 0, 0);
                Agent.Archive(new List<TransferRecord> { new TransferRecord { Time = t, User = "acme", Action = TransferRecord.Upload, File = "/in/a.csv", Bytes = 10 } });
                var file = TransferArchive.FileOf(t);
                // What File.Replace holds for a moment: delete access, shared for everything.
                var problems = new List<string>();
                List<TransferRecord> read;
                using (var replacing = new FileStream(file, FileMode.Open, FileSystemRights.Delete | FileSystemRights.ReadData, FileShare.ReadWrite | FileShare.Delete, 4096, FileOptions.None))
                {
                    var release = new Thread(() => { Thread.Sleep(400); replacing.Dispose(); });
                    release.Start();
                    read = TransferArchive.Read(t.Date, t.Date.AddDays(1), problems);
                    release.Join();
                }
                if (read.Count != 1 || problems.Count != 0) throw new Exception("a read during the replace got " + read.Count + " record(s): " + string.Join("; ", problems));
                // A reader holds the file while the agent archives: the agent's replace waits for it.
                using (var opened = new ManualResetEvent(false))
                {
                    var reader = new Thread(() => { using (new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite)) { opened.Set(); Thread.Sleep(500); } });
                    reader.Start();
                    try
                    {
                        if (!opened.WaitOne(5000)) throw new Exception("the fixture reader did not open the archive");
                        Agent.Archive(new List<TransferRecord> { new TransferRecord { Time = t.AddMinutes(1), User = "acme", Action = TransferRecord.Upload, File = "/in/b.csv", Bytes = 20 } });
                    }
                    finally { reader.Join(); }
                }
                if (TransferArchive.Read(t.Date, t.Date.AddDays(1)).Count != 2) throw new Exception("the archive replace under a reader lost a record");
                problems.Clear();
                using (new FileStream(file, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
                    read = TransferArchive.Read(t.Date, t.Date.AddDays(1), problems);
                if (read.Count != 0 || problems.Count != 1 || !problems[0].Contains(Path.GetFileName(file))) throw new Exception("an unreadable archive was not reported: " + string.Join("; ", problems));
                File.AppendAllText(file, "not a record\r\n");
                problems.Clear();
                read = TransferArchive.Read(t.Date, t.Date.AddDays(1), problems);
                if (read.Count != 2 || problems.Count != 1) throw new Exception("a line that is not a record was dropped silently");
                return null;
            }));
            test("agent: a refused expiry keeps the blocks due and lets the rest of the run go on", () => Isolated(dir =>
            {
                var now = new DateTime(2026, 10, 8, 12, 0, 0);
                var st = new AgentState();
                st.Blocks["198.51.100.9"] = new AgentState.BlockEntry { Until = now.AddMinutes(-1), Strikes = 1, LastStrike = now.AddMinutes(-61) };
                var error = Agent.LiftExpired(st, now, a => { throw new COMException("fixture: RPC server unavailable", unchecked((int)0x800706BA)); });
                if (error == null || !error.Contains("could not be lifted")) throw new Exception("the failure was not reported: " + error);
                if (st.Blocks["198.51.100.9"].Until != now.AddMinutes(-1)) throw new Exception("an expiry that did not happen was recorded");
                if (Agent.BlockingReason(true, "", error) != error) throw new Exception("a successful block step hid the failed expiry");
                var removed = new List<string>();
                if (Agent.LiftExpired(st, now.AddMinutes(1), a => removed.AddRange(a)) != null) throw new Exception("a working firewall reported a failure");
                if (string.Join(",", removed) != "198.51.100.9" || st.Blocks["198.51.100.9"].Until != DateTime.MinValue) throw new Exception("the retried expiry did not lift the block");
                return null;
            }));
            test("agent: a blocking problem from when automatic blocking was on goes once it is off", () =>
            {
                if (Agent.BlockingReason(false, "peer inspection unavailable", null) != "") throw new Exception("a stale reason stayed");
                if (Agent.BlockingReason(true, "peer inspection unavailable", null) != "peer inspection unavailable") throw new Exception("a current reason was lost");
                if (Agent.BlockingReason(false, "stale", "blocks whose time is up could not be lifted: x") != "blocks whose time is up could not be lifted: x") throw new Exception("a failed expiry was hidden");
                return null;
            });
            test("firewall: the block rule reads as empty only when it does not exist; any other failure throws", () =>
            {
                var blockRules = typeof(Firewall).GetMethod("BlockRules", BindingFlags.NonPublic | BindingFlags.Static);
                Func<Func<string, object>, object> policyOf = item => { dynamic rules = new ExpandoObject(); rules.Item = item; dynamic p = new ExpandoObject(); p.Rules = rules; return (object)p; };
                Func<object, System.Collections.IList> read = policy => (System.Collections.IList)blockRules.Invoke(null, new[] { policy });
                if (read(policyOf(n => { throw new FileNotFoundException(); })).Count != 0) throw new Exception("a missing rule was found");
                if (read(policyOf(n => { throw new COMException("fixture", unchecked((int)0x80070002)); })).Count != 0) throw new Exception("0x80070002 was not 'no rule'");
                try { read(policyOf(n => { throw new COMException("fixture: RPC server unavailable", unchecked((int)0x800706BA)); })); throw new Exception("an unreadable rule read as empty"); }
                catch (TargetInvocationException ex) { if (!(ex.InnerException is COMException)) throw new Exception("unexpected failure: " + ex.InnerException); }
                dynamic rule = new ExpandoObject(); rule.RemoteAddresses = "192.0.2.1/255.255.255.255";
                var found = (List<KeyValuePair<string, object>>)read(policyOf(n => { if (n == Firewall.BlockRuleName) return (object)rule; throw new FileNotFoundException(); }));
                if (found.Count != 1 || found[0].Key != Firewall.BlockRuleName) throw new Exception("the rule of the current name was not read");
                return null;
            });
            test("firewall: a block adds to the rule as it is at the write, keeping a block made meanwhile and taking the new ports", () =>
            {
                dynamic rule = new ExpandoObject();
                rule.RemoteAddresses = "198.51.100.1/255.255.255.255,203.0.113.5/255.255.255.255"; rule.LocalPorts = "22"; rule.Enabled = false;
                bool added = false; var removed = new List<string>();
                Func<bool, object> policyOf = exists =>
                {
                    dynamic rules = new ExpandoObject();
                    rules.Item = (Func<string, object>)(n => { if (exists && n == Firewall.BlockRuleName) return (object)rule; throw new FileNotFoundException(); });
                    rules.Remove = (Action<string>)(n => removed.Add(n));
                    rules.Add = (Action<object>)(r => added = true);
                    dynamic p = new ExpandoObject(); p.Rules = rules; return (object)p;
                };
                // The agent read 198.51.100.1 alone; the Logs dialog added 203.0.113.5 since.
                Firewall.AddBlockedAddresses(policyOf(true), new[] { "192.0.2.7", "198.51.100.1" }, "22,2222");
                if ((string)rule.RemoteAddresses != "198.51.100.1,203.0.113.5,192.0.2.7" || (string)rule.LocalPorts != "22,2222" || !(bool)rule.Enabled)
                    throw new Exception("rule: " + (string)rule.RemoteAddresses + " ports " + (string)rule.LocalPorts);
                Firewall.AddBlockedAddresses(policyOf(true), new string[0], "2200");
                if ((string)rule.RemoteAddresses != "198.51.100.1,203.0.113.5,192.0.2.7" || (string)rule.LocalPorts != "2200") throw new Exception("a listener change did not reach the existing blocks");
                Firewall.AddBlockedAddresses(policyOf(false), new string[0], "22");
                if (added || removed.Count != 0) throw new Exception("an empty rule was written");
                return null;
            });
            test("agent: blocking defers on an unreadable rule, saves its schedule first, and a failed write adds no strike", () => Isolated(dir =>
            {
                var s = new AlertSettings { BlockThreshold = 10, OnFailedLogins = false };
                var now = new DateTime(2026, 10, 8, 12, 0, 0);
                var sources = new List<EventLogs.FailedSource> { new EventLogs.FailedSource { Address = "192.0.2.7", Count = 12, First = now, Last = now } };
                var peers = new HashSet<string>();
                // (a) The rule cannot be read: nothing is written.
                var st = new AgentState(); bool wrote = false;
                var add = Agent.ApplyBlocks(s, st, sources, now, "fixture", peers, "22", () => { throw new COMException("fixture", unchecked((int)0x800706BA)); }, (a, p) => wrote = true, null);
                if (add.Count != 0 || wrote || !st.BlockingDegradedReason.Contains("could not be read") || st.Blocks.Count != 0) throw new Exception("blocked from an unread rule");
                // (b) The schedule is saved before the firewall changes, and only the new address is handed to the merge.
                bool saved = false; List<string> written = null; string writtenPorts = null;
                add = Agent.ApplyBlocks(s, st, sources, now, "fixture", peers, "22,2222", () => new List<string> { "198.51.100.1" },
                    (a, p) => { if (!saved) throw new Exception("the firewall changed before the schedule was saved"); written = a.ToList(); writtenPorts = p; },
                    () => { if (st.Blocks["192.0.2.7"].Until != now.AddHours(1)) throw new Exception("checkpoint without the schedule"); saved = true; });
                if (string.Join(",", add) != "192.0.2.7" || written == null || string.Join(",", written) != "192.0.2.7" || writtenPorts != "22,2222" || st.BlockingDegradedReason != "")
                    throw new Exception("block: " + string.Join(",", add) + " written " + (written == null ? "nothing" : string.Join(",", written)));
                // (c) A failed write leaves the strikes as they were (saved again), so the next attempt is still a first block.
                st = new AgentState(); int checkpoints = 0;
                try { Agent.ApplyBlocks(s, st, sources, now, "fixture", peers, "22", () => new List<string>(), (a, p) => { throw new COMException("fixture", unchecked((int)0x800706BA)); }, () => checkpoints++); throw new Exception("the failed write was not reported"); }
                catch (COMException) { }
                if (st.Blocks.ContainsKey("192.0.2.7") || checkpoints != 2) throw new Exception("a strike for a block that never happened was kept (" + checkpoints + " checkpoints)");
                Agent.ApplyBlocks(s, st, sources, now.AddMinutes(1), "fixture", peers, "22", () => new List<string>(), (a, p) => { }, null);
                if (st.Blocks["192.0.2.7"].Strikes != 1 || st.Blocks["192.0.2.7"].Until != now.AddMinutes(1).AddHours(1)) throw new Exception("the retry escalated to strike " + st.Blocks["192.0.2.7"].Strikes);
                var earlier = new AgentState.BlockEntry { Until = DateTime.MinValue, Strikes = 1, LastStrike = now.AddDays(-1) };
                st = new AgentState(); st.Blocks["192.0.2.7"] = earlier;
                try { Agent.ApplyBlocks(s, st, sources, now, "fixture", peers, "22", () => new List<string>(), (a, p) => { throw new IOException("fixture"); }, null); }
                catch (IOException) { }
                var back = st.Blocks["192.0.2.7"];
                if (back.Strikes != 1 || back.LastStrike != now.AddDays(-1) || back.Until != DateTime.MinValue) throw new Exception("the earlier strike was not restored");
                return null;
            }));
            test("agent: a manual block or unblock ends the agent's timer, so its expiry never lifts it", () => Isolated(dir =>
            {
                var s = new AlertSettings { BlockThreshold = 10 };
                var now = new DateTime(2026, 10, 8, 12, 0, 0);
                var one = new List<EventLogs.FailedSource> { new EventLogs.FailedSource { Address = "198.51.100.9", Count = 12, First = now, Last = now } };
                var none = new HashSet<string>();
                var st = new AgentState();
                Agent.PlanBlocks(s, st, one, now, none, none, a => false);
                if (Agent.ClearTimers(st, new[] { "203.0.113.1" }) != 0 || st.Blocks["198.51.100.9"].Until != now.AddHours(1)) throw new Exception("an unrelated address ended a timer");
                // The dialog's Unblock passes the firewall's form of the address.
                if (Agent.ClearTimers(st, new[] { "198.51.100.9/255.255.255.255" }) != 1) throw new Exception("the timer was not found");
                var removed = new List<string>();
                Agent.LiftExpired(st, now.AddHours(2), a => removed.AddRange(a));
                if (removed.Count != 0) throw new Exception("expiry lifted a manual block");
                Agent.PlanBlocks(s, st, one, now.AddHours(3), none, none, a => false);
                if (st.Blocks["198.51.100.9"].Strikes != 2) throw new Exception("the strikes were not kept");
                st.Blocks["2001:db8::5"] = new AgentState.BlockEntry { Until = now.AddHours(1), Strikes = 1, LastStrike = now };
                if (Agent.ClearTimers(st, new[] { "2001:DB8:0:0::5/128" }) != 1) throw new Exception("an IPv6 address in another form was not matched");
                // The dialog's path: the firewall change and the timer, under the agent's lock.
                st = new AgentState(); st.Blocks["198.51.100.9"] = new AgentState.BlockEntry { Until = now.AddDays(7), Strikes = 3, LastStrike = now }; st.Save();
                bool changed = false;
                var warning = FailedLoginsDialog.ChangeBlocks(new[] { "198.51.100.9" }, () => changed = true);
                var loaded = AgentState.Load().Blocks["198.51.100.9"];
                if (warning != null || !changed || loaded.Until != DateTime.MinValue || loaded.Strikes != 3) throw new Exception("the dialog left the agent's timer: " + warning);
                return null;
            }));
            test("notifications: an exhausted alert keeps no credentials, and undelivered ones are kept 30 days, 200 per destination", () =>
            {
                var st = new AgentState(); var now = DateTime.UtcNow;
                var settings = new AlertSettings { SmtpHost = "smtp.example.com", From = "server@example.com", AdminTo = "admin@example.com", SmtpUser = "u", SmtpPassword = "fixture-password", Webhook = "https://example.com/hook?sig=fixture" };
                NotificationOutbox.Enqueue(st, settings, "fixture", "subject", "body", null, null, null, null, now);
                for (int i = 0; i < NotificationOutbox.MaxAttempts; i++)
                {
                    var at = now.AddDays(i + 1); NotificationItem claim;
                    while ((claim = NotificationOutbox.Claim(st, at)) != null) NotificationOutbox.Complete(st, claim.Id, claim.Lease, at, "fixture unavailable");
                }
                if (st.Notifications.Count != 2 || st.Notifications.Any(n => !n.Exhausted)) throw new Exception("the fixture did not exhaust both destinations");
                foreach (var n in st.Notifications)
                {
                    var stored = NotificationItem.Restore(n.Store());
                    if (n.Transport.SmtpPassword.Length > 0 || n.Transport.Webhook.Length > 0 || stored.Transport.SmtpPassword.Length > 0 || stored.Transport.Webhook.Length > 0 || stored.Text != "body")
                        throw new Exception("an exhausted alert kept its secrets or lost its text");
                }
                // An item exhausted by an earlier version still holds its transport in memory: it is stored without it.
                var old = new NotificationItem { Id = "old", Destination = "mail", Exhausted = true, Attempts = 12, Transport = settings };
                if (NotificationItem.Restore(old.Store()).Transport.SmtpPassword.Length > 0) throw new Exception("an older exhausted alert kept its password");
                st = new AgentState();
                for (int i = 0; i < 250; i++)
                    st.Notifications.Add(new NotificationItem { Id = "mail-" + i, Destination = "mail", Exhausted = true, Attempts = 12, CreatedUtc = now.AddMinutes(-i), NextUtc = now });
                for (int i = 0; i < 10; i++)
                    st.Notifications.Add(new NotificationItem { Id = "hook-" + i, Destination = "webhook", Exhausted = true, Attempts = 12, CreatedUtc = now.AddDays(-40), NextUtc = now });
                st.Notifications.Add(new NotificationItem { Id = "pending", Destination = "webhook", CreatedUtc = now.AddDays(-40), NextUtc = now.AddHours(1) });
                st.Notifications.Add(new NotificationItem { Id = "sent", Destination = "mail", Delivered = true, CreatedUtc = now, NextUtc = now });
                if (NotificationOutbox.Prune(st, now) != 60) throw new Exception("not 60 alerts given up");
                var exhausted = st.Notifications.Where(n => n.Exhausted).ToList();
                if (exhausted.Count != 200 || exhausted.Any(n => n.Destination != "mail") || exhausted.Any(n => n.CreatedUtc < now.AddMinutes(-199)))
                    throw new Exception(exhausted.Count + " exhausted alerts kept, not the newest 200 of mail");
                if (!st.Notifications.Any(n => n.Id == "pending") || !st.Notifications.Any(n => n.Id == "sent")) throw new Exception("a pending or delivered alert was dropped");
                var health = AgentHealth.From(st);
                if (st.NotificationsDiscarded != 60 || health.DiscardedNotifications != 60 || !MainForm.AgentHealthText(health, now).Contains("60 given up")) throw new Exception("the discarded alerts were not counted");
                return Isolated(dir =>
                {
                    // The agent's delivery run prunes, and the count is kept.
                    st.Notifications.Add(new NotificationItem { Id = "stale", Destination = "mail", Exhausted = true, Attempts = 12, CreatedUtc = now.AddDays(-31), NextUtc = now });
                    st.Save();
                    NotificationOutbox.Drain(item => { throw new Exception("fixture: nothing is due"); });
                    var loaded = AgentState.Load();
                    if (loaded.NotificationsDiscarded != 61 || loaded.Notifications.Any(n => n.Id == "stale")) throw new Exception("the delivery run did not prune, or lost the count");
                    return null;
                });
            });
            test("notifications: a sent alert waits for the state lock to record its delivery instead of going out again", () => Isolated(dir =>
            {
                var st = new AgentState();
                NotificationOutbox.Enqueue(st, new AlertSettings { Webhook = "https://example.com/hook" }, "fixture", "subject", "body", null, new List<string>(), null, null, DateTime.UtcNow);
                st.Save();
                Thread worker = null; Exception workerError = null; int sends = 0;
                using (var entered = new ManualResetEvent(false))
                {
                    NotificationOutbox.Drain(item =>
                    {
                        sends++;
                        if (worker != null) return;
                        // Another job takes the state lock while this alert is being sent, and keeps it for longer than a second.
                        worker = new Thread(() =>
                        {
                            try { if (!Agent.WithStateLock(Agent.StateLockName, 0, () => { entered.Set(); Thread.Sleep(2500); })) workerError = new Exception("the fixture job could not take the lock"); }
                            catch (Exception ex) { workerError = ex; }
                        });
                        worker.Start();
                        if (!entered.WaitOne(5000)) throw new Exception("the fixture job did not start");
                    });
                    if (worker != null) worker.Join();
                }
                if (workerError != null) throw workerError;
                st = AgentState.Load();
                var sent = st.Notifications.Single();
                if (sends != 1 || !sent.Delivered || sent.Attempts != 1) throw new Exception("the delivery was not recorded (sent " + sends + " time(s))");
                if (NotificationOutbox.Claim(st, DateTime.UtcNow.AddMinutes(4)) != null) throw new Exception("the delivered alert would be sent again");
                if (!Agent.TaskXml("d", "c", "a", false).Contains("T00:30:30</StartBoundary>")) throw new Exception("Daily starts with a Watch run");
                return null;
            }));
            test("notifications: a destination that failed in a run is not tried again in it, so the others get its turns", () => Isolated(dir =>
            {
                var settings = new AlertSettings { SmtpHost = "smtp.example.com", From = "server@example.com", AdminTo = "admin@example.com", Webhook = "https://example.com/hook" };
                var st = new AgentState(); var now = DateTime.UtcNow;
                for (int i = 0; i < 8; i++) NotificationOutbox.Enqueue(st, settings, "fixture", "subject " + i, "body", null, null, null, null, now);
                var first = NotificationOutbox.Claim(st, now);
                // The first event's webhook item is next in the queue now.
                var skipped = NotificationOutbox.Claim(st, now, new HashSet<string> { "webhook" });
                if (first.Destination != "mail" || skipped == null || skipped.Destination != "mail" || skipped.Subject != "subject 1") throw new Exception("a skipped destination was claimed");
                st = new AgentState();
                for (int i = 0; i < 8; i++) NotificationOutbox.Enqueue(st, settings, "fixture", "subject " + i, "body", null, null, null, null, now);
                st.Save();
                int mail = 0, hook = 0;
                NotificationOutbox.Drain(item => { if (item.Destination == "mail") mail++; else { hook++; throw new IOException("fixture hook down"); } });
                if (hook != 1 || mail != NotificationOutbox.MaxDeliveriesPerRun - 1) throw new Exception("mail " + mail + ", webhook " + hook);
                return null;
            }));
            test("monthly report: it states gaps, a late start and archive files it could not read", () =>
            {
                var from = new DateTime(2026, 9, 1); var to = new DateTime(2026, 10, 1);
                var j = new TransferJournalState { NotifyFromUtc = new DateTime(2026, 8, 1, 0, 0, 0, DateTimeKind.Utc) };
                if (Agent.ReportCaveats(j, from, to, new string[0]).Count != 0) throw new Exception("a complete month got a caveat");
                j.Gap = "The OpenSSH event log overwrote unprocessed events (records 5 through 9)."; j.GapUtc = from.ToUniversalTime().AddDays(3);
                var c = Agent.ReportCaveats(j, from, to, new string[0]);
                if (c.Count != 1 || !c[0].Contains("records 5 through 9")) throw new Exception("a gap in the month was not stated");
                j.GapUtc = from.ToUniversalTime().AddDays(-3);
                if (Agent.ReportCaveats(j, from, to, new string[0]).Count != 0) throw new Exception("a gap before the month was stated");
                j.NotifyFromUtc = from.ToUniversalTime().AddDays(10);
                c = Agent.ReportCaveats(j, from, to, new[] { "Reading transfers-2026-09.csv: in use" });
                if (c.Count != 2 || !c[0].Contains("began collecting") || !c[1].Contains("transfers-2026-09.csv")) throw new Exception("caveats: " + string.Join(" | ", c));
                var html = Transfers.ReportHtml(new List<TransferRecord>(), from, to, "SRV", null, new[] { "gap <b>&" });
                if (!html.Contains("<p class=warn>gap &lt;b&gt;&amp;</p>")) throw new Exception("the caveat is not in the report");
                return null;
            });
            test("failed logins: link-local addresses with a zone count, the values' fallback text is read, rejected keys are not counted", () =>
            {
                string user;
                if (EventLogs.FailedLoginAddress("sshd-session: Failed password for alice from fe80::1234:5678%12 port 5 ssh2", out user) != "fe80::1234:5678" || user != "alice") throw new Exception("zone id with a password failure");
                if (EventLogs.FailedLoginAddress("sshd: Invalid user bob from fe80::1%7 port 22", out user) != "fe80::1" || user != "bob") throw new Exception("zone id with an invalid user");
                // Owner decision: under LogLevel VERBOSE a legitimate client logs this for each key it offers before the right one.
                if (EventLogs.FailedLoginAddress("sshd-session: Failed publickey for alice from 192.0.2.14 port 4 ssh2: ED25519 SHA256:x", out user) != null) throw new Exception("a rejected key was counted");
                if (EventLogs.FailedLoginAddress(EventLogs.FallbackText(new object[] { "sshd-session", "Failed password for a from 192.0.2.16 port 1 ssh2" }), out user) != "192.0.2.16") throw new Exception("the fallback text was not read");
                // A logged-in peer appears with its zone in the TCP table, its failures without: it is still not blocked.
                var s = new AlertSettings { BlockThreshold = 10 };
                var src = new List<EventLogs.FailedSource> { new EventLogs.FailedSource { Address = "fe80::1", Count = 20, First = DateTime.Now, Last = DateTime.Now } };
                if (Agent.PlanBlocks(s, new AgentState(), src, DateTime.Now, new HashSet<string>(), new HashSet<string> { "fe80::1%7" }, a => false).Count != 0) throw new Exception("a logged-in link-local peer was blocked");
                return null;
            });
            test("failed logins: the scan counts failures, not events, so other lines cannot push older failures out", () =>
            {
                var t = new DateTime(2026, 10, 8, 12, 0, 0);
                var events = new List<KeyValuePair<string, LogEvent>>();
                for (int i = 0; i < 25000; i++)
                    events.Add(i % 2 == 0
                        ? new KeyValuePair<string, LogEvent>("sftp-server", new LogEvent { Time = t.AddSeconds(-i), Message = "open \"/in/a.csv\" flags WRITE,CREATE,TRUNCATE mode 0666" })
                        : new KeyValuePair<string, LogEvent>("sshd-session", new LogEvent { Time = t.AddSeconds(-i), Message = "Accepted publickey for bob from 192.0.2.50 port " + (1000 + i % 60000) + " ssh2" }));
                events.Add(new KeyValuePair<string, LogEvent>("sftp-server", new LogEvent { Time = t.AddSeconds(-25000), Message = "Failed password for x from 198.51.100.77 port 1 ssh2" }));
                for (int i = 0; i < 10; i++)
                    events.Add(new KeyValuePair<string, LogEvent>("sshd-session", new LogEvent { Time = t.AddSeconds(-25001 - i), Message = "Failed password for admin from 203.0.113.9 port " + (40000 + i) + " ssh2" }));
                bool truncated;
                var failures = EventLogs.CollectFailures(events, EventLogs.MaxFailures, TimeSpan.FromSeconds(30), out truncated);
                var sources = EventLogs.FailedByAddress(failures);
                if (truncated || sources.Count != 1 || sources[0].Address != "203.0.113.9" || sources[0].Count != 10) throw new Exception("counted: " + string.Join(", ", sources.Select(x => x.Address + " " + x.Count)));
                if (string.Join(",", Agent.PlanBlocks(new AlertSettings { BlockThreshold = 10 }, new AgentState(), sources, t, new HashSet<string>(), new HashSet<string>(), a => false)) != "203.0.113.9") throw new Exception("the slow attacker was not blocked");
                failures = EventLogs.CollectFailures(events, 5, TimeSpan.FromSeconds(30), out truncated);
                if (!truncated || failures.Count != 5) throw new Exception("a cut-short scan was not reported");
                var query = EventLogs.FailureQuery(TimeSpan.FromMinutes(10), true);
                if (!query.Contains("Data[@Name='process']!='sftp-server'") || !query.Contains("timediff(@SystemTime) <= 600000") || EventLogs.FailureQuery(TimeSpan.FromMinutes(10), false).Contains("sftp-server"))
                    throw new Exception("query: " + query);
                return null;
            });
            test("firewall: Get and Apply pick the same rule when both names exist; a failed query is not 'no rule'", () =>
            {
                Func<int, string, AuditInfrastructureTests.FakeFirewallRule> rule = (direction, name) => new AuditInfrastructureTests.FakeFirewallRule { Name = name, Direction = direction };
                // The managed-name rule is newer, so COM enumerates it first; Get has always shown the Preview rule.
                var policy = new FakePolicy();
                var preview = rule(1, Firewall.RuleName);
                policy.Rules.Items.AddRange(new object[] { rule(1, Firewall.ManagedRuleName), rule(2, Firewall.RuleName), preview });
                if (!ReferenceEquals(Firewall.SelectManaged(policy), preview) || !ReferenceEquals(Firewall.FindInbound(policy, Firewall.RuleName), preview)) throw new Exception("Apply would change a rule Get does not show");
                if (Firewall.CaptureRule(Firewall.SelectManaged(policy)).Attributes["Direction"] != "1") throw new Exception("an outbound rule was chosen");
                var managed = rule(1, Firewall.ManagedRuleName);
                policy = new FakePolicy(); policy.Rules.Items.Add(managed);
                if (!ReferenceEquals(Firewall.SelectManaged(policy), managed)) throw new Exception("the managed-name rule alone was not found");
                if (Firewall.SelectManaged(new FakePolicy()) != null) throw new Exception("a rule was found in an empty policy");
                policy.Rules.ItemError = new COMException("fixture: RPC server unavailable", unchecked((int)0x800706BA));
                try { Firewall.SelectManaged(policy); throw new Exception("a failed query read as 'no rule'"); }
                catch (COMException) { }
                return null;
            });
            test("webhooks: bare addresses and host names chosen by clients are not links; IPv4 addresses stay readable", () =>
            {
                var hostile = "accounts tried: https://evil.example/unblock-now.png, www.phish.example, payload.zip; seen from 192.0.2.7";
                foreach (var teams in new[] { false, true })
                {
                    var body = Agent.HookBody(teams, "Blocked 192.0.2.7 on SRV", hostile);
                    foreach (var link in new[] { "https://evil", "evil.example", "www.phish", "phish.example", "payload.zip" })
                        if (body.Contains(link)) throw new Exception((teams ? "Teams" : "Slack") + " body still links " + link + ": " + body);
                    if (!body.Contains("Blocked 192.0.2.7") || !body.Contains("from 192.0.2.7")) throw new Exception("an IPv4 address became unreadable: " + body);
                }
                return null;
            });
            test("webhooks: a redirect is not followed, so the page it leads to cannot take the alert as delivered (servers on 127.0.0.1)", () =>
            {
                var hook = new TcpListener(IPAddress.Loopback, 0); var landing = new TcpListener(IPAddress.Loopback, 0);
                hook.Start(); landing.Start();
                bool reached = false;
                try
                {
                    int landingPort = ((IPEndPoint)landing.LocalEndpoint).Port;
                    var redirecting = new Thread(() =>
                    {
                        try { using (var c = hook.AcceptTcpClient()) Answer(c, "302 Found", "Location: http://127.0.0.1:" + landingPort + "/\r\n"); } catch { }
                    }) { IsBackground = true };
                    var page = new Thread(() =>
                    {
                        try
                        {
                            var until = DateTime.UtcNow.AddSeconds(5);
                            while (!landing.Pending() && DateTime.UtcNow < until) Thread.Sleep(20);
                            if (!landing.Pending()) return;
                            reached = true;
                            using (var c = landing.AcceptTcpClient()) Answer(c, "200 OK", "");
                        }
                        catch { }
                    }) { IsBackground = true };
                    redirecting.Start(); page.Start();
                    try
                    {
                        Agent.SendHook(new AlertSettings { Webhook = "http://127.0.0.1:" + ((IPEndPoint)hook.LocalEndpoint).Port + "/hook", WebhookTeams = false }, "subject", "text");
                        throw new Exception("a redirect counted as delivered");
                    }
                    catch (WebException) { }
                    Thread.Sleep(1000);
                    if (reached || landing.Pending()) throw new Exception("the redirect was followed");
                    redirecting.Join(5000);
                }
                finally { hook.Stop(); landing.Stop(); }
                return null;
            });
        }

        /// <summary>Agent storage (state, log, archive) in a scratch folder of its own, as AuditAgentTests does.</summary>
        private static string Isolated(Func<string, string> body)
        {
            var previous = Ssh.ConfigDirOverride;
            var directory = Path.Combine(Path.GetTempPath(), "pn-agent-followup-" + Guid.NewGuid().ToString("N"));
            try
            {
                Ssh.ConfigDirOverride = directory;
                using (new AuditAgentTests.ScratchStorage(directory))
                {
                    // Agent.Note would otherwise create the folder with administrator-only permissions.
                    Directory.CreateDirectory(AlertSettings.Dir);
                    return body(directory);
                }
            }
            finally { Ssh.ConfigDirOverride = previous; if (Directory.Exists(directory)) Directory.Delete(directory, true); }
        }

        /// <summary>Reads one HTTP request and answers it with the status, the extra header lines and no body.</summary>
        private static void Answer(TcpClient client, string status, string headers)
        {
            client.ReceiveTimeout = 10000;
            var s = client.GetStream();
            var head = new StringBuilder(); int b;
            while (!head.ToString().EndsWith("\r\n\r\n") && (b = s.ReadByte()) >= 0) head.Append((char)b);
            var m = Regex.Match(head.ToString(), @"Content-Length:\s*(\d+)", RegexOptions.IgnoreCase);
            int length = m.Success ? int.Parse(m.Groups[1].Value) : 0, read = 0;
            var body = new byte[length];
            while (read < length) { int n = s.Read(body, read, length - read); if (n <= 0) break; read += n; }
            var reply = Encoding.ASCII.GetBytes("HTTP/1.1 " + status + "\r\n" + headers + "Content-Length: 0\r\nConnection: close\r\n\r\n");
            s.Write(reply, 0, reply.Length);
        }

        /// <summary>A firewall policy for Firewall.FindInbound: Rules.Item(name) as COM answers it, and the rules in enumeration order.</summary>
        internal sealed class FakePolicy { public FakeRules Rules = new FakeRules(); }

        internal sealed class FakeRules : System.Collections.IEnumerable
        {
            public readonly List<object> Items = new List<object>();
            public Exception ItemError;
            public object Item(string name)
            {
                if (ItemError != null) throw ItemError;
                var found = Items.Cast<AuditInfrastructureTests.FakeFirewallRule>().FirstOrDefault(r => r.Name == name);
                if (found == null) throw new FileNotFoundException("fixture: no rule " + name);
                return found;
            }
            public System.Collections.IEnumerator GetEnumerator() { return Items.GetEnumerator(); }
        }
    }
}

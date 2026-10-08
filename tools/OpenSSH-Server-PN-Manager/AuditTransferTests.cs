using System;
using System.Linq;
using System.IO;
using System.Collections.Generic;

namespace OpenSSHServerPNManager
{
    internal static class AuditTransferTests
    {
        internal static void Run(Action<string, Func<string>> test, string tmpDir)
        {
            using (new AuditAgentTests.ScratchStorage(tmpDir)) RunTests(test, tmpDir);
        }

        private static void RunTests(Action<string, Func<string>> test, string tmpDir)
        {
            test("transfers: every batch split preserves session, empty-upload and refusal context", () =>
            {
                var events = new[] { E("session opened for local user acme from [203.0.113.7]"),
                    E("open \"/empty\" flags WRITE,CREATE,TRUNCATE mode 0666"), E("close \"/empty\" bytes read 0 written 0"),
                    E("open \"/denied\" flags WRITE,CREATE,TRUNCATE mode 0666"), E("request 2: sent status 3"),
                    E("sent status Permission denied"), E("forced close \"/partial\" bytes read 12 written 42") };
                for (int i = 0; i < events.Length; i++) events[i].RecordId = i + 1;
                var expected = Transfers.Parse(events).Select(Transfers.CsvLine).ToArray();
                for (int split = 0; split <= events.Length; split++)
                {
                    var state = new Transfers.ParserState();
                    var actual = Transfers.Parse(events.Take(split), state);
                    state = Transfers.ParserState.Restore(state.Store());
                    actual.AddRange(Transfers.Parse(events.Skip(split), state));
                    if (!actual.Select(Transfers.CsvLine).SequenceEqual(expected)) throw new Exception("batch split " + split + " lost context");
                }
                return null;
            });
            test("transfers: agent journal survives process and midnight boundaries without losing or replaying uploads", () =>
            {
                var old = Ssh.ConfigDirOverride;
                try
                {
                    Ssh.ConfigDirOverride = Path.Combine(tmpDir, "transfer-journal");
                    var clock = new DateTime(2026, 10, 1, 0, 1, 0);
                    var source = new FixtureSource();
                    source.Events.Add(E("session opened for local user acme from [203.0.113.7]"));
                    source.Events.Add(E("open \"/midnight\" flags WRITE,CREATE,TRUNCATE mode 0666"));
                    for (int i = 0; i < source.Events.Count; i++) { source.Events[i].RecordId = i + 1; source.Events[i].Time = clock.AddMinutes(-2); }
                    var settings = new AlertSettings(); var partners = new HashSet<string> { "acme" }; var st = new AgentState();
                    Agent.CollectTransfers(settings, st, clock.AddMinutes(-1), source, partners); st.Save();
                    source.Events.Add(E("close \"/midnight\" bytes read 0 written 0")); source.Events[2].RecordId = 3; source.Events[2].Time = clock;
                    st = AgentState.Load(); Agent.CollectTransfers(settings, st, clock, source, partners); st.Save();
                    var saved = TransferArchive.Read(clock.Date, clock.Date.AddDays(1));
                    if (saved.Count != 1 || saved[0].Bytes != 0 || saved[0].Address != "203.0.113.7" || saved[0].EventRecordId != 3)
                        throw new Exception("journal/archive lost the empty transfer, address, or event identity");
                    st = AgentState.Load(); Agent.CollectTransfers(settings, st, clock.AddMinutes(1), source, partners); st.Save();
                    if (st.Pending["acme"].Count != 1 || TransferArchive.Read(clock.Date, clock.Date.AddDays(1)).Count != 1)
                        throw new Exception("replaying a committed batch duplicated history or pending notifications");
                    // Clearing the channel reuses IDs. A new event remains distinct even with the same payload.
                    source.Generation = "replacement"; source.Events.Clear();
                    source.Events.Add(E("close \"/midnight\" bytes read 0 written 42")); source.Events[0].RecordId = 1; source.Events[0].Time = clock.AddMinutes(2);
                    Agent.CollectTransfers(settings, st, clock.AddMinutes(2), source, partners); st.Save();
                    if (st.Journal.Gap.Length == 0 || st.Journal.LastRecordId != 1 || st.Pending["acme"].Count != 2)
                        throw new Exception("log replacement did not resume with a distinct transfer and visible gap");
                    return null;
                }
                finally { Ssh.ConfigDirOverride = old; }
            });
            test("transfers: rollover distinguishes consumed context from missing events", () =>
            {
                var st = new TransferJournalState { LastRecordId = 10, LastIdentity = "anchor", Generation = "one" };
                Transfers.Parse(new[] { E("session opened for local user acme from [203.0.113.7]") }, st.Parser);
                TransferJournal.Prepare(st, new TransferJournal.Snapshot { Generation = "one", Oldest = 11, Newest = 12 }, DateTime.UtcNow);
                if (st.Gap.Length != 0 || st.Parser.Address.Count != 1) throw new Exception("ordinary rollover discarded retained session context");
                TransferJournal.Prepare(st, new TransferJournal.Snapshot { Generation = "one", Oldest = 13, Newest = 15 }, DateTime.UtcNow);
                if (!st.Gap.Contains("overwrote") || st.Parser.Address.Count != 0 || st.LastRecordId != 10)
                    throw new Exception("missing events were not surfaced, or stale PID context survived the gap");
                st.LastRecordId = 14; st.LastIdentity = "previous";
                TransferJournal.Prepare(st, new TransferJournal.Snapshot { Generation = "one", Oldest = 1, Newest = 20, CheckpointIdentity = "replacement" }, DateTime.UtcNow);
                if (st.LastRecordId != 0 || !st.Gap.Contains("replaced")) throw new Exception("reset with reused record IDs was not detected");
                return null;
            });
            test("transfers: GUI range reuses saved open context after rollover before the next watch run", () =>
            {
                var st = new TransferJournalState { LastRecordId = 2, LastIdentity = "open", Generation = "one" };
                Transfers.Parse(new[] { E("session opened for local user acme from [203.0.113.7]"), E("open \"/empty\" flags WRITE,CREATE,TRUNCATE mode 0666") }, st.Parser);
                var close = E("close \"/empty\" bytes read 0 written 0"); close.RecordId = 3; close.Generation = "one";
                var source = new TransferJournal.Snapshot { Oldest = 3, Newest = 3, Generation = "one" };
                var records = Transfers.ParseForRange(new List<Transfers.SftpEvent> { close }, close.Time, close.Time.AddMinutes(1), st, source);
                if (records.Count != 1 || records[0].Address != "203.0.113.7" || st.Parser.Active[123].Count != 1)
                    throw new Exception("the GUI lost an empty upload or consumed the watch's parser state");
                return null;
            });
            test("transfers: a log change during a read cannot advance the durable journal", () =>
            {
                var old = Ssh.ConfigDirOverride;
                try
                {
                    Ssh.ConfigDirOverride = Path.Combine(tmpDir, "transfer-interrupted");
                    var st = new AgentState(); st.Save();
                    var source = new FixtureSource { Valid = false }; var e = E("close \"/a\" bytes read 0 written 1"); e.RecordId = 1; source.Events.Add(e);
                    bool rejected = false;
                    try { Agent.CollectTransfers(new AlertSettings { OnUploads = false }, st, e.Time, source); }
                    catch (InvalidOperationException) { rejected = true; }
                    if (!rejected || AgentState.Load().Journal.LastRecordId != 0 || Directory.Exists(TransferArchive.Dir))
                        throw new Exception("a changed event stream was committed");
                    return null;
                }
                finally { Ssh.ConfigDirOverride = old; }
            });
            test("transfers: legacy archive migration and GUI merge never inflate or collapse repeated events", () =>
            {
                var old = Ssh.ConfigDirOverride;
                try
                {
                    Ssh.ConfigDirOverride = Path.Combine(tmpDir, "transfer-upgrade"); Directory.CreateDirectory(TransferArchive.Dir);
                    var a = E("close \"/same\" bytes read 0 written 42"); var b = E("close \"/same\" bytes read 0 written 42"); a.RecordId = 1; b.RecordId = 2;
                    var current = Transfers.Parse(new[] { a, b });
                    var legacy = Transfers.FromCsv("2026-09-29 00:00:00,acme,,upload,/same,42,");
                    if (Transfers.Merge(new List<TransferRecord> { legacy }, current).Count != 2) throw new Exception("GUI merge inflated or collapsed legacy history");
                    var file = TransferArchive.FileOf(a.Time);
                    File.WriteAllText(file, "Time,Account,Address,Action,File,Bytes,Detail\r\n2026-09-29 00:00:00,acme,,upload,/same,42,\r\n");
                    if (Agent.Archive(current) != 1 || Agent.Archive(current) != 0) throw new Exception("archive migration/replay count is incorrect");
                    var records = TransferArchive.Read(a.Time.Date, a.Time.Date.AddDays(1));
                    if (records.Count != 2 || records.Any(r => r.EventIdentity.Length == 0)) throw new Exception("archive failed to acquire durable event identities");
                    return null;
                }
                finally { Ssh.ConfigDirOverride = old; }
            });
            test("transfers: archive retains distinct same-second transfers and replay is idempotent", () =>
            {
                var old = Ssh.ConfigDirOverride;
                try
                {
                    Ssh.ConfigDirOverride = Path.Combine(tmpDir, "transfer-identity");
                    var first = E("close \"/same\" bytes read 0 written 42");
                    var second = E("close \"/same\" bytes read 0 written 42");
                    second.Time = first.Time.AddTicks(1000); second.Pid++;
                    var records = Transfers.Parse(new[] { first, second });
                    if (Agent.Archive(records) != 2) throw new Exception("archive merged two separate transfers within the same second");
                    if (Agent.Archive(records) != 0 || TransferArchive.Read(first.Time.Date, first.Time.Date.AddDays(1)).Count != 2)
                        throw new Exception("archive replay changed the transfer count");
                    return null;
                }
                finally { Ssh.ConfigDirOverride = old; }
            });
            test("transfers: verbose and debug explanations preserve open refusals", () =>
            {
                var records = Transfers.Parse(new[] {
                    E("open \"/a\" flags WRITE,CREATE,TRUNCATE mode 0666"),
                    E("Refusing open request in read-only mode"),
                    E("request 3: sent status 3"), E("sent status Permission denied") });
                if (records.Count != 1 || records[0].Action != TransferRecord.Refused || records[0].File != "/a")
                    throw new Exception("verbose open refusal missing");
                return null;
            });
            test("transfers: concurrent empty uploads keep their own open flags", () =>
            {
                var records = Transfers.Parse(new[] {
                    E("open \"/a\" flags WRITE,CREATE,TRUNCATE mode 0666"),
                    E("open \"/b\" flags WRITE,CREATE,TRUNCATE mode 0666"),
                    E("close \"/a\" bytes read 0 written 0"),
                    E("close \"/b\" bytes read 0 written 0") });
                if (records.Count != 2 || records.Any(r => r.Action != TransferRecord.Upload))
                    throw new Exception("expected two empty uploads; got " + records.Count);
                return null;
            });
            test("transfers: interrupted sessions retain forced-close byte counts", () =>
            {
                var records = Transfers.Parse(new[] { E("forced close \"/partial\" bytes read 0 written 8192") });
                if (records.Count != 1 || records[0].Bytes != 8192 || records[0].Action != TransferRecord.Upload)
                    throw new Exception("forced-close upload missing");
                return null;
            });
            test("transfers: a refused directory operation is not an upload refusal", () =>
            {
                var records = Transfers.Parse(new[] {
                    E("open \"/a\" flags WRITE,CREATE,TRUNCATE mode 0666"),
                    E("opendir \"/private\""), E("sent status Permission denied"),
                    E("close \"/a\" bytes read 0 written 0") });
                if (records.Count != 1 || records[0].Action != TransferRecord.Upload)
                    throw new Exception("unrelated refusal consumed the active upload: " + string.Join(",", records.Select(r => r.Action)));
                return null;
            });
        }

        private sealed class FixtureSource : TransferJournal.EventSource
        {
            internal readonly List<Transfers.SftpEvent> Events = new List<Transfers.SftpEvent>();
            internal string Generation = "fixture";
            internal bool Valid = true;
            public TransferJournal.Snapshot Inspect(long checkpoint)
            {
                var anchor = Events.FirstOrDefault(e => e.RecordId == checkpoint);
                return new TransferJournal.Snapshot { Generation = Generation, Oldest = Events.Count == 0 ? 0 : Events.Min(e => e.RecordId),
                    Newest = Events.Count == 0 ? 0 : Events.Max(e => e.RecordId), CheckpointIdentity = anchor == null ? "" : anchor.Identity };
            }
            public TransferJournal.Batch Read(long after, TransferJournal.Snapshot snapshot, DateTime now)
            {
                var batch = new TransferJournal.Batch();
                foreach (var e in Events.Where(e => e.RecordId > after && e.RecordId <= snapshot.Newest))
                {
                    e.Generation = Generation; batch.Events.Add(e); batch.LastRecordId = e.RecordId;
                    batch.LastIdentity = e.Identity; batch.LastEventUtc = e.Time.ToUniversalTime();
                }
                return batch;
            }
            public bool Verify(TransferJournal.Snapshot snapshot, TransferJournal.Batch batch) { return Valid && snapshot.Generation == Generation; }
        }

        private static Transfers.SftpEvent E(string text)
        {
            return new Transfers.SftpEvent { Time = new DateTime(2026, 9, 29), Pid = 123, Text = "user: acme: " + text + " [postauth]" };
        }
    }
}

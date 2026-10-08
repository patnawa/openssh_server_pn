using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Linq;
using System.Threading;

namespace OpenSSHServerPNManager
{
    /// <summary>Durable stream cursor and parser context. AgentState commits it with pending upload notifications.</summary>
    internal sealed class TransferJournalState
    {
        public long LastRecordId;
        public string Generation = "", LastIdentity = "", Gap = "";
        public DateTime? CheckedUtc, LastEventUtc, GapUtc, NotifyFromUtc;
        /// <summary>The first run of the journal; none when an earlier version had archived transfers already (its start is unknown).</summary>
        public DateTime? StartedUtc;
        public Transfers.ParserState Parser = new Transfers.ParserState();
        public long Backlog;

        internal void Save(IDictionary<string, string> d)
        {
            d["journal.record"] = LastRecordId.ToString(CultureInfo.InvariantCulture);
            d["journal.generation"] = Generation; d["journal.identity"] = LastIdentity;
            d["journal.parser"] = Parser.Store(); d["journal.gap"] = Gap;
            d["journal.backlog"] = Backlog.ToString(CultureInfo.InvariantCulture);
            d["journal.checked"] = CheckedUtc.HasValue ? CheckedUtc.Value.ToString("o") : "";
            d["journal.event"] = LastEventUtc.HasValue ? LastEventUtc.Value.ToString("o") : "";
            d["journal.gapat"] = GapUtc.HasValue ? GapUtc.Value.ToString("o") : "";
            d["journal.notifyfrom"] = NotifyFromUtc.HasValue ? NotifyFromUtc.Value.ToString("o") : "";
            d["journal.started"] = StartedUtc.HasValue ? StartedUtc.Value.ToString("o") : "";
        }
        internal static TransferJournalState Load(IDictionary<string, string> d)
        {
            var st = new TransferJournalState(); string s; long n; DateTime t;
            if (d.TryGetValue("journal.record", out s) && long.TryParse(s, out n)) st.LastRecordId = n;
            if (d.TryGetValue("journal.generation", out s)) st.Generation = s;
            if (d.TryGetValue("journal.identity", out s)) st.LastIdentity = s;
            if (d.TryGetValue("journal.gap", out s)) st.Gap = s;
            if (d.TryGetValue("journal.backlog", out s) && long.TryParse(s, out n)) st.Backlog = n;
            if (d.TryGetValue("journal.checked", out s) && DateTime.TryParse(s, null, DateTimeStyles.RoundtripKind, out t)) st.CheckedUtc = t;
            if (d.TryGetValue("journal.event", out s) && DateTime.TryParse(s, null, DateTimeStyles.RoundtripKind, out t)) st.LastEventUtc = t;
            if (d.TryGetValue("journal.gapat", out s) && DateTime.TryParse(s, null, DateTimeStyles.RoundtripKind, out t)) st.GapUtc = t;
            if (d.TryGetValue("journal.notifyfrom", out s) && DateTime.TryParse(s, null, DateTimeStyles.RoundtripKind, out t)) st.NotifyFromUtc = t;
            if (d.TryGetValue("journal.started", out s) && DateTime.TryParse(s, null, DateTimeStyles.RoundtripKind, out t)) st.StartedUtc = t;
            if (d.TryGetValue("journal.parser", out s)) st.Parser = Transfers.ParserState.Restore(s);
            return st;
        }
    }

    internal static class TransferJournal
    {
        internal sealed class Snapshot
        {
            public string Generation = "", CheckpointIdentity = "";
            public long Oldest, Newest;
        }
        internal sealed class Batch
        {
            public readonly List<Transfers.SftpEvent> Events = new List<Transfers.SftpEvent>();
            public long LastRecordId; public string LastIdentity = ""; public DateTime? LastEventUtc;
        }
        internal interface EventSource
        {
            Snapshot Inspect(long checkpoint);
            Batch Read(long after, Snapshot snapshot, DateTime now);
            bool Verify(Snapshot snapshot, Batch batch);
        }

        internal sealed class WindowsEventSource : EventSource
        {
            public Snapshot Inspect(long checkpoint) { return TransferJournal.Inspect(checkpoint); }
            public Batch Read(long after, Snapshot snapshot, DateTime now) { return ReadBatch(after, snapshot, now); }
            public bool Verify(Snapshot snapshot, Batch batch)
            { return LogGeneration() == snapshot.Generation && (batch.LastRecordId == 0 || Anchor(batch.LastRecordId) == batch.LastIdentity); }
        }

        internal static string LogGeneration()
        {
            var info = EventLogSession.GlobalSession.GetLogInformation(EventLogs.LogName, PathType.LogName);
            return info.CreationTime.HasValue ? info.CreationTime.Value.ToUniversalTime().Ticks.ToString(CultureInfo.InvariantCulture) : "unknown";
        }

        private static string Identity(EventRecord r) { return Transfers.Fingerprint(r.ToXml()); }
        private static EventRecord Edge(bool last)
        {
            using (var reader = new EventLogReader(new EventLogQuery(EventLogs.LogName, PathType.LogName) { ReverseDirection = last }))
                return reader.ReadEvent();
        }
        private static string Anchor(long id)
        {
            if (id == 0) return "";
            using (var reader = new EventLogReader(new EventLogQuery(EventLogs.LogName, PathType.LogName,
                "*[System[EventRecordID=" + id.ToString(CultureInfo.InvariantCulture) + "]]")))
            using (var r = reader.ReadEvent()) return r == null ? "" : Identity(r);
        }
        private static Snapshot Inspect(long checkpoint)
        {
            var snapshot = new Snapshot { Generation = LogGeneration(), CheckpointIdentity = Anchor(checkpoint) };
            using (var first = Edge(false)) snapshot.Oldest = first == null ? 0 : first.RecordId ?? 0;
            using (var last = Edge(true)) snapshot.Newest = last == null ? 0 : last.RecordId ?? 0;
            return snapshot;
        }

        /// <summary>Prepare the cursor using a captured log range and checkpoint identity. Normal rollover preserves active sessions.</summary>
        internal static long Prepare(TransferJournalState st, Snapshot log, DateTime utcNow)
        {
            string gap = null;
            bool reset = st.LastRecordId > 0 &&
                (log.Newest < st.LastRecordId || (st.Generation.Length > 0 && st.Generation != log.Generation) ||
                 (log.CheckpointIdentity.Length > 0 && st.LastIdentity.Length > 0 && log.CheckpointIdentity != st.LastIdentity));
            if (reset) gap = "The OpenSSH event log was cleared or replaced. Earlier unarchived events may be unavailable.";
            else if (st.LastRecordId > 0 && log.Oldest > st.LastRecordId + 1)
                gap = "The OpenSSH event log overwrote unprocessed events (records " + (st.LastRecordId + 1) + " through " + (log.Oldest - 1) + ").";
            else if (st.LastRecordId > 0 && log.CheckpointIdentity.Length == 0 && log.Oldest <= st.LastRecordId && log.Newest >= st.LastRecordId)
                gap = "The saved OpenSSH event checkpoint is missing from the log; retained history will be replayed.";
            if (gap != null)
            {
                st.Gap = gap; st.GapUtc = utcNow; st.Parser.Clear();
                // Replay retained history after replacement, but don't replay already-consumed records on a wrap.
                if (reset || log.Oldest <= st.LastRecordId) { st.LastRecordId = 0; st.LastIdentity = ""; }
            }
            st.Generation = log.Generation;
            return st.LastRecordId;
        }

        internal static List<TransferRecord> Apply(TransferJournalState st, Snapshot snapshot, Batch batch, DateTime utcNow)
        {
            var records = Transfers.Parse(batch.Events, st.Parser);
            if (batch.LastRecordId > 0)
            {
                st.LastRecordId = batch.LastRecordId; st.LastIdentity = batch.LastIdentity;
                st.LastEventUtc = batch.LastEventUtc;
            }
            st.CheckedUtc = utcNow;
            st.Backlog = Math.Max(0, snapshot.Newest - st.LastRecordId);
            return records;
        }

        /// <summary>Reads a bounded, verified prefix. Archive and AgentState must commit before the next call.</summary>
        internal static List<TransferRecord> Read(TransferJournalState st, DateTime now, EventSource source = null)
        {
            source = source ?? new WindowsEventSource();
            var snapshot = source.Inspect(st.LastRecordId);
            long after = Prepare(st, snapshot, now.ToUniversalTime());
            var batch = source.Read(after, snapshot, now);
            // A clear or sufficiently fast rollover during reading must not commit a cursor from a different stream.
            if (!source.Verify(snapshot, batch))
                throw new InvalidOperationException("The OpenSSH event log changed while reading. The checkpoint was not advanced; the next run will retry.");
            return Apply(st, snapshot, batch, now.ToUniversalTime());
        }

        private static Batch ReadBatch(long after, Snapshot snapshot, DateTime now)
        {
            var batch = new Batch();
            var xpath = "*[System[EventRecordID>" + after.ToString(CultureInfo.InvariantCulture) + " and EventRecordID<=" + snapshot.Newest.ToString(CultureInfo.InvariantCulture) + "]]";
            using (var reader = new EventLogReader(new EventLogQuery(EventLogs.LogName, PathType.LogName, xpath)))
            {
                EventRecord r; int count = 0;
                while (count++ < 25000 && (r = reader.ReadEvent()) != null)
                {
                    using (r)
                    {
                        batch.LastRecordId = r.RecordId ?? batch.LastRecordId;
                        batch.LastIdentity = Identity(r); batch.LastEventUtc = r.TimeCreated.HasValue ? r.TimeCreated.Value.ToUniversalTime() : (DateTime?)null;
                        if (r.Properties.Count < 2 || Convert.ToString(r.Properties[0].Value) != "sftp-server") continue;
                        batch.Events.Add(new Transfers.SftpEvent { Time = r.TimeCreated ?? now, Pid = r.ProcessId ?? 0,
                            Text = Convert.ToString(r.Properties[1].Value).Trim(), RecordId = r.RecordId ?? 0, Generation = snapshot.Generation });
                    }
                }
            }
            return batch;
        }
    }
}

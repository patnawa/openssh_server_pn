using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;

namespace OpenSSHServerPNManager
{
    /// <summary>One destination's delivery. Payload and route survive changes to alert settings; transport secrets remain DPAPI protected.</summary>
    internal sealed class NotificationItem
    {
        public string Id = "", Source = "", Destination = "", Subject = "", Text = "", Html = "", Recipients = "", AttachmentName = "", AttachmentText = "";
        public string Lease = "", LastError = "";
        public int Attempts; public bool Delivered, Exhausted;
        public DateTime CreatedUtc, NextUtc, LeaseUntilUtc;
        public AlertSettings Transport = new AlertSettings();

        internal string Store()
        {
            using (var bytes = new MemoryStream())
            using (var w = new BinaryWriter(bytes, Encoding.UTF8))
            {
                w.Write(1);
                foreach (var s in new[] { Id, Source, Destination, Subject, Text, Html, Recipients, AttachmentName, AttachmentText, Lease, LastError }) w.Write(s ?? "");
                w.Write(Attempts); w.Write(Delivered); w.Write(Exhausted);
                w.Write(CreatedUtc.Ticks); w.Write(NextUtc.Ticks); w.Write(LeaseUntilUtc.Ticks);
                // An exhausted item is sent again only by RetryFailed, with the settings of then: keep no sealed secrets for it.
                var t = Exhausted ? new AlertSettings() : Transport;
                foreach (var s in new[] { t.SmtpHost, t.SmtpUser, Secret.Seal(t.SmtpPassword), t.From, Secret.Seal(t.Webhook) }) w.Write(s ?? "");
                w.Write(t.SmtpPort); w.Write(t.SmtpTls); w.Write(t.WebhookTeams);
                w.Flush(); return Convert.ToBase64String(bytes.ToArray());
            }
        }
        internal static NotificationItem Restore(string stored)
        {
            using (var bytes = new MemoryStream(Convert.FromBase64String(stored)))
            using (var r = new BinaryReader(bytes, Encoding.UTF8))
            {
                if (r.ReadInt32() != 1) throw new InvalidDataException("Unsupported notification state.");
                var n = new NotificationItem { Id = r.ReadString(), Source = r.ReadString(), Destination = r.ReadString(), Subject = r.ReadString(),
                    Text = r.ReadString(), Html = r.ReadString(), Recipients = r.ReadString(), AttachmentName = r.ReadString(), AttachmentText = r.ReadString(), Lease = r.ReadString(), LastError = r.ReadString(),
                    Attempts = r.ReadInt32(), Delivered = r.ReadBoolean(), Exhausted = r.ReadBoolean(),
                    CreatedUtc = new DateTime(r.ReadInt64(), DateTimeKind.Utc), NextUtc = new DateTime(r.ReadInt64(), DateTimeKind.Utc), LeaseUntilUtc = new DateTime(r.ReadInt64(), DateTimeKind.Utc) };
                n.Transport.SmtpHost = r.ReadString(); n.Transport.SmtpUser = r.ReadString(); n.Transport.SmtpPassword = Secret.Open(r.ReadString());
                n.Transport.From = r.ReadString(); n.Transport.Webhook = Secret.Open(r.ReadString());
                n.Transport.SmtpPort = r.ReadInt32(); n.Transport.SmtpTls = r.ReadBoolean(); n.Transport.WebhookTeams = r.ReadBoolean();
                if (bytes.Position != bytes.Length) throw new InvalidDataException("Trailing notification state.");
                return n;
            }
        }
    }

    internal static class NotificationOutbox
    {
        internal const int MaxAttempts = 12, MaxDeliveriesPerRun = 8;
        /// <summary>Undelivered alerts kept for "Retry failed deliveries": the newest 200 of each destination, for 30 days.</summary>
        internal const int MaxExhaustedPerDestination = 200;
        internal static readonly TimeSpan ExhaustedRetention = TimeSpan.FromDays(30);

        internal static void Enqueue(AgentState st, AlertSettings settings, string source, string subject, string text,
            string html, List<string> recipients, string attachmentName, string attachmentText, DateTime utcNow, bool mailOnly = false)
        {
            var transports = new List<string>();
            if (settings.MailConfigured) transports.Add("mail");
            if (!mailOnly && settings.WebhookConfigured) transports.Add("webhook");
            if (transports.Count == 0) return;
            var eventId = (++st.NotificationSequence).ToString(CultureInfo.InvariantCulture) + "-" + Guid.NewGuid().ToString("N");
            foreach (var destination in transports)
            {
                st.Notifications.Add(new NotificationItem { Id = eventId + "-" + destination, Source = source, Destination = destination,
                    Subject = subject, Text = text ?? "", Html = html ?? "", Recipients = string.Join(",", recipients ?? AlertSettings.Addresses(settings.AdminTo)),
                    AttachmentName = attachmentName ?? "", AttachmentText = attachmentText ?? "", CreatedUtc = utcNow, NextUtc = utcNow,
                    Transport = new AlertSettings { SmtpHost = settings.SmtpHost, SmtpPort = settings.SmtpPort, SmtpTls = settings.SmtpTls,
                        SmtpUser = settings.SmtpUser, SmtpPassword = settings.SmtpPassword, From = settings.From,
                        Webhook = settings.Webhook, WebhookTeams = settings.WebhookTeams } });
            }
        }

        /// <summary>
        /// Claims exactly one due destination while state is locked. An expired lease is retried after a crashed worker.
        /// Destinations in skip (failed earlier in this run) are left for the next run.
        /// </summary>
        internal static NotificationItem Claim(AgentState st, DateTime utcNow, ICollection<string> skip = null)
        {
            var oldDelivered = new HashSet<string>(st.Notifications.Where(n => n.Delivered).OrderByDescending(n => n.NextUtc).Skip(256).Select(n => n.Id));
            st.Notifications.RemoveAll(n => n.Delivered && (n.NextUtc < utcNow.AddDays(-7) || oldDelivered.Contains(n.Id)));
            var item = st.Notifications.Where(n => !n.Delivered && !n.Exhausted && n.NextUtc <= utcNow && n.LeaseUntilUtc <= utcNow && (skip == null || !skip.Contains(n.Destination)))
                .OrderBy(n => n.NextUtc).ThenBy(n => n.CreatedUtc).FirstOrDefault();
            if (item == null) return null;
            item.Lease = Guid.NewGuid().ToString("N"); item.LeaseUntilUtc = utcNow.AddMinutes(3);
            return item;
        }

        internal static void Complete(AgentState st, string id, string lease, DateTime utcNow, string error)
        {
            var item = st.Notifications.FirstOrDefault(n => n.Id == id && n.Lease == lease);
            if (item == null) return; // another worker owns an expired lease now
            item.Attempts++; item.Lease = ""; item.LeaseUntilUtc = DateTime.MinValue;
            item.LastError = error ?? ""; item.Delivered = error == null;
            item.Exhausted = !item.Delivered && item.Attempts >= MaxAttempts;
            if (!item.Delivered) item.NextUtc = utcNow.AddMinutes(Math.Min(360, Math.Pow(2, item.Attempts - 1)));
            else
            {
                item.NextUtc = utcNow;
                // Keep a small delivery receipt, not copies of reports or credentials for every successful alert.
                item.Text = item.Html = item.AttachmentText = ""; item.Transport = new AlertSettings();
            }
            if (item.Exhausted) item.Transport = new AlertSettings(); // RetryFailed sends with the settings of its time
        }

        /// <summary>
        /// Drops undelivered alerts kept for an explicit retry once they are older than ExhaustedRetention or beyond the newest
        /// MaxExhaustedPerDestination of their destination: weeks of a broken mail server must not grow the state without end.
        /// </summary>
        internal static int Prune(AgentState st, DateTime utcNow)
        {
            var drop = new HashSet<NotificationItem>(st.Notifications.Where(n => n.Exhausted && !n.Delivered).GroupBy(n => n.Destination)
                .SelectMany(g => g.OrderByDescending(n => n.CreatedUtc).Where((n, i) => i >= MaxExhaustedPerDestination || n.CreatedUtc < utcNow - ExhaustedRetention)));
            if (drop.Count == 0) return 0;
            st.Notifications.RemoveAll(drop.Contains);
            st.NotificationsDiscarded += drop.Count;
            return drop.Count;
        }

        internal static void Drain(Action<NotificationItem> deliver = null)
        {
            deliver = deliver ?? Deliver;
            var elapsed = Stopwatch.StartNew();
            // A destination that failed in this run waits for the next: one that hangs for its timeout must not use up the run.
            var failed = new HashSet<string>();
            for (int i = 0; i < MaxDeliveriesPerRun && elapsed.Elapsed < TimeSpan.FromSeconds(120); i++)
            {
                NotificationItem item = null;
                if (!Agent.WithStateLock(Agent.StateLockName, 1000, () =>
                    { var st = AgentState.Load(); int count = st.Notifications.Count; Prune(st, DateTime.UtcNow); item = Claim(st, DateTime.UtcNow, failed); if (item != null || st.Notifications.Count != count) st.Save(); }) || item == null) return;
                // Network calls deliberately run outside the state lock. Watch and Daily can keep recording events.
                string error = null;
                try
                {
                    deliver(item);
                }
                catch (Exception ex) { error = ex.Message; failed.Add(item.Destination); }
                var result = error;
                // Sent already: wait for the lock while the lease lasts, or the alert goes out again once the lease expires.
                int wait = (int)Math.Max(1000, Math.Min(120000, (item.LeaseUntilUtc - DateTime.UtcNow - TimeSpan.FromSeconds(10)).TotalMilliseconds));
                if (!Agent.WithStateLock(Agent.StateLockName, wait, () =>
                    { var st = AgentState.Load(); Complete(st, item.Id, item.Lease, DateTime.UtcNow, result); st.Save(); }))
                    Agent.Note("notification " + item.Id + ": delivery result could not be committed; lease recovery will retry");
                Agent.Note("notification " + item.Id + " by " + item.Destination + (error == null ? " delivered" : " failed: " + error));
            }
        }

        private static void Deliver(NotificationItem item)
        {
            if (item.Destination == "mail") Agent.SendMail(item.Transport, item.Subject, item.Text, item.Html.Length == 0 ? null : item.Html,
                AlertSettings.Addresses(item.Recipients), item.AttachmentName.Length == 0 ? null : item.AttachmentName, item.AttachmentText, item.Id);
            else Agent.SendHook(item.Transport, item.Subject, item.Text, item.Id);
        }

        /// <summary>Explicit administrator retry after correcting settings. Preserve the original mail recipients and payload.</summary>
        internal static int RetryFailed(AlertSettings settings)
        {
            int count = 0;
            if (!Agent.WithStateLock(Agent.StateLockName, 1000, () =>
            {
                var st = AgentState.Load(); var now = DateTime.UtcNow;
                foreach (var item in st.Notifications.Where(n => !n.Delivered && n.Attempts > 0 && n.LeaseUntilUtc <= now))
                {
                    if (item.Destination == "mail" && !settings.MailConfigured || item.Destination == "webhook" && !settings.WebhookConfigured) continue;
                    item.Transport = new AlertSettings { SmtpHost = settings.SmtpHost, SmtpPort = settings.SmtpPort, SmtpTls = settings.SmtpTls,
                        SmtpUser = settings.SmtpUser, SmtpPassword = settings.SmtpPassword, From = settings.From, Webhook = settings.Webhook, WebhookTeams = settings.WebhookTeams };
                    item.Attempts = 0; item.Exhausted = false; item.LastError = ""; item.NextUtc = now; item.Lease = ""; item.LeaseUntilUtc = DateTime.MinValue; count++;
                }
                st.Save();
            })) throw new InvalidOperationException("The background job is updating its state. Retry in a moment.");
            return count;
        }
    }

    /// <summary>A read-only background health snapshot for the dashboard. Failed or incomplete work remains visible.</summary>
    internal sealed class AgentHealth
    {
        public DateTime? LastWatchSuccessUtc, LastDailySuccessUtc, CheckpointUtc, LastEventUtc, GapUtc;
        public long CheckpointRecordId, Backlog;
        public int PendingNotifications, FailedNotifications, ExhaustedNotifications;
        public long DiscardedNotifications;
        public string LastWatchError = "", LastDailyError = "", JournalGap = "", LastDeliveryError = "", BlockingDegradedReason = "";
        public Dictionary<string, int> PendingByDestination = new Dictionary<string, int>();
        public Dictionary<string, int> FailedByDestination = new Dictionary<string, int>();
        internal static AgentHealth Load() { return From(AgentState.Load()); }
        internal static AgentHealth From(AgentState st)
        {
            return new AgentHealth { LastWatchSuccessUtc = st.LastWatchSuccessUtc, LastDailySuccessUtc = st.LastDailySuccessUtc,
                LastWatchError = st.LastWatchError, LastDailyError = st.LastDailyError, CheckpointUtc = st.Journal.CheckedUtc,
                CheckpointRecordId = st.Journal.LastRecordId, LastEventUtc = st.Journal.LastEventUtc, Backlog = st.Journal.Backlog,
                JournalGap = st.Journal.Gap, GapUtc = st.Journal.GapUtc, BlockingDegradedReason = st.BlockingDegradedReason,
                PendingNotifications = st.Notifications.Count(n => !n.Delivered && !n.Exhausted),
                FailedNotifications = st.Notifications.Count(n => !n.Delivered && n.Attempts > 0),
                ExhaustedNotifications = st.Notifications.Count(n => n.Exhausted), DiscardedNotifications = st.NotificationsDiscarded,
                LastDeliveryError = st.Notifications.Where(n => !n.Delivered && n.LastError.Length > 0).OrderByDescending(n => n.NextUtc).Select(n => n.LastError).FirstOrDefault() ?? "",
                PendingByDestination = st.Notifications.Where(n => !n.Delivered && !n.Exhausted).GroupBy(n => n.Destination).ToDictionary(g => g.Key, g => g.Count()),
                FailedByDestination = st.Notifications.Where(n => !n.Delivered && n.Attempts > 0).GroupBy(n => n.Destination).ToDictionary(g => g.Key, g => g.Count()) };
        }
    }
}

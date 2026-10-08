// OpenSSH Server PN Manager: Agent (alerts, automatic blocking, the transfer archive; run by Task Scheduler as SYSTEM)

using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Mail;
using System.Security.Cryptography;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace OpenSSHServerPNManager
{
    // ------------------------------------------------------------------------------------------
    // What runs while the manager is closed. Two scheduled tasks, both as SYSTEM, both the manager itself:
    //   "OpenSSH Server PN Manager\Watch"  every minute: sshd stopped, failed logins (and automatic blocking), partner
    //                                       uploads (one message per partner per 5 minutes), low disk space
    //   "OpenSSH Server PN Manager\Daily"  each night: the transfer archive, and on the 1st the monthly report
    // Settings, state and a log live in %ProgramData%\ssh\manager, which only SYSTEM and Administrators can open;
    // the SMTP password and the webhook address are encrypted with DPAPI for this computer.
    // ------------------------------------------------------------------------------------------

    /// <summary>The settings of alerts and automatic blocking.</summary>
    internal sealed class AlertSettings
    {
        public string SmtpHost = "", SmtpUser = "", SmtpPassword = "", From = "", AdminTo = "";
        public int SmtpPort = 587; public bool SmtpTls = true;
        public string Webhook = ""; public bool WebhookTeams = true;
        public bool OnSshdStopped = true, OnFailedLogins = true, OnUploads = true, OnDiskLow = true, MonthlyReport = true;
        public bool AutoBlock = true; public int BlockThreshold = 10, BlockWindowMinutes = 10, BurstThreshold = 50, DiskLowPercent = 10;
        /// <summary>Addresses and networks (CIDR) that are never blocked, separated by commas or spaces.</summary>
        public string AllowList = "";
        /// <summary>Per partner: who is told when its files arrive (e-mail addresses separated by commas); empty: the admins.</summary>
        public Dictionary<string, string> PartnerNotify = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        public bool MailConfigured { get { return SmtpHost.Length > 0 && From.Length > 0 && AdminTo.Length > 0; } }
        public bool WebhookConfigured { get { return Webhook.Length > 0; } }

        public static string Dir { get { return Path.Combine(AgentStorage.Root, "manager"); } }
        public static string FilePath { get { return Path.Combine(Dir, "alerts.ini"); } }

        public static AlertSettings Load() { return FromValues(Ini.Read(FilePath)); }

        /// <summary>The settings from the lines of the file (secrets opened with DPAPI).</summary>
        internal static AlertSettings FromValues(IDictionary<string, string> d)
        {
            var s = new AlertSettings();
            Func<string, string, string> str = (k, def) => { string v; return d.TryGetValue(k, out v) ? v : def; };
            Func<string, bool, bool> b = (k, def) => { string v; return d.TryGetValue(k, out v) ? v == "1" : def; };
            Func<string, int, int> n = (k, def) => { string v; int x; return d.TryGetValue(k, out v) && int.TryParse(v, NumberStyles.None, CultureInfo.InvariantCulture, out x) ? x : def; };
            s.SmtpHost = str("smtp.host", ""); s.SmtpPort = n("smtp.port", 587); s.SmtpTls = b("smtp.starttls", true); s.SmtpUser = str("smtp.user", "");
            s.SmtpPassword = Secret.Open(str("smtp.password", "")); s.From = str("mail.from", ""); s.AdminTo = str("mail.admins", "");
            s.Webhook = Secret.Open(str("webhook.url", "")); s.WebhookTeams = str("webhook.format", "teams") == "teams";
            s.OnSshdStopped = b("alert.sshd", true); s.OnFailedLogins = b("alert.failures", true); s.OnUploads = b("alert.uploads", true); s.OnDiskLow = b("alert.disk", true); s.MonthlyReport = b("report.monthly", true);
            s.AutoBlock = b("block.on", true); s.BlockThreshold = Math.Max(3, n("block.threshold", 10)); s.BlockWindowMinutes = Math.Max(1, n("block.minutes", 10)); s.BurstThreshold = Math.Max(10, n("alert.burst", 50));
            s.DiskLowPercent = Math.Min(50, Math.Max(1, n("alert.diskpercent", 10))); s.AllowList = str("block.allow", "");
            foreach (var kv in d.Where(kv => kv.Key.StartsWith("partner.", StringComparison.Ordinal) && kv.Key.EndsWith(".notify", StringComparison.Ordinal)))
                s.PartnerNotify[kv.Key.Substring(8, kv.Key.Length - 15)] = kv.Value;
            return s;
        }

        public void Save() { Ini.Write(FilePath, ToValues()); }

        /// <summary>The lines of the file (secrets sealed with DPAPI).</summary>
        internal SortedDictionary<string, string> ToValues()
        {
            var d = new SortedDictionary<string, string>(StringComparer.Ordinal)
            {
                { "smtp.host", SmtpHost }, { "smtp.port", SmtpPort.ToString(CultureInfo.InvariantCulture) }, { "smtp.starttls", SmtpTls ? "1" : "0" }, { "smtp.user", SmtpUser },
                { "smtp.password", Secret.Seal(SmtpPassword) }, { "mail.from", From }, { "mail.admins", AdminTo },
                { "webhook.url", Secret.Seal(Webhook) }, { "webhook.format", WebhookTeams ? "teams" : "text" },
                { "alert.sshd", OnSshdStopped ? "1" : "0" }, { "alert.failures", OnFailedLogins ? "1" : "0" }, { "alert.uploads", OnUploads ? "1" : "0" }, { "alert.disk", OnDiskLow ? "1" : "0" }, { "report.monthly", MonthlyReport ? "1" : "0" },
                { "block.on", AutoBlock ? "1" : "0" }, { "block.threshold", BlockThreshold.ToString(CultureInfo.InvariantCulture) }, { "block.minutes", BlockWindowMinutes.ToString(CultureInfo.InvariantCulture) },
                { "alert.burst", BurstThreshold.ToString(CultureInfo.InvariantCulture) }, { "alert.diskpercent", DiskLowPercent.ToString(CultureInfo.InvariantCulture) }, { "block.allow", AllowList },
            };
            foreach (var kv in PartnerNotify.Where(kv => kv.Value.Trim().Length > 0)) d["partner." + kv.Key.ToLowerInvariant() + ".notify"] = kv.Value.Trim();
            return d;
        }

        /// <summary>E-mail addresses from a list separated by commas, semicolons or spaces; throws ConfigException for one that is not valid.</summary>
        public static List<string> Addresses(string list)
        {
            var l = new List<string>();
            foreach (var a in (list ?? "").Split(new[] { ',', ';', ' ', '\t', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
            {
                try { var m = new MailAddress(a); if (m.Address != a) throw new FormatException(); l.Add(a); }
                catch (FormatException) { throw new ConfigException("\"" + a + "\" is not an e-mail address."); }
            }
            return l;
        }

        /// <summary>Why the settings cannot be used, or null.</summary>
        public string Problem()
        {
            try
            {
                if (SmtpHost.Length > 0 || AdminTo.Length > 0 || From.Length > 0)
                {
                    if (SmtpHost.Length == 0 || Uri.CheckHostName(SmtpHost) == UriHostNameType.Unknown) return "Enter the name or address of the mail server.";
                    if (SmtpPort < 1 || SmtpPort > 65535) return "The mail server's port is a number from 1 to 65535.";
                    if (Addresses(From).Count != 1) return "Enter one sender address (From).";
                    if (Addresses(AdminTo).Count == 0) return "Enter at least one address for the admins.";
                }
                foreach (var kv in PartnerNotify) Addresses(kv.Value);
                if (Webhook.Length > 0)
                {
                    Uri u;
                    if (!Uri.TryCreate(Webhook, UriKind.Absolute, out u) || u.Scheme != Uri.UriSchemeHttps) return "The webhook address must start with https://.";
                }
                foreach (var a in AllowListEntries()) if (!Network.TryParse(a, out _dummy)) return "\"" + a + "\" in the allow list is not an address or a network (like 203.0.113.0/24).";
                return null;
            }
            catch (ConfigException ex) { return ex.Message; }
        }
        private static Network _dummy;

        public List<string> AllowListEntries() { return AllowList.Split(new[] { ',', ';', ' ', '\t', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).ToList(); }
    }

    /// <summary>An address or a network in CIDR form, to test addresses against the allow list.</summary>
    internal sealed class Network
    {
        private byte[] _bytes; private int _bits;

        public static bool TryParse(string s, out Network n)
        {
            n = null;
            var parts = (s ?? "").Trim().Split('/');
            IPAddress ip; int bits;
            if (parts.Length > 2 || !IPAddress.TryParse(parts[0], out ip)) return false;
            var bytes = (ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip).GetAddressBytes();
            if (parts.Length == 2) { if (!int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out bits) || bits > bytes.Length * 8) return false; }
            else bits = bytes.Length * 8;
            n = new Network { _bytes = bytes, _bits = bits };
            return true;
        }

        public bool Contains(string address)
        {
            IPAddress ip;
            if (!IPAddress.TryParse(address, out ip)) return false;
            var b = (ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip).GetAddressBytes();
            if (b.Length != _bytes.Length) return false;
            for (int i = 0; i < _bits; i++) { int mask = 0x80 >> (i % 8); if ((b[i / 8] & mask) != (_bytes[i / 8] & mask)) return false; }
            return true;
        }
    }

    /// <summary>Secrets in the settings file: DPAPI for this computer (the file itself is readable by SYSTEM and Administrators only).</summary>
    internal static class Secret
    {
        private static readonly byte[] Entropy = Encoding.ASCII.GetBytes("OpenSSH Server PN Manager alerts");
        public static string Seal(string value)
        {
            if (string.IsNullOrEmpty(value)) return "";
            return "dpapi:" + Convert.ToBase64String(ProtectedData.Protect(Encoding.UTF8.GetBytes(value), Entropy, DataProtectionScope.LocalMachine));
        }
        public static string Open(string stored)
        {
            if (string.IsNullOrEmpty(stored) || !stored.StartsWith("dpapi:", StringComparison.Ordinal)) return "";
            try { return Encoding.UTF8.GetString(ProtectedData.Unprotect(Convert.FromBase64String(stored.Substring(6)), Entropy, DataProtectionScope.LocalMachine)); }
            catch (Exception ex) { Log.Error("A secret of the alert settings cannot be read (was the file copied from another computer?)", ex, false); return ""; }
        }
    }

    /// <summary>"key=value" files, one per line, written so that only SYSTEM and Administrators can read them.</summary>
    internal static class Ini
    {
        public static Dictionary<string, string> Read(string path)
        {
            var d = new Dictionary<string, string>(StringComparer.Ordinal);
            if (!File.Exists(path)) return d;
            foreach (var line in ReadLines(path, FileShare.Read))
            {
                if (line.StartsWith("#")) continue;
                int i = line.IndexOf('=');
                if (i > 0) d[line.Substring(0, i).Trim()] = line.Substring(i + 1).Trim();
            }
            return d;
        }

        /// <summary>
        /// The lines of a file that another process replaces (Replace). Never shared for delete: where a deleted file keeps its
        /// name while it is open (Windows Server 2016 and older), File.Replace under such a reader deletes the file and then
        /// cannot rename the new one into its place. Without that sharing the replace fails cleanly and is retried; the replace
        /// itself holds the file for a moment, which a reader waits out.
        /// </summary>
        internal static List<string> ReadLines(string path, FileShare share)
        {
            for (int attempt = 1; ; attempt++)
            {
                try
                {
                    var lines = new List<string>();
                    using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, share))
                    using (var reader = new StreamReader(stream, Encoding.UTF8))
                    { string l; while ((l = reader.ReadLine()) != null) lines.Add(l); }
                    return lines;
                }
                catch (IOException ex) when (attempt < 40 && !(ex is FileNotFoundException) && !(ex is DirectoryNotFoundException)) { Thread.Sleep(50); }
            }
        }

        public static void Write(string path, IEnumerable<KeyValuePair<string, string>> values)
        {
            var dir = Path.GetDirectoryName(path);
            if (!Directory.Exists(dir)) AgentStorage.Permissions.CreateFolder(dir);
            var text = "# " + Program.AppName + ": written by the program, " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) + "\r\n" +
                       string.Concat(values.Select(kv => kv.Key + "=" + (kv.Value ?? "").Replace("\r", " ").Replace("\n", " ") + "\r\n"));
            WriteReplacing(path, writer => writer.Write(text));
        }

        /// <summary>Writes a file in full to a temporary file, which then replaces it (Replace).</summary>
        internal static void WriteReplacing(string path, Action<StreamWriter> write, Action<string, string> replace = null)
        {
            var tmp = path + "." + Guid.NewGuid().ToString("N") + ".new";
            bool complete = false;
            try
            {
                using (var stream = new FileStream(tmp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                using (var writer = new StreamWriter(stream, new UTF8Encoding(false)))
                { write(writer); writer.Flush(); stream.Flush(true); }
                AgentStorage.Permissions.RestrictFile(tmp);
                complete = true;
                Replace(tmp, path, replace);
            }
            finally
            {
                // A replace that deleted path but could not rename tmp into its place leaves tmp as the only copy.
                if (File.Exists(tmp))
                {
                    if (!complete || File.Exists(path)) File.Delete(tmp);
                    else try { File.Move(tmp, path); } catch (IOException) { } catch (UnauthorizedAccessException) { }
                }
            }
        }

        /// <summary>
        /// Puts tmp in the place of path. A reader of path (readers never share delete) makes File.Replace fail cleanly with a
        /// sharing violation; readers finish within moments, so the replace is retried for a few seconds.
        /// </summary>
        private static void Replace(string tmp, string path, Action<string, string> replace)
        {
            replace = replace ?? ((from, to) => File.Replace(from, to, null));
            var until = DateTime.UtcNow.AddSeconds(5);
            while (true)
            {
                try { if (File.Exists(path)) replace(tmp, path); else File.Move(tmp, path); return; }
                catch (Exception ex) when ((ex is IOException || ex is UnauthorizedAccessException) && DateTime.UtcNow < until && File.Exists(tmp)) { Thread.Sleep(100); }
            }
        }
    }

    /// <summary>
    /// The package's request for the setup wizard after a first installation with a window. A deferred step of the package
    /// (as LocalSystem, after the files are installed) runs "--agent open-wizard", which leaves this marker; after the
    /// installation the package starts the manager, which takes a fresh marker and opens the wizard. The step that starts it
    /// (WixShellExec) passes no arguments, and the program that started the manager may have ended by the time it looks.
    /// </summary>
    internal static class WizardRequest
    {
        public static string FilePath { get { return Path.Combine(AlertSettings.Dir, "open-wizard"); } }
        /// <summary>How long a marker counts: an installation that failed after leaving one does not open the wizard later.</summary>
        public static readonly TimeSpan Fresh = TimeSpan.FromMinutes(15);

        public static void Leave(DateTime now)
        {
            if (!Directory.Exists(AlertSettings.Dir)) Acl.CreatePrivateFolder(AlertSettings.Dir);
            File.WriteAllText(FilePath, now.ToString("yyyy-MM-ddTHH:mm:ss", CultureInfo.InvariantCulture));
        }

        /// <summary>Whether a marker left within the last 15 minutes is there. It is removed either way. Only administrators can read it.</summary>
        public static bool Take(DateTime now)
        {
            try
            {
                if (!File.Exists(FilePath)) return false;
                DateTime at;
                bool ok = DateTime.TryParseExact(File.ReadAllText(FilePath).Trim(), "yyyy-MM-ddTHH:mm:ss", CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out at);
                File.Delete(FilePath);
                return ok && at <= now.AddMinutes(1) && now - at < Fresh;
            }
            catch { return false; }
        }
    }

    /// <summary>What the agent remembers between runs.</summary>
    internal sealed class AgentState
    {
        public long LastRecordId; public string SshdStatus = ""; public DateTime? LastBurstAlert, DiskAlertDay, LastDiskCheck; public DateTime ArchivedUntil; public string ReportedMonth = "";
        public TransferJournalState Journal = new TransferJournalState();
        public List<NotificationItem> Notifications = new List<NotificationItem>();
        public long NotificationSequence;
        /// <summary>Undelivered alerts given up for good (NotificationOutbox.Prune), in all.</summary>
        public long NotificationsDiscarded;
        public DateTime? LastWatchSuccessUtc, LastDailySuccessUtc;
        public string LastWatchError = "", LastDailyError = "", BlockingDegradedReason = "";
        /// <summary>Addresses the agent blocked: until when, how many times in the last week, and when the last one was.</summary>
        public Dictionary<string, BlockEntry> Blocks = new Dictionary<string, BlockEntry>();
        /// <summary>Uploads waiting to be reported, per partner: "time|file|bytes".</summary>
        public Dictionary<string, List<string>> Pending = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);

        internal sealed class BlockEntry { public DateTime Until, LastStrike; public int Strikes; }

        public static string FilePath { get { return Path.Combine(AlertSettings.Dir, "agent-state.ini"); } }
        private const string Fmt = "yyyy-MM-ddTHH:mm:ss";

        public static AgentState Load()
        {
            var st = new AgentState(); var d = Ini.Read(FilePath);
            Func<string, DateTime?> t = k => { string v; DateTime x; return d.TryGetValue(k, out v) && DateTime.TryParseExact(v, Fmt, CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out x) ? (DateTime?)x : null; };
            string s; long id;
            if (d.TryGetValue("events.last", out s) && long.TryParse(s, NumberStyles.None, CultureInfo.InvariantCulture, out id)) st.LastRecordId = id;
            if (d.TryGetValue("sshd.status", out s)) st.SshdStatus = s;
            st.LastBurstAlert = t("alert.burst.last"); st.DiskAlertDay = t("alert.disk.day"); st.LastDiskCheck = t("disk.checked");
            st.ArchivedUntil = t("archive.until") ?? DateTime.MinValue;
            if (d.TryGetValue("report.month", out s)) st.ReportedMonth = s;
            foreach (var kv in d.Where(kv => kv.Key.StartsWith("block.", StringComparison.Ordinal)))
            {
                var f = kv.Value.Split('|'); DateTime until, last; int strikes;
                if (f.Length == 3 && DateTime.TryParseExact(f[0], Fmt, CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out until) && int.TryParse(f[1], out strikes) && DateTime.TryParseExact(f[2], Fmt, CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out last))
                    st.Blocks[kv.Key.Substring(6)] = new BlockEntry { Until = until, Strikes = strikes, LastStrike = last };
            }
            foreach (var kv in d.Where(kv => kv.Key.StartsWith("pending.", StringComparison.Ordinal)))
                st.Pending[kv.Key.Substring(8)] = kv.Value.Split(new[] { '\t' }, StringSplitOptions.RemoveEmptyEntries).ToList();
            st.Journal = TransferJournalState.Load(d);
            foreach (var kv in d.Where(kv => kv.Key.StartsWith("notify.item.", StringComparison.Ordinal))) st.Notifications.Add(NotificationItem.Restore(kv.Value));
            if (d.TryGetValue("notify.sequence", out s) && long.TryParse(s, out id)) st.NotificationSequence = id;
            if (d.TryGetValue("notify.discarded", out s) && long.TryParse(s, out id)) st.NotificationsDiscarded = id;
            DateTime utc;
            if (d.TryGetValue("health.watch.success", out s) && DateTime.TryParse(s, null, DateTimeStyles.RoundtripKind, out utc)) st.LastWatchSuccessUtc = utc;
            if (d.TryGetValue("health.daily.success", out s) && DateTime.TryParse(s, null, DateTimeStyles.RoundtripKind, out utc)) st.LastDailySuccessUtc = utc;
            if (d.TryGetValue("health.watch.error", out s)) st.LastWatchError = s;
            if (d.TryGetValue("health.daily.error", out s)) st.LastDailyError = s;
            if (d.TryGetValue("health.block.degraded", out s)) st.BlockingDegradedReason = s;
            return st;
        }

        public void Save()
        {
            var d = new SortedDictionary<string, string>(StringComparer.Ordinal) { { "events.last", LastRecordId.ToString(CultureInfo.InvariantCulture) }, { "sshd.status", SshdStatus }, { "report.month", ReportedMonth } };
            Action<string, DateTime?> t = (k, v) => { if (v != null) d[k] = v.Value.ToString(Fmt, CultureInfo.InvariantCulture); };
            t("alert.burst.last", LastBurstAlert); t("alert.disk.day", DiskAlertDay); t("disk.checked", LastDiskCheck);
            if (ArchivedUntil > DateTime.MinValue) t("archive.until", ArchivedUntil);
            foreach (var b in Blocks) d["block." + b.Key] = b.Value.Until.ToString(Fmt, CultureInfo.InvariantCulture) + "|" + b.Value.Strikes + "|" + b.Value.LastStrike.ToString(Fmt, CultureInfo.InvariantCulture);
            foreach (var p in Pending.Where(p => p.Value.Count > 0)) d["pending." + p.Key] = string.Join("\t", p.Value.Select(x => x.Replace("\t", " ")));
            Journal.Save(d);
            d["notify.sequence"] = NotificationSequence.ToString(CultureInfo.InvariantCulture);
            if (NotificationsDiscarded > 0) d["notify.discarded"] = NotificationsDiscarded.ToString(CultureInfo.InvariantCulture);
            foreach (var item in Notifications) d["notify.item." + item.Id] = item.Store();
            if (LastWatchSuccessUtc.HasValue) d["health.watch.success"] = LastWatchSuccessUtc.Value.ToString("o");
            if (LastDailySuccessUtc.HasValue) d["health.daily.success"] = LastDailySuccessUtc.Value.ToString("o");
            d["health.watch.error"] = LastWatchError; d["health.daily.error"] = LastDailyError;
            d["health.block.degraded"] = BlockingDegradedReason;
            Ini.Write(FilePath, d);
        }
    }

    internal static class Agent
    {
        /// <summary>Machine-wide. Unit tests set a lock of their own, so they never wait for or hold up the installed agent.</summary>
        internal static string StateLockName = "Global\\OpenSSHServerPNManager.AgentState";
        public const string TaskFolder = "OpenSSH Server PN Manager";
        public static readonly string WatchTask = TaskFolder + "\\Watch", DailyTask = TaskFolder + "\\Daily";
        public static string LogPath { get { return Path.Combine(AlertSettings.Dir, "agent.log"); } }
        /// <summary>Block times after the first, second and third strike within a week.</summary>
        public static readonly TimeSpan[] BlockTimes = { TimeSpan.FromHours(1), TimeSpan.FromHours(24), TimeSpan.FromDays(7) };
        public static readonly TimeSpan UploadBatch = TimeSpan.FromMinutes(5);

        /// <summary>Both scheduled jobs replace the same state file; hold one machine-wide lock from load through save.</summary>
        internal static bool WithStateLock(string name, int timeoutMilliseconds, Action action)
        {
            var security = new MutexSecurity();
            foreach (var sid in new[] { WellKnownSidType.LocalSystemSid, WellKnownSidType.BuiltinAdministratorsSid })
                security.AddAccessRule(new MutexAccessRule(new SecurityIdentifier(sid, null), MutexRights.FullControl, AccessControlType.Allow));
            using (var identity = WindowsIdentity.GetCurrent())
                security.AddAccessRule(new MutexAccessRule(identity.User, MutexRights.FullControl, AccessControlType.Allow));
            bool created;
            using (var mutex = new Mutex(false, name, out created, security))
            {
                bool owned = false;
                try
                {
                    try { owned = mutex.WaitOne(timeoutMilliseconds); }
                    catch (AbandonedMutexException) { owned = true; } // the failed job's lock now belongs to this thread
                    if (!owned) return false;
                    action();
                    return true;
                }
                finally { if (owned) mutex.ReleaseMutex(); }
            }
        }

        /// <summary>
        /// --agent watch | daily: what the scheduled tasks run; --agent uninstall: what the MSI runs (as SYSTEM) before it
        /// removes the program files; --agent open-wizard: what it runs during a first installation with a window
        /// (WizardRequest). Returns the exit code.
        /// </summary>
        public static int Run(string job)
        {
            job = job ?? "";
            if (job.StartsWith("probe:", StringComparison.OrdinalIgnoreCase)) return Probe(job.Substring(6));
            job = job.ToLowerInvariant();
            if (job == "uninstall") return Uninstall();
            if (job == "open-wizard")
            {
                try { WizardRequest.Leave(DateTime.Now); return 0; }
                catch (Exception ex) { Note("the request for the setup wizard failed: " + ex.Message); return 1; }
            }
            try
            {
                if (job != "watch" && job != "daily") { Note("unknown job " + job); return 2; }
                // Watch retries next minute. Daily waits beyond Watch's five-minute scheduler execution limit.
                bool completed = WithStateLock(StateLockName, job == "daily" ? 360000 : 1000, () =>
                {
                    if (job == "watch") MoveToInstalled();
                    var s = AlertSettings.Load(); var st = AgentState.Load();
                    if (job == "watch") Watch(s, st, DateTime.Now, st.Save);
                    else Daily(s, st, DateTime.Now);
                    if (job == "watch") { st.LastWatchSuccessUtc = DateTime.UtcNow; st.LastWatchError = ""; }
                    else { st.LastDailySuccessUtc = DateTime.UtcNow; st.LastDailyError = ""; }
                    st.Save();
                });
                if (!completed) Note("the " + job + " run deferred: another agent job is still running");
                if (completed) NotificationOutbox.Drain();
                return completed || job == "watch" ? 0 : 1;
            }
            catch (Exception ex)
            {
                Note("the " + job + " run failed: " + ex);
                try
                {
                    WithStateLock(StateLockName, 1000, () =>
                    { var st = AgentState.Load(); if (job == "watch") st.LastWatchError = ex.Message; else st.LastDailyError = ex.Message; st.Save(); });
                    // Previously queued notifications must still be attempted if collection fails this run.
                    NotificationOutbox.Drain();
                }
                catch (Exception delivery) { Note("recording or delivering after the failed run: " + delivery.Message); }
                return 1;
            }
        }

        /// <summary>A line in agent.log (kept to about 1 MB: the older half goes).</summary>
        public static void Note(string text)
        {
            try
            {
                if (!Directory.Exists(AlertSettings.Dir)) Acl.CreatePrivateFolder(AlertSettings.Dir);
                var p = LogPath;
                if (File.Exists(p) && new FileInfo(p).Length > 1024 * 1024)
                {
                    var lines = File.ReadAllLines(p); File.WriteAllLines(p, lines.Skip(lines.Length / 2));
                }
                File.AppendAllText(p, DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) + "  " + text.Replace("\r", " ").Replace("\n", " ") + "\r\n", new UTF8Encoding(false));
            }
            catch { }
        }

        // ---------------- Every minute ----------------
        public static void Watch(AlertSettings s, AgentState st, DateTime now, Action checkpoint = null)
        {
            var server = Environment.MachineName;
            // sshd stopped, or running again.
            var status = Services.Status("sshd");
            var current = status.Exists ? status.Status : "Not installed";
            ObserveStatus(s, st, current, now, server);
            // Later event-log/firewall failures must not discard an already observed service transition.
            if (checkpoint != null) checkpoint();

            // Addresses blocked by the agent whose time is up.
            // (An entry stays a week after its block ends, with Until = MinValue, so that a new strike gets the next block time.)
            var unblockError = LiftExpired(st, now, Firewall.RemoveBlockedAddresses);
            foreach (var a in st.Blocks.Where(b => b.Value.Until == DateTime.MinValue && b.Value.LastStrike < now.AddDays(-7)).Select(b => b.Key).ToList()) st.Blocks.Remove(a);

            // Failed logins in the window: automatic blocking and bursts.
            if (s.AutoBlock || s.OnFailedLogins)
            {
                string scanProblem;
                var events = EventLogs.ReadFailures(TimeSpan.FromMinutes(s.BlockWindowMinutes), CancellationToken.None, out scanProblem);
                if (scanProblem != null) Note(scanProblem);
                var sources = EventLogs.FailedByAddress(events);
                if (s.AutoBlock) Block(s, st, sources, now, server, checkpoint);
                int total = sources.Sum(x => x.Count);
                if (s.OnFailedLogins && total >= s.BurstThreshold && (st.LastBurstAlert == null || st.LastBurstAlert < now.AddMinutes(-15)))
                {
                    st.LastBurstAlert = now;
                    Queue(s, st, "failed-logins", total + " failed logins on " + server + " in " + s.BlockWindowMinutes + " minutes",
                         total + " failed or abandoned SSH logins on " + server + " in the last " + s.BlockWindowMinutes + " minutes, from " + sources.Count + " address(es):\n" +
                         string.Join("\n", sources.Take(10).Select(x => "  " + x.Address + ": " + x.Count + (x.Users.Count > 0 ? " (accounts tried: " + string.Join(", ", x.Users.Take(5)) + ")" : ""))), null, null, null);
                }
            }
            st.BlockingDegradedReason = BlockingReason(s.AutoBlock, st.BlockingDegradedReason, unblockError);

            if (checkpoint != null) checkpoint(); // preserve completed blocking/burst work before transfer collection

            // Partner uploads: collected per partner, reported once the first is 5 minutes old.
            CollectTransfers(s, st, now);
            if (s.OnUploads)
            {
                foreach (var p in DuePending(st, now))
                {
                    var items = st.Pending[p].Select(x => x.Split('|')).Where(x => x.Length == 3).ToList(); // file names cannot contain |
                    string to; s.PartnerNotify.TryGetValue(p, out to);
                    var total = items.Sum(x => { long b; return long.TryParse(x[2], out b) ? b : 0; });
                    var body = p + " uploaded " + items.Count + " file(s), " + Ui.Bytes(total) + ", to " + server + ":\n" + string.Join("\n", items.Take(50).Select(x => { long b; long.TryParse(x[2], out b); return "  " + x[0].Replace('T', ' ') + "  " + x[1] + "  (" + Ui.Bytes(b) + ")"; })) + (items.Count > 50 ? "\n  ... and " + (items.Count - 50) + " more" : "");
                    Queue(s, st, "uploads", "Files from " + p + " on " + server + ": " + items.Count + " new", body, null, string.IsNullOrWhiteSpace(to) ? null : AlertSettings.Addresses(to), null);
                    st.Pending.Remove(p); // transferred to the durable, per-destination outbox in this state transaction
                }
            }

            // Free space on the drive of the partners' folders, once an hour.
            if (s.OnDiskLow && (st.LastDiskCheck == null || st.LastDiskCheck < now.AddHours(-1)))
            {
                st.LastDiskCheck = now;
                var root = PartnerRootFromConfig() ?? Ssh.ConfigDir;
                try
                {
                    var drive = new DriveInfo(Path.GetPathRoot(root));
                    double pct = 100.0 * drive.AvailableFreeSpace / Math.Max(1, drive.TotalSize);
                    if (pct < s.DiskLowPercent && (st.DiskAlertDay == null || st.DiskAlertDay.Value.Date != now.Date))
                    {
                        st.DiskAlertDay = now.Date;
                        Queue(s, st, "disk-low", "Disk " + drive.Name + " of " + server + " is almost full (" + pct.ToString("0.0", CultureInfo.InvariantCulture) + "% free)",
                             "Drive " + drive.Name + " of " + server + ", which holds " + root + ", has " + Ui.Bytes(drive.AvailableFreeSpace) + " free of " + Ui.Bytes(drive.TotalSize) + ". Uploads fail when it is full.", null, null, null);
                    }
                }
                catch (Exception ex) { Note("disk check of " + root + ": " + ex.Message); }
            }
        }

        // Used only by the explicitly invoked destructive auth test's uniquely named SYSTEM task. No firewall,
        // service, notification, installer, or normal task operations run in this probe.
        private static int Probe(string encodedDirectory)
        {
            string previous = AgentStorage.RootOverride;
            try
            {
                var root = Path.GetFullPath(Encoding.UTF8.GetString(Convert.FromBase64String(encodedDirectory))).TrimEnd(Path.DirectorySeparatorChar);
                // AuthTest runs under the user's temp root while the task runs under SYSTEM. The marker and every
                // parent below the profile/temp root must be real directories, never a redirected junction.
                var marker = Path.Combine(root, "agent-probe.marker");
                if (!Path.GetFileName(root).StartsWith("pn-agent-probe-", StringComparison.Ordinal) ||
                    !Directory.Exists(root) || !File.Exists(marker) || !Acl.IsAdminOnly(root) || !Acl.IsAdminOnly(marker))
                    throw new InvalidOperationException("The agent probe requires an administrator-only test directory and marker.");
                for (var folder = new DirectoryInfo(root); folder != null; folder = folder.Parent)
                    if ((folder.Attributes & FileAttributes.ReparsePoint) != 0) throw new InvalidOperationException("Agent probe directories cannot contain reparse points.");
                AgentStorage.RootOverride = root;
                var st = new AgentState { SshdStatus = Services.Status("sshd").Status };
                CollectTransfers(new AlertSettings { OnUploads = false }, st, DateTime.Now);
                st.Save();
                return 0;
            }
            catch (Exception ex)
            {
                if (AgentStorage.RootOverride != previous) Note("agent probe failed: " + ex.Message);
                return 1;
            }
            finally { AgentStorage.RootOverride = previous; }
        }

        internal static void ObserveStatus(AlertSettings s, AgentState st, string current, DateTime now, string server)
        {
            if (s.OnSshdStopped && st.SshdStatus.Length > 0 && current != st.SshdStatus && (current == "Running" || st.SshdStatus == "Running"))
                Queue(s, st, "service-status", current == "Running" ? "sshd is running again on " + server : "sshd is not running on " + server + " (" + current + ")",
                    current == "Running" ? "The SSH server sshd on " + server + " is running again, since " + now.ToString("HH:mm") + "." : "The SSH server sshd on " + server + " stopped: " + current + " at " + now.ToString("yyyy-MM-dd HH:mm") + ". Nobody can log in or transfer files until it runs again.", null, null, null);
            st.SshdStatus = current;
        }

        private static void Queue(AlertSettings s, AgentState st, string source, string subject, string text, string html, List<string> to, string attachmentName)
        { NotificationOutbox.Enqueue(st, s, source, subject, text, html, to, attachmentName, null, DateTime.UtcNow); }

        private static string PartnerRootFromConfig()
        {
            try { return PartnerSetup.Check(SshdConfig.Load(), PartnerGroups.Default).Root; } catch { return null; }
        }

        /// <summary>
        /// Blocks the addresses with at least BlockThreshold failed logins in the window (sshd logs an attempt with an account
        /// that does not exist twice, so such attempts count double): 1 hour, then 24 hours, then 7 days within a week. Never
        /// blocked: the allow list, this computer, and addresses with a logged-in session.
        /// </summary>
        internal static List<string> Block(AlertSettings s, AgentState st, List<EventLogs.FailedSource> sources, DateTime now, string server, Action checkpoint = null)
        {
            var state = ServerState.Read(); HashSet<string> peers; string error;
            if (!state.Verified)
            { st.BlockingDegradedReason = state.Error; Note("automatic blocking deferred: " + state.Error); return new List<string>(); }
            if (!Sessions.TryLoggedInAddresses(state.Ports, out peers, out error))
            { st.BlockingDegradedReason = error; Note("automatic blocking deferred: " + error); return new List<string>(); }
            return ApplyBlocks(s, st, sources, now, server, peers, state.FirewallPorts, Firewall.BlockedAddresses, Firewall.AddBlockedAddresses, checkpoint);
        }

        /// <summary>Block's firewall steps in their order, with the firewall passed in: read the rule, plan, save the schedule, add.</summary>
        internal static List<string> ApplyBlocks(AlertSettings s, AgentState st, List<EventLogs.FailedSource> sources, DateTime now, string server, HashSet<string> peers, string ports,
            Func<List<string>> readBlocked, Action<IEnumerable<string>, string> addBlocked, Action checkpoint)
        {
            HashSet<string> already;
            try { already = new HashSet<string>(readBlocked()); }
            catch (Exception ex)
            {
                // Rewriting the rule from an unread list would unblock every address already in it.
                st.BlockingDegradedReason = "the firewall block rule could not be read: " + ex.Message;
                Note("automatic blocking deferred: " + st.BlockingDegradedReason); return new List<string>();
            }
            st.BlockingDegradedReason = "";
            var before = st.Blocks.ToDictionary(e => e.Key, e => new AgentState.BlockEntry { Until = e.Value.Until, Strikes = e.Value.Strikes, LastStrike = e.Value.LastStrike });
            var add = PlanBlocks(s, st, sources, now, already, peers, a => Firewall.NotBlockable(a) != null);
            // Record the schedule before the firewall changes: a block whose expiry was never saved would last for ever.
            if (add.Count > 0 && checkpoint != null) checkpoint();
            // A listener change also updates the scope of existing blocks, even when no new address was added.
            try { if (add.Count > 0 || already.Count > 0) addBlocked(add, ports); }
            catch
            {
                // The write is several firewall calls and the first adds the addresses. An address the failed write did add keeps
                // its timer, or it would stay blocked for ever; one it did not add gets no strike, or its next block would be longer.
                if (add.Count > 0)
                {
                    List<string> inRule = null;
                    try { inRule = readBlocked(); } catch { }
                    foreach (var a in add)
                    {
                        AgentState.BlockEntry old;
                        bool had = before.TryGetValue(a, out old);
                        if (inRule != null && inRule.Any(r => SameAddress(r, a))) continue;
                        // Not known whether it was added: the timer stays to lift it, without the strike.
                        if (inRule == null) st.Blocks[a] = new AgentState.BlockEntry { Until = st.Blocks[a].Until, Strikes = had ? old.Strikes : 0, LastStrike = had ? old.LastStrike : DateTime.MinValue };
                        else if (had) st.Blocks[a] = old;
                        else st.Blocks.Remove(a);
                    }
                    if (checkpoint != null) checkpoint();
                }
                throw;
            }
            foreach (var a in add)
            {
                var x = sources.First(y => y.Address == a); var b = st.Blocks[a];
                Note("blocked " + a + " until " + b.Until.ToString("yyyy-MM-dd HH:mm") + " after " + x.Count + " failed logins (strike " + b.Strikes + ")");
                if (s.OnFailedLogins)
                    Queue(s, st, "auto-block", "Blocked " + a + " on " + server, a + " is blocked from SSH on " + server + " until " + b.Until.ToString("yyyy-MM-dd HH:mm") + " after " + x.Count + " failed logins in " + s.BlockWindowMinutes + " minutes" +
                         (x.Users.Count > 0 ? " (accounts tried: " + string.Join(", ", x.Users.Take(8)) + ")" : "") + ". The Logs tab of OpenSSH Server PN Manager unblocks it.", null, null, null);
            }
            return add;
        }

        /// <summary>
        /// Lifts the agent's blocks whose time is up. When the firewall cannot be changed they stay due, to be lifted by a later
        /// run, and the reason is returned: the rest of the run (alerts, transfers, disk) must go on.
        /// </summary>
        internal static string LiftExpired(AgentState st, DateTime now, Action<IEnumerable<string>> remove)
        {
            var expired = st.Blocks.Where(b => b.Value.Until != DateTime.MinValue && b.Value.Until <= now).Select(b => b.Key).ToList();
            if (expired.Count == 0) return null;
            try { remove(expired); }
            catch (Exception ex)
            {
                Note("automatic unblocking deferred: " + ex.Message);
                return "blocks whose time is up could not be lifted: " + ex.Message;
            }
            foreach (var a in expired) { Note("unblocked " + a + " (its time is up)"); st.Blocks[a].Until = DateTime.MinValue; }
            return null;
        }

        /// <summary>Why automatic blocking is impaired after a run: Block's own reason only while it is on, and a failed expiry either way.</summary>
        internal static string BlockingReason(bool autoBlock, string blockReason, string unblockError)
        {
            var reasons = new List<string>();
            if (autoBlock && !string.IsNullOrEmpty(blockReason)) reasons.Add(blockReason);
            if (unblockError != null) reasons.Add(unblockError);
            return string.Join("; ", reasons);
        }

        /// <summary>
        /// Ends the agent's timers for addresses an admin blocked or unblocked: its expiry then never lifts them. Strikes stay, so a
        /// later automatic block still gets the next block time, and the entry goes after a quiet week. Returns how many ended.
        /// </summary>
        internal static int ClearTimers(AgentState st, IEnumerable<string> addresses)
        {
            int count = 0;
            foreach (var address in addresses)
                foreach (var entry in st.Blocks.Where(e => e.Value.Until != DateTime.MinValue && SameAddress(e.Key, address)).Select(e => e.Value).ToList())
                { entry.Until = DateTime.MinValue; count++; }
            return count;
        }

        /// <summary>The firewall writes addresses in its own form ("1.2.3.4/255.255.255.255", IPv6 in other cases); the log does not.</summary>
        private static bool SameAddress(string first, string second)
        {
            first = Firewall.WithoutZone(Firewall.NormaliseAddress((first ?? "").Trim())); second = Firewall.WithoutZone(Firewall.NormaliseAddress((second ?? "").Trim()));
            IPAddress x, y;
            if (IPAddress.TryParse(first, out x) && IPAddress.TryParse(second, out y))
                return (x.IsIPv4MappedToIPv6 ? x.MapToIPv4() : x).Equals(y.IsIPv4MappedToIPv6 ? y.MapToIPv4() : y);
            return string.Equals(first, second, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Which addresses to block now, and until when (written into the state): at least BlockThreshold failures, not
        /// blocked already, not on the allow list, not connected, not this computer. Strikes within a week give 1 hour, then
        /// 24 hours, then 7 days.
        /// </summary>
        internal static List<string> PlanBlocks(AlertSettings s, AgentState st, List<EventLogs.FailedSource> sources, DateTime now, HashSet<string> already, HashSet<string> connected, Func<string, bool> notBlockable)
        {
            var allow = s.AllowListEntries().Select(a => { Network n; return Network.TryParse(a, out n) ? n : null; }).Where(n => n != null).ToList();
            // Peers from the TCP table keep the zone of a link-local address (fe80::1%12); the log's addresses have none.
            var live = new HashSet<string>(connected.Select(Firewall.WithoutZone), StringComparer.OrdinalIgnoreCase);
            var add = new List<string>();
            foreach (var x in sources.Where(x => x.Count >= s.BlockThreshold))
            {
                if (already.Contains(x.Address) || notBlockable(x.Address) || allow.Any(n => n.Contains(x.Address)) || live.Contains(x.Address)) continue;
                AgentState.BlockEntry b;
                if (!st.Blocks.TryGetValue(x.Address, out b) || b.LastStrike < now.AddDays(-7)) b = new AgentState.BlockEntry();
                b.Strikes = Math.Min(b.Strikes + 1, BlockTimes.Length); b.LastStrike = now; b.Until = now + BlockTimes[b.Strikes - 1];
                st.Blocks[x.Address] = b;
                add.Add(x.Address);
            }
            return add;
        }

        /// <summary>Adds partner uploads to the waiting list of each partner.</summary>
        internal static void AddPending(AgentState st, IEnumerable<TransferRecord> records, HashSet<string> partners)
        {
            foreach (var r in records.Where(x => x.Action == TransferRecord.Upload && partners.Contains(Accounts.AsciiLower(x.User))))
            {
                List<string> l;
                if (!st.Pending.TryGetValue(r.User, out l)) st.Pending[r.User] = l = new List<string>();
                l.Add(r.Time.ToString("yyyy-MM-ddTHH:mm:ss", CultureInfo.InvariantCulture) + "|" + r.File + "|" + r.Bytes.ToString(CultureInfo.InvariantCulture));
            }
        }

        /// <summary>The partners whose first waiting upload is at least 5 minutes old: their message goes now.</summary>
        internal static List<string> DuePending(AgentState st, DateTime now)
        {
            var due = new List<string>();
            foreach (var p in st.Pending.Where(p => p.Value.Count > 0))
            {
                DateTime first;
                var f = p.Value[0].Split('|');
                if (DateTime.TryParseExact(f[0], "yyyy-MM-ddTHH:mm:ss", CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out first) && now - first >= UploadBatch) due.Add(p.Key);
            }
            return due;
        }

        /// <summary>Watch and Daily advance the same journal, archive, and pending-upload transaction.</summary>
        internal static void CollectTransfers(AlertSettings s, AgentState st, DateTime now, TransferJournal.EventSource source = null, HashSet<string> partnerNames = null)
        {
            if (!st.Journal.NotifyFromUtc.HasValue)
            {
                st.Journal.NotifyFromUtc = now.ToUniversalTime().AddHours(-2);
                // Manager 2.2 and older archived transfers without this journal, from a start they did not record: no late start then.
                if (st.ArchivedUntil == DateTime.MinValue && st.ReportedMonth.Length == 0) st.Journal.StartedUtc = now.ToUniversalTime();
            }
            var records = TransferJournal.Read(st.Journal, now, source);
            Archive(records);
            st.LastRecordId = st.Journal.LastRecordId; // retained for older managers reading their compatibility field
            if (s.OnUploads)
            {
                var partners = partnerNames ?? new HashSet<string>(new[] { PartnerGroups.Default.Full, PartnerGroups.Default.ReadOnly }.SelectMany(LocalAccounts.GroupMembers).Select(Accounts.AsciiLower));
                // Backfill all retained transfers on first use, without sending old upload alerts.
                AddPending(st, records.Where(r => r.Time.ToUniversalTime() >= st.Journal.NotifyFromUtc.Value), partners);
            }
        }

        // ---------------- Each night ----------------
        public static void Daily(AlertSettings s, AgentState st, DateTime now)
        {
            CollectTransfers(s, st, now);
            if (st.Journal.Backlog == 0) st.ArchivedUntil = now.Date;
            // Archive files older than a year.
            try
            {
                if (Directory.Exists(TransferArchive.Dir))
                    foreach (var f in Directory.GetFiles(TransferArchive.Dir, "transfers-*.csv"))
                    {
                        DateTime month;
                        var name = Path.GetFileNameWithoutExtension(f).Substring(10);
                        if (DateTime.TryParseExact(name, "yyyy-MM", CultureInfo.InvariantCulture, DateTimeStyles.None, out month) && month.AddMonths(1) < now.AddDays(-TransferArchive.KeepDays)) { File.Delete(f); Note("deleted the old archive " + f); }
                    }
            }
            catch (Exception ex) { Note("cleaning the archive: " + ex.Message); }
            // The monthly report, on the 1st (or the first run after it) for the month before.
            var last = new DateTime(now.Year, now.Month, 1).AddMonths(-1);
            var key = last.ToString("yyyy-MM", CultureInfo.InvariantCulture);
            if (s.MonthlyReport && s.MailConfigured && st.ReportedMonth != key && st.Journal.Backlog == 0)
            {
                var to = last.AddMonths(1);
                var problems = new List<string>();
                var records = Transfers.Read(last, to, CancellationToken.None, problems);
                foreach (var p in problems) Note("the monthly report of " + key + ": " + p);
                // An archive file that cannot be read (open in another program) holds the report, which is tried again each night;
                // after a week it goes out saying what it lacks.
                if (problems.Count > 0 && now < to.AddDays(7)) return;
                var companies = Partners.List(PartnerGroups.Default).ToDictionary(p => p.Name, p => p.Company, StringComparer.OrdinalIgnoreCase);
                var html = Transfers.ReportHtml(records, last, to, Environment.MachineName, companies, ReportCaveats(st.Journal, last, to, problems));
                var csv = string.Join("\r\n", new[] { string.Join(",", Transfers.CsvHeader) }.Concat(records.Select(Transfers.CsvLine))) + "\r\n";
                var t = Transfers.Totals(records);
                NotificationOutbox.Enqueue(st, s, "monthly-report", "SFTP transfers of " + Environment.MachineName + ", " + last.ToString("MMMM yyyy", CultureInfo.InvariantCulture) + ": " + t.Sum(x => x.Uploads) + " up, " + t.Sum(x => x.Downloads) + " down",
                    null, html, AlertSettings.Addresses(s.AdminTo), "sftp-transfers-" + key + ".csv", csv, now.ToUniversalTime(), true);
                st.ReportedMonth = key; // queued durably with the report; retries no longer depend on another monthly run
            }
        }

        /// <summary>
        /// What the report of a period may lack: a gap in the event history since the period began, a journal that began after it,
        /// archive files that could not be read.
        /// </summary>
        internal static List<string> ReportCaveats(TransferJournalState journal, DateTime from, DateTime to, IEnumerable<string> problems)
        {
            Func<DateTime, string> local = utc => utc.ToLocalTime().ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture);
            var l = new List<string>();
            if (journal.Gap.Length > 0 && journal.GapUtc.HasValue && journal.GapUtc.Value >= from.ToUniversalTime())
                l.Add("History gap noticed " + local(journal.GapUtc.Value) + ": " + journal.Gap + " The figures may be incomplete.");
            if (journal.StartedUtc.HasValue && journal.StartedUtc.Value > from.ToUniversalTime())
                l.Add("The background agent began collecting transfers " + local(journal.StartedUtc.Value) + "; earlier transfers of the period come only from what the event log still held.");
            l.AddRange((problems ?? Enumerable.Empty<string>()).Select(p => "Not included: " + p));
            return l;
        }

        /// <summary>Appends records to the monthly CSV files, leaving out those already there. Returns how many were added.</summary>
        internal static int Archive(List<TransferRecord> records)
        {
            if (!Directory.Exists(TransferArchive.Dir)) AgentStorage.Permissions.CreateFolder(TransferArchive.Dir);
            int added = 0;
            foreach (var g in records.GroupBy(r => new DateTime(r.Time.Year, r.Time.Month, 1)))
            {
                var file = TransferArchive.FileOf(g.Key);
                // A partial append can join the next complete record to a torn CSV line. Replace the month atomically,
                // and never rewrite an unreadable archive as though it were empty.
                var existing = new List<TransferRecord>();
                if (File.Exists(file))
                    foreach (var line in File.ReadAllLines(file, Encoding.UTF8).Skip(1).Where(line => line.Length > 0))
                    { var record = Transfers.FromCsv(line); if (record == null) throw new InvalidDataException("Invalid transfer archive record in " + file); existing.Add(record); }
                var have = new HashSet<string>(existing.Select(r => r.Key));
                bool changed = false;
                foreach (var record in g)
                {
                    if (!have.Add(record.Key)) continue;
                    // Migrate each legacy descriptive record to at most one event identity. A second identical real
                    // event remains a second transfer; old archives that merged it can be repaired from retained logs.
                    int legacy = record.EventIdentity.Length == 0 ? -1 : existing.FindIndex(r => r.EventIdentity.Length == 0 && Transfers.LegacyKey(r) == Transfers.LegacyKey(record) && (r.Address.Length == 0 || r.Address == record.Address));
                    if (legacy >= 0) existing[legacy] = record;
                    else { existing.Add(record); added++; }
                    changed = true;
                }
                if (!changed) continue;
                Ini.WriteReplacing(file, writer =>
                {
                    writer.WriteLine(string.Join(",", Transfers.CsvHeader));
                    foreach (var record in existing.OrderBy(r => r.Time)) writer.WriteLine(Transfers.CsvLine(record));
                });
            }
            return added;
        }

        // ---------------- Sending ----------------
        private static void Tls12()
        {
            // TLS 1.2 (3072) and 1.3 (12288) where Windows has them; .NET Framework 4.x may default to older ones.
            try { ServicePointManager.SecurityProtocol |= (SecurityProtocolType)3072; } catch (NotSupportedException) { }
            try { ServicePointManager.SecurityProtocol |= (SecurityProtocolType)12288; } catch (NotSupportedException) { }
        }

        public static void SendMail(AlertSettings s, string subject, string text, string html, List<string> to, string attachmentName, string attachmentText, string notificationId = null)
        {
            Tls12();
            using (var m = new MailMessage { From = new MailAddress(s.From), Subject = subject, SubjectEncoding = Encoding.UTF8, BodyEncoding = Encoding.UTF8 })
            using (var c = new SmtpClient(s.SmtpHost, s.SmtpPort) { EnableSsl = s.SmtpTls, DeliveryMethod = SmtpDeliveryMethod.Network, Timeout = 30000 })
            {
                foreach (var a in to) m.To.Add(a);
                if (notificationId != null) { m.Headers.Add("X-OpenSSH-Notification-Id", notificationId); m.Headers.Add("Message-ID", "<" + notificationId + "@openssh-server-pn.local>"); }
                if (html != null) { m.Body = html; m.IsBodyHtml = true; } else m.Body = text + "\n\n-- \n" + Program.AppName + " on " + Environment.MachineName;
                if (attachmentName != null) m.Attachments.Add(Attachment.CreateAttachmentFromString(attachmentText, attachmentName, Encoding.UTF8, "text/csv"));
                if (s.SmtpUser.Length > 0) c.Credentials = new NetworkCredential(s.SmtpUser, s.SmtpPassword); else c.UseDefaultCredentials = false;
                c.Send(m);
            }
        }

        /// <summary>The webhook body: an Adaptive Card for Teams (Workflows), or {"text": ...} for Slack, Mattermost and most others.</summary>
        internal static string HookBody(bool teams, string subject, string text)
        {
            Func<string, string> j = v =>
            {
                var quoted = new StringBuilder("\"");
                foreach (char c in v ?? "")
                {
                    if (c == '\\' || c == '"') quoted.Append('\\').Append(c);
                    else if (c == '\n') quoted.Append("\\n");
                    else if (c == '\r') quoted.Append("\\r");
                    else if (c == '\t') quoted.Append("\\t");
                    else if (c < 32) quoted.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                    else quoted.Append(c);
                }
                return quoted.Append('"').ToString();
            };
            // Account and file names in alerts are chosen by whoever connects. Alerts use no markup of their own, so none of the
            // text may act as markup: no labelled links ("[Unlock](https://...)"), no Slack links or <!channel>, no @mentions.
            Func<string, string> inert = v =>
            {
                v = Regex.Replace(v ?? "", @"\]\s*\(", "]​(");
                v = Regex.Replace(v, @"@(?=\w)", "@​");
                // Bare addresses are linked (and previewed) too: break "scheme://" and the dots of host names, not those of IPv4 addresses.
                v = v.Replace("://", "://​");
                v = Regex.Replace(v, @"(?<=[\p{L}\p{N}_-])\.(?=\p{L})", "​.");
                return teams ? v : v.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;");
            };
            if (!teams) return "{\"text\":" + j(inert(subject + "\n" + text)) + "}";
            return "{\"type\":\"message\",\"attachments\":[{\"contentType\":\"application/vnd.microsoft.card.adaptive\",\"content\":{\"$schema\":\"http://adaptivecards.io/schemas/adaptive-card.json\",\"type\":\"AdaptiveCard\",\"version\":\"1.4\",\"body\":[" +
                   "{\"type\":\"TextBlock\",\"size\":\"Medium\",\"weight\":\"Bolder\",\"wrap\":true,\"text\":" + j(inert(subject)) + "},{\"type\":\"TextBlock\",\"wrap\":true,\"text\":" + j(inert(text).Replace("\n", "\n\n")) + "}]}}]}";
        }

        public static void SendHook(AlertSettings s, string subject, string text, string notificationId = null)
        {
            Tls12();
            var body = Encoding.UTF8.GetBytes(HookBody(s.WebhookTeams, subject, text));
            var req = (HttpWebRequest)WebRequest.Create(s.Webhook);
            req.Method = "POST"; req.ContentType = "application/json; charset=utf-8"; req.Timeout = 30000; req.ContentLength = body.Length; req.ServicePoint.Expect100Continue = false; req.UserAgent = Program.AppName + "/" + Program.AppVersion;
            req.ReadWriteTimeout = 30000;
            // A redirect would repeat the request as a GET without the alert, and its 200 would count as delivered.
            req.AllowAutoRedirect = false;
            if (notificationId != null) req.Headers.Add("Idempotency-Key", notificationId);
            using (var rs = req.GetRequestStream()) rs.Write(body, 0, body.Length);
            using (var resp = (HttpWebResponse)req.GetResponse()) { if ((int)resp.StatusCode >= 300) throw new WebException("HTTP " + (int)resp.StatusCode); }
        }

        // ---------------- The scheduled tasks ----------------
        /// <summary>
        /// Where the tasks run the manager from: the copy the MSI installs next to sshd.exe, else a copy of this program in
        /// %ProgramFiles%\OpenSSH Server PN Manager (made or updated here). The folder must be one only administrators can
        /// change: the tasks run it as SYSTEM.
        /// </summary>
        public static string AgentExe()
        {
            var installed = Ssh.Exe("OpenSSHServerPNManager.exe");
            if (File.Exists(installed)) return installed;
            var dir = PortableDir;
            var exe = Path.Combine(dir, "OpenSSHServerPNManager.exe");
            var me = System.Windows.Forms.Application.ExecutablePath;
            if (!string.Equals(Path.GetFullPath(me), exe, StringComparison.OrdinalIgnoreCase))
            {
                Directory.CreateDirectory(dir); // inherits the permissions of Program Files: only administrators change it
                File.Copy(me, exe, true);
                var cfg = me + ".config";
                if (File.Exists(cfg)) File.Copy(cfg, exe + ".config", true);
            }
            return exe;
        }

        internal static string TaskXml(string description, string exe, string arguments, bool everyMinute)
        {
            Func<string, string> x = System.Security.SecurityElement.Escape;
            // Daily starts half a minute after a Watch run, not with one: both take the state lock, and Watch gives up after a second.
            var start = DateTime.Today.ToString("yyyy-MM-ddT", CultureInfo.InvariantCulture) + (everyMinute ? "00:00:00" : "00:30:30");
            var triggers = everyMinute
                ? "<TimeTrigger><StartBoundary>" + start + "</StartBoundary><Enabled>true</Enabled><Repetition><Interval>PT1M</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition></TimeTrigger><BootTrigger><Enabled>true</Enabled><Delay>PT1M</Delay></BootTrigger>"
                : "<CalendarTrigger><StartBoundary>" + start + "</StartBoundary><Enabled>true</Enabled><ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay></CalendarTrigger>";
            return "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\r\n<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">" +
                   "<RegistrationInfo><Description>" + x(description) + "</Description></RegistrationInfo><Triggers>" + triggers + "</Triggers>" +
                   "<Principals><Principal id=\"Author\"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>" +
                   "<Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>" +
                   "<AllowHardTerminate>true</AllowHardTerminate><StartWhenAvailable>true</StartWhenAvailable><AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>false</Hidden>" +
                   "<ExecutionTimeLimit>" + (everyMinute ? "PT5M" : "PT1H") + "</ExecutionTimeLimit></Settings>" +
                   "<Actions Context=\"Author\"><Exec><Command>" + x(exe) + "</Command><Arguments>" + x(arguments) + "</Arguments></Exec></Actions></Task>";
        }

        public static void InstallTasks()
        {
            var exe = AgentExe();
            SystemTasks.RegisterXml(WatchTask, TaskXml("OpenSSH Server PN Manager: alerts and automatic blocking of addresses with many failed SSH logins (every minute).", exe, "--agent watch", true));
            SystemTasks.RegisterXml(DailyTask, TaskXml("OpenSSH Server PN Manager: the archive of SFTP transfers, and the monthly transfer report (each night).", exe, "--agent daily", false));
            Note("tasks installed, running " + exe);
        }

        public static void RemoveTasks()
        {
            SystemTasks.Delete(WatchTask); SystemTasks.Delete(DailyTask); DeleteTaskFolder();
            Note("tasks removed");
        }

        /// <summary>The folder of the two tasks in Task Scheduler, once it is empty (schtasks cannot delete folders).</summary>
        private static void DeleteTaskFolder()
        {
            try
            {
                dynamic service = Activator.CreateInstance(Type.GetTypeFromProgID("Schedule.Service"));
                service.Connect();
                service.GetFolder("\\").DeleteFolder(TaskFolder, 0);
            }
            catch { } // gone already, or not empty
        }

        public static bool TasksInstalled() { return SystemTasks.Exists(WatchTask) && SystemTasks.Exists(DailyTask); }

        private static string PortableDir { get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "OpenSSH Server PN Manager"); } }

        /// <summary>
        /// Tasks set up by the portable manager run its copy in %ProgramFiles%\OpenSSH Server PN Manager. Once a package has
        /// installed the manager next to sshd.exe, the next Watch run points both tasks at that one, which later packages keep
        /// up to date; the copy is removed by the uninstall step.
        /// </summary>
        private static void MoveToInstalled()
        {
            var installed = Ssh.Exe("OpenSSHServerPNManager.exe");
            var me = Path.GetFullPath(System.Windows.Forms.Application.ExecutablePath);
            if (!File.Exists(installed) || string.Equals(me, Path.GetFullPath(installed), StringComparison.OrdinalIgnoreCase)) return;
            if (!string.Equals(Path.GetDirectoryName(me), PortableDir, StringComparison.OrdinalIgnoreCase) || !TasksInstalled()) return;
            InstallTasks();
        }

        /// <summary>
        /// --agent uninstall: the package is being removed (not upgraded). Deletes the two tasks, which would otherwise start a
        /// missing program every minute, and the copy the portable manager made for them. Settings, state, the log and the
        /// transfer archive stay in %ProgramData%\ssh\manager, like sshd_config; ticking the box on the Alerts tab of a later
        /// installation sets the tasks up again with them.
        /// </summary>
        private static int Uninstall()
        {
            try
            {
                bool any = false;
                foreach (var t in new[] { WatchTask, DailyTask, ConfigurationRecovery.TaskName }) if (SystemTasks.Exists(t)) { any = true; if (!SystemTasks.Delete(t)) throw new Exception("schtasks /Delete " + t + " failed"); }
                DeleteTaskFolder();
                if (any) Note("OpenSSH Server PN is being uninstalled: tasks removed");
                foreach (var f in new[] { "OpenSSHServerPNManager.exe.config", "OpenSSHServerPNManager.exe" })
                {
                    var p = Path.Combine(PortableDir, f);
                    if (File.Exists(p)) try { File.Delete(p); } catch (Exception ex) { Note("could not remove " + p + ": " + ex.Message); }
                }
                if (Directory.Exists(PortableDir) && !Directory.EnumerateFileSystemEntries(PortableDir).Any()) Directory.Delete(PortableDir);
                return 0;
            }
            catch (Exception ex) { Note("the uninstall step failed: " + ex.Message); return 1; }
        }
    }
}

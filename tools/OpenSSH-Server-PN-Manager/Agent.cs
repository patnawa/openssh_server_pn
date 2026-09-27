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

        public static string Dir { get { return Path.Combine(Ssh.ConfigDir, "manager"); } }
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
            foreach (var line in File.ReadAllLines(path, Encoding.UTF8))
            {
                if (line.StartsWith("#")) continue;
                int i = line.IndexOf('=');
                if (i > 0) d[line.Substring(0, i).Trim()] = line.Substring(i + 1).Trim();
            }
            return d;
        }

        public static void Write(string path, IEnumerable<KeyValuePair<string, string>> values)
        {
            var dir = Path.GetDirectoryName(path);
            if (!Directory.Exists(dir)) Acl.CreatePrivateFolder(dir);
            var text = "# " + Program.AppName + ": written by the program, " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) + "\r\n" +
                       string.Concat(values.Select(kv => kv.Key + "=" + (kv.Value ?? "").Replace("\r", " ").Replace("\n", " ") + "\r\n"));
            var tmp = path + ".new";
            File.WriteAllText(tmp, text, new UTF8Encoding(false));
            Acl.Restrict(tmp, null);
            if (File.Exists(path)) File.Replace(tmp, path, null); else File.Move(tmp, path);
        }
    }

    /// <summary>What the agent remembers between runs.</summary>
    internal sealed class AgentState
    {
        public long LastRecordId; public string SshdStatus = ""; public DateTime? LastBurstAlert, DiskAlertDay, LastDiskCheck; public DateTime ArchivedUntil; public string ReportedMonth = "";
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
            Ini.Write(FilePath, d);
        }
    }

    internal static class Agent
    {
        public const string TaskFolder = "OpenSSH Server PN Manager";
        public static readonly string WatchTask = TaskFolder + "\\Watch", DailyTask = TaskFolder + "\\Daily";
        public static string LogPath { get { return Path.Combine(AlertSettings.Dir, "agent.log"); } }
        /// <summary>Block times after the first, second and third strike within a week.</summary>
        public static readonly TimeSpan[] BlockTimes = { TimeSpan.FromHours(1), TimeSpan.FromHours(24), TimeSpan.FromDays(7) };
        public static readonly TimeSpan UploadBatch = TimeSpan.FromMinutes(5);

        /// <summary>
        /// --agent watch | daily: what the scheduled tasks run; --agent uninstall: what the MSI runs (as SYSTEM) before it
        /// removes the program files. Returns the exit code.
        /// </summary>
        public static int Run(string job)
        {
            if (job == "uninstall") return Uninstall();
            try
            {
                if (job == "watch") MoveToInstalled();
                var s = AlertSettings.Load(); var st = AgentState.Load();
                if (job == "watch") Watch(s, st, DateTime.Now);
                else if (job == "daily") Daily(s, st, DateTime.Now);
                else { Note("unknown job " + job); return 2; }
                st.Save();
                return 0;
            }
            catch (Exception ex) { Note("the " + job + " run failed: " + ex); return 1; }
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
        public static void Watch(AlertSettings s, AgentState st, DateTime now)
        {
            var server = Environment.MachineName;
            // sshd stopped, or running again.
            var status = Services.Status("sshd");
            var current = status.Exists ? status.Status : "Not installed";
            if (s.OnSshdStopped && st.SshdStatus.Length > 0 && current != st.SshdStatus && (current == "Running" || st.SshdStatus == "Running"))
                Send(s, current == "Running" ? "sshd is running again on " + server : "sshd is not running on " + server + " (" + current + ")",
                     current == "Running" ? "The SSH server sshd on " + server + " is running again, since " + now.ToString("HH:mm") + "." : "The SSH server sshd on " + server + " stopped: " + current + " at " + now.ToString("yyyy-MM-dd HH:mm") + ". Nobody can log in or transfer files until it runs again.", null, null, null);
            st.SshdStatus = current;

            // Addresses blocked by the agent whose time is up.
            // (An entry stays a week after its block ends, with Until = MinValue, so that a new strike gets the next block time.)
            var expired = st.Blocks.Where(b => b.Value.Until != DateTime.MinValue && b.Value.Until <= now).Select(b => b.Key).ToList();
            if (expired.Count > 0)
            {
                var blocked = Firewall.BlockedAddresses();
                var left = blocked.Where(a => !expired.Contains(a)).ToList();
                if (left.Count != blocked.Count) Firewall.SetBlockedAddresses(left, BlockPorts());
                foreach (var a in expired) { Note("unblocked " + a + " (its time is up)"); st.Blocks[a].Until = DateTime.MinValue; }
            }
            foreach (var a in st.Blocks.Where(b => b.Value.Until == DateTime.MinValue && b.Value.LastStrike < now.AddDays(-7)).Select(b => b.Key).ToList()) st.Blocks.Remove(a);

            // Failed logins in the window: automatic blocking and bursts.
            if (s.AutoBlock || s.OnFailedLogins)
            {
                var events = EventLogs.Read(20000, null, TimeSpan.FromMinutes(s.BlockWindowMinutes), CancellationToken.None);
                var sources = EventLogs.FailedByAddress(events);
                if (s.AutoBlock) Block(s, st, sources, now, server);
                int total = sources.Sum(x => x.Count);
                if (s.OnFailedLogins && total >= s.BurstThreshold && (st.LastBurstAlert == null || st.LastBurstAlert < now.AddMinutes(-15)))
                {
                    st.LastBurstAlert = now;
                    Send(s, total + " failed logins on " + server + " in " + s.BlockWindowMinutes + " minutes",
                         total + " failed or abandoned SSH logins on " + server + " in the last " + s.BlockWindowMinutes + " minutes, from " + sources.Count + " address(es):\n" +
                         string.Join("\n", sources.Take(10).Select(x => "  " + x.Address + ": " + x.Count + (x.Users.Count > 0 ? " (accounts tried: " + string.Join(", ", x.Users.Take(5)) + ")" : ""))), null, null, null);
                }
            }

            // Partner uploads: collected per partner, reported once the first is 5 minutes old.
            var newEvents = ReadNewSftpEvents(st, now);
            if (s.OnUploads)
            {
                var partners = new HashSet<string>(new[] { PartnerGroups.Default.Full, PartnerGroups.Default.ReadOnly }.SelectMany(LocalAccounts.GroupMembers).Select(Accounts.AsciiLower));
                AddPending(st, Transfers.Parse(newEvents), partners);
                foreach (var p in DuePending(st, now))
                {
                    var items = st.Pending[p].Select(x => x.Split('|')).Where(x => x.Length == 3).ToList(); // file names cannot contain |
                    string to; s.PartnerNotify.TryGetValue(p, out to);
                    var total = items.Sum(x => { long b; return long.TryParse(x[2], out b) ? b : 0; });
                    var body = p + " uploaded " + items.Count + " file(s), " + Ui.Bytes(total) + ", to " + server + ":\n" + string.Join("\n", items.Take(50).Select(x => { long b; long.TryParse(x[2], out b); return "  " + x[0].Replace('T', ' ') + "  " + x[1] + "  (" + Ui.Bytes(b) + ")"; })) + (items.Count > 50 ? "\n  ... and " + (items.Count - 50) + " more" : "");
                    if (Send(s, "Files from " + p + " on " + server + ": " + items.Count + " new", body, null, string.IsNullOrWhiteSpace(to) ? null : AlertSettings.Addresses(to), null)) st.Pending.Remove(p);
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
                        Send(s, "Disk " + drive.Name + " of " + server + " is almost full (" + pct.ToString("0.0", CultureInfo.InvariantCulture) + "% free)",
                             "Drive " + drive.Name + " of " + server + ", which holds " + root + ", has " + Ui.Bytes(drive.AvailableFreeSpace) + " free of " + Ui.Bytes(drive.TotalSize) + ". Uploads fail when it is full.", null, null, null);
                    }
                }
                catch (Exception ex) { Note("disk check of " + root + ": " + ex.Message); }
            }
        }

        private static string PartnerRootFromConfig()
        {
            try { return PartnerSetup.Check(SshdConfig.Load(), PartnerGroups.Default).Root; } catch { return null; }
        }

        private static string BlockPorts() { try { return SshdConfig.Load().EffectivePort.ToString(CultureInfo.InvariantCulture); } catch { return "22"; } }

        /// <summary>
        /// Blocks the addresses with at least BlockThreshold failed logins in the window (sshd logs an attempt with an account
        /// that does not exist twice, so such attempts count double): 1 hour, then 24 hours, then 7 days within a week. Never
        /// blocked: the allow list, this computer, and addresses with a logged-in session.
        /// </summary>
        internal static List<string> Block(AlertSettings s, AgentState st, List<EventLogs.FailedSource> sources, DateTime now, string server)
        {
            var already = new HashSet<string>(Firewall.BlockedAddresses());
            var add = PlanBlocks(s, st, sources, now, already, LoggedInPeers(), a => Firewall.NotBlockable(a) != null);
            foreach (var a in add)
            {
                var x = sources.First(y => y.Address == a); var b = st.Blocks[a];
                Note("blocked " + a + " until " + b.Until.ToString("yyyy-MM-dd HH:mm") + " after " + x.Count + " failed logins (strike " + b.Strikes + ")");
                if (s.OnFailedLogins)
                    Send(s, "Blocked " + a + " on " + server, a + " is blocked from SSH on " + server + " until " + b.Until.ToString("yyyy-MM-dd HH:mm") + " after " + x.Count + " failed logins in " + s.BlockWindowMinutes + " minutes" +
                         (x.Users.Count > 0 ? " (accounts tried: " + string.Join(", ", x.Users.Take(8)) + ")" : "") + ". The Logs tab of OpenSSH Server PN Manager unblocks it.", null, null, null);
            }
            if (add.Count > 0) Firewall.SetBlockedAddresses(already.Concat(add).ToList(), BlockPorts());
            return add;
        }

        /// <summary>
        /// Which addresses to block now, and until when (written into the state): at least BlockThreshold failures, not
        /// blocked already, not on the allow list, not connected, not this computer. Strikes within a week give 1 hour, then
        /// 24 hours, then 7 days.
        /// </summary>
        internal static List<string> PlanBlocks(AlertSettings s, AgentState st, List<EventLogs.FailedSource> sources, DateTime now, HashSet<string> already, HashSet<string> connected, Func<string, bool> notBlockable)
        {
            var allow = s.AllowListEntries().Select(a => { Network n; return Network.TryParse(a, out n) ? n : null; }).Where(n => n != null).ToList();
            var add = new List<string>();
            foreach (var x in sources.Where(x => x.Count >= s.BlockThreshold))
            {
                if (already.Contains(x.Address) || notBlockable(x.Address) || allow.Any(n => n.Contains(x.Address)) || connected.Contains(x.Address)) continue;
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

        /// <summary>The client addresses of logged-in sessions: a working login shows the address is not an attacker's.</summary>
        private static HashSet<string> LoggedInPeers()
        {
            try { return Sessions.LoggedInAddresses(SshdConfig.Load().EffectivePort); }
            catch (Exception ex) { Note("the open sessions could not be read: " + ex.Message); return new HashSet<string>(); }
        }

        /// <summary>sftp-server events written since the last run (at most the last 2 hours on the first run).</summary>
        private static List<Transfers.SftpEvent> ReadNewSftpEvents(AgentState st, DateTime now)
        {
            var l = new List<Transfers.SftpEvent>();
            var xpath = st.LastRecordId > 0 ? "*[System[EventRecordID>" + st.LastRecordId.ToString(CultureInfo.InvariantCulture) + "]]" : "*[System[TimeCreated[timediff(@SystemTime) <= 7200000]]]";
            try
            {
                using (var reader = new EventLogReader(new EventLogQuery(EventLogs.LogName, PathType.LogName, xpath)))
                {
                    EventRecord r;
                    while ((r = reader.ReadEvent()) != null)
                    {
                        using (r)
                        {
                            if (r.RecordId.HasValue && r.RecordId.Value > st.LastRecordId) st.LastRecordId = r.RecordId.Value;
                            if (r.Properties.Count < 2 || Convert.ToString(r.Properties[0].Value) != "sftp-server") continue;
                            l.Add(new Transfers.SftpEvent { Time = r.TimeCreated ?? now, Pid = r.ProcessId ?? 0, Text = Convert.ToString(r.Properties[1].Value).Trim() });
                        }
                    }
                }
            }
            catch (EventLogNotFoundException) { }
            return l;
        }

        // ---------------- Each night ----------------
        public static void Daily(AlertSettings s, AgentState st, DateTime now)
        {
            // The archive: every whole day since the last run, one CSV file per month.
            var until = now.Date;
            var from = st.ArchivedUntil > DateTime.MinValue ? st.ArchivedUntil : until.AddDays(-1);
            if (from < until)
            {
                var records = Transfers.Parse(Transfers.ReadEvents(from, until, CancellationToken.None));
                int n = Archive(records);
                st.ArchivedUntil = until;
                Note("archived " + n + " transfer record(s) from " + from.ToString("yyyy-MM-dd") + " to " + until.AddDays(-1).ToString("yyyy-MM-dd"));
            }
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
            if (s.MonthlyReport && s.MailConfigured && st.ReportedMonth != key)
            {
                var to = last.AddMonths(1);
                var records = Transfers.Read(last, to, CancellationToken.None);
                var companies = Partners.List(PartnerGroups.Default).ToDictionary(p => p.Name, p => p.Company, StringComparer.OrdinalIgnoreCase);
                var html = Transfers.ReportHtml(records, last, to, Environment.MachineName, companies);
                var csv = string.Join("\r\n", new[] { string.Join(",", Transfers.CsvHeader) }.Concat(records.Select(Transfers.CsvLine))) + "\r\n";
                var t = Transfers.Totals(records);
                if (Mail(s, "SFTP transfers of " + Environment.MachineName + ", " + last.ToString("MMMM yyyy", CultureInfo.InvariantCulture) + ": " + t.Sum(x => x.Uploads) + " up, " + t.Sum(x => x.Downloads) + " down",
                         null, html, AlertSettings.Addresses(s.AdminTo), "sftp-transfers-" + key + ".csv", csv))
                    st.ReportedMonth = key;
            }
        }

        /// <summary>Appends records to the monthly CSV files, leaving out those already there. Returns how many were added.</summary>
        internal static int Archive(List<TransferRecord> records)
        {
            if (!Directory.Exists(TransferArchive.Dir)) Acl.CreatePrivateFolder(TransferArchive.Dir);
            int added = 0;
            foreach (var g in records.GroupBy(r => new DateTime(r.Time.Year, r.Time.Month, 1)))
            {
                var file = TransferArchive.FileOf(g.Key);
                var have = new HashSet<string>(TransferArchive.Read(g.Key, g.Key.AddMonths(1)).Select(r => r.Key));
                var lines = g.Where(r => have.Add(r.Key)).Select(Transfers.CsvLine).ToList();
                if (lines.Count == 0) continue;
                bool fresh = !File.Exists(file);
                File.AppendAllText(file, (fresh ? string.Join(",", Transfers.CsvHeader) + "\r\n" : "") + string.Join("\r\n", lines) + "\r\n", new UTF8Encoding(false));
                if (fresh) Acl.Restrict(file, null);
                added += lines.Count;
            }
            return added;
        }

        // ---------------- Sending ----------------
        /// <summary>An alert by e-mail and by webhook, as configured. True when at least one way worked (or none is configured).</summary>
        public static bool Send(AlertSettings s, string subject, string text, string html, List<string> to, string attachmentName)
        {
            bool any = false, ok = false;
            if (s.MailConfigured) { any = true; ok |= Mail(s, subject, text, html, to ?? AlertSettings.Addresses(s.AdminTo), null, null); }
            if (s.WebhookConfigured) { any = true; ok |= Hook(s, subject, text); }
            Note("alert: " + subject + (any ? (ok ? "" : " (NOT delivered)") : " (no mail or webhook set up)"));
            return ok || !any;
        }

        private static void Tls12()
        {
            // TLS 1.2 (3072) and 1.3 (12288) where Windows has them; .NET Framework 4.x may default to older ones.
            try { ServicePointManager.SecurityProtocol |= (SecurityProtocolType)3072; } catch (NotSupportedException) { }
            try { ServicePointManager.SecurityProtocol |= (SecurityProtocolType)12288; } catch (NotSupportedException) { }
        }

        public static bool Mail(AlertSettings s, string subject, string text, string html, List<string> to, string attachmentName, string attachmentText)
        {
            try { SendMail(s, subject, text, html, to, attachmentName, attachmentText); return true; }
            catch (Exception ex) { Note("mail \"" + subject + "\" to " + string.Join(", ", to) + " failed: " + ex.Message + (ex.InnerException != null ? " (" + ex.InnerException.Message + ")" : "")); return false; }
        }

        public static void SendMail(AlertSettings s, string subject, string text, string html, List<string> to, string attachmentName, string attachmentText)
        {
            Tls12();
            using (var m = new MailMessage { From = new MailAddress(s.From), Subject = subject, SubjectEncoding = Encoding.UTF8, BodyEncoding = Encoding.UTF8 })
            using (var c = new SmtpClient(s.SmtpHost, s.SmtpPort) { EnableSsl = s.SmtpTls, DeliveryMethod = SmtpDeliveryMethod.Network, Timeout = 30000 })
            {
                foreach (var a in to) m.To.Add(a);
                if (html != null) { m.Body = html; m.IsBodyHtml = true; } else m.Body = text + "\n\n-- \n" + Program.AppName + " on " + Environment.MachineName;
                if (attachmentName != null) m.Attachments.Add(Attachment.CreateAttachmentFromString(attachmentText, attachmentName, Encoding.UTF8, "text/csv"));
                if (s.SmtpUser.Length > 0) c.Credentials = new NetworkCredential(s.SmtpUser, s.SmtpPassword); else c.UseDefaultCredentials = false;
                c.Send(m);
            }
        }

        public static bool Hook(AlertSettings s, string subject, string text)
        {
            try { SendHook(s, subject, text); return true; }
            catch (Exception ex) { Note("webhook \"" + subject + "\" failed: " + ex.Message); return false; }
        }

        /// <summary>The webhook body: an Adaptive Card for Teams (Workflows), or {"text": ...} for Slack, Mattermost and most others.</summary>
        internal static string HookBody(bool teams, string subject, string text)
        {
            Func<string, string> j = v => "\"" + (v ?? "").Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\r", "").Replace("\n", "\\n").Replace("\t", "\\t") + "\"";
            if (!teams) return "{\"text\":" + j(subject + "\n" + text) + "}";
            return "{\"type\":\"message\",\"attachments\":[{\"contentType\":\"application/vnd.microsoft.card.adaptive\",\"content\":{\"$schema\":\"http://adaptivecards.io/schemas/adaptive-card.json\",\"type\":\"AdaptiveCard\",\"version\":\"1.4\",\"body\":[" +
                   "{\"type\":\"TextBlock\",\"size\":\"Medium\",\"weight\":\"Bolder\",\"wrap\":true,\"text\":" + j(subject) + "},{\"type\":\"TextBlock\",\"wrap\":true,\"text\":" + j(text.Replace("\n", "\n\n")) + "}]}}]}";
        }

        public static void SendHook(AlertSettings s, string subject, string text)
        {
            Tls12();
            var body = Encoding.UTF8.GetBytes(HookBody(s.WebhookTeams, subject, text));
            var req = (HttpWebRequest)WebRequest.Create(s.Webhook);
            req.Method = "POST"; req.ContentType = "application/json; charset=utf-8"; req.Timeout = 30000; req.ContentLength = body.Length; req.ServicePoint.Expect100Continue = false; req.UserAgent = Program.AppName + "/" + Program.AppVersion;
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
            var start = DateTime.Today.ToString("yyyy-MM-ddT", CultureInfo.InvariantCulture) + (everyMinute ? "00:00:00" : "00:30:00");
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
                foreach (var t in new[] { WatchTask, DailyTask }) if (SystemTasks.Exists(t)) { any = true; if (!SystemTasks.Delete(t)) throw new Exception("schtasks /Delete " + t + " failed"); }
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

// OpenSSH Server PN Manager: Transfers (the file transfer history of SFTP)

using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace OpenSSHServerPNManager
{
    // ------------------------------------------------------------------------------------------
    // With transfer logging on (sftp-server -l INFO), every SFTP session writes lines like these to OpenSSH/Operational,
    // all from the sftp-server process of the session (the event's process id):
    //   user: acme: session opened for local user acme from [203.0.113.7] [postauth]
    //   user: acme: open "/in/report.csv" flags WRITE,CREATE,TRUNCATE mode 0666 [postauth]
    //   user: acme: close "/in/report.csv" bytes read 0 written 52873 [postauth]
    //   user: acme: remove name "/old.csv" [postauth]
    //   user: acme: sent status Permission denied [postauth]
    // They are read into one record per transfer or change, with the client address of the session.
    // ------------------------------------------------------------------------------------------

    /// <summary>One file transfer or change over SFTP.</summary>
    internal sealed class TransferRecord
    {
        public DateTime Time; public string User = "", Address = "", Action = "", File = "", Detail = ""; public long Bytes;
        public const string Upload = "upload", Download = "download", Delete = "delete", Rename = "rename", NewFolder = "new folder", RemoveFolder = "remove folder", Refused = "refused";
        public bool IsTransfer { get { return Action == Upload || Action == Download; } }
        /// <summary>What makes two records the same one, to the second (the archive keeps seconds, the event log more).</summary>
        public string Key { get { return Time.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) + "\n" + User + "\n" + Action + "\n" + File + "\n" + Bytes; } }
    }

    /// <summary>What one account moved in a period.</summary>
    internal sealed class TransferTotals
    {
        public string User; public int Uploads, Downloads, Changes, Refused; public long UploadBytes, DownloadBytes; public DateTime? Last;
        public SortedSet<string> Addresses = new SortedSet<string>(StringComparer.Ordinal);
        public string Short { get { return Uploads + " up, " + Downloads + " down"; } }
    }

    internal static class Transfers
    {
        /// <summary>An sftp-server event: when, which process, and its text after "sftp-server".</summary>
        internal sealed class SftpEvent { public DateTime Time; public int Pid; public string Text; }

        private static readonly Regex Line = new Regex(@"^user: (?<user>.+?): (?<rest>.*?)(?: \[postauth\])?$", RegexOptions.Compiled);
        private static readonly Regex SessionOpened = new Regex(@"^session opened for local user .+ from \[(?<ip>[^\]]*)\]", RegexOptions.Compiled);
        private static readonly Regex Open = new Regex("^open \"(?<f>.*)\" flags (?<flags>\\S+)", RegexOptions.Compiled);
        private static readonly Regex Close = new Regex("^(?:forced )?close \"(?<f>.*)\" bytes read (?<r>\\d+) written (?<w>\\d+)$", RegexOptions.Compiled);
        private static readonly Regex Remove = new Regex("^remove name \"(?<f>.*)\"$", RegexOptions.Compiled);
        private static readonly Regex Rename = new Regex("^(?:posix-)?rename old \"(?<o>.*)\" new \"(?<n>.*)\"$", RegexOptions.Compiled);
        private static readonly Regex Mkdir = new Regex("^mkdir name \"(?<f>.*)\"", RegexOptions.Compiled);
        private static readonly Regex Rmdir = new Regex("^rmdir name \"(?<f>.*)\"$", RegexOptions.Compiled);

        /// <summary>Records from sftp-server events in the order they were written (oldest first).</summary>
        public static List<TransferRecord> Parse(IEnumerable<SftpEvent> events)
        {
            var l = new List<TransferRecord>();
            var address = new Dictionary<int, string>(); var lastOpen = new Dictionary<int, KeyValuePair<string, string>>(); // pid => (file, flags)
            var active = new Dictionary<int, List<KeyValuePair<string, string>>>();
            foreach (var e in events)
            {
                var m = Line.Match(e.Text ?? "");
                if (!m.Success) continue;
                var user = m.Groups["user"].Value; var rest = m.Groups["rest"].Value;
                List<KeyValuePair<string, string>> files;
                if (!active.TryGetValue(e.Pid, out files)) active[e.Pid] = files = new List<KeyValuePair<string, string>>();
                // Only the preceding open request can be identified as refused. VERBOSE/DEBUG3 may emit
                // explanatory lines before its status; those lines do not start another request.
                KeyValuePair<string, string> pending;
                bool hadPending = lastOpen.TryGetValue(e.Pid, out pending);
                if (rest == "Refusing open request in read-only mode" || Regex.IsMatch(rest, @"^request \d+: sent status \d+$")) continue;
                lastOpen.Remove(e.Pid);
                Func<string, string, long, string, TransferRecord> rec = (action, file, bytes, detail) =>
                {
                    string ip; address.TryGetValue(e.Pid, out ip);
                    return new TransferRecord { Time = e.Time, User = user, Address = ip ?? "", Action = action, File = file, Bytes = bytes, Detail = detail ?? "" };
                };
                Match x;
                if ((x = SessionOpened.Match(rest)).Success) { address[e.Pid] = x.Groups["ip"].Value; files.Clear(); continue; }
                if (rest.StartsWith("session closed for local user ", StringComparison.Ordinal)) { address.Remove(e.Pid); active.Remove(e.Pid); continue; }
                if ((x = Open.Match(rest)).Success)
                {
                    var openedFile = new KeyValuePair<string, string>(x.Groups["f"].Value, x.Groups["flags"].Value);
                    lastOpen[e.Pid] = openedFile; files.Add(openedFile); continue;
                }
                if ((x = Close.Match(rest)).Success)
                {
                    long read = long.Parse(x.Groups["r"].Value, CultureInfo.InvariantCulture), written = long.Parse(x.Groups["w"].Value, CultureInfo.InvariantCulture);
                    var file = x.Groups["f"].Value;
                    int index = files.FindIndex(o => o.Key == file);
                    bool forWriting = index >= 0 && files[index].Value.Contains("WRITE");
                    if (written > 0 || forWriting && read == 0) l.Add(rec(TransferRecord.Upload, file, written, null));
                    if (read > 0) l.Add(rec(TransferRecord.Download, file, read, null));
                    if (index >= 0) files.RemoveAt(index);
                    continue;
                }
                if ((x = Remove.Match(rest)).Success) { l.Add(rec(TransferRecord.Delete, x.Groups["f"].Value, 0, null)); continue; }
                if ((x = Rename.Match(rest)).Success) { l.Add(rec(TransferRecord.Rename, x.Groups["n"].Value, 0, "from " + x.Groups["o"].Value)); continue; }
                if ((x = Mkdir.Match(rest)).Success) { l.Add(rec(TransferRecord.NewFolder, x.Groups["f"].Value, 0, null)); continue; }
                if ((x = Rmdir.Match(rest)).Success) { l.Add(rec(TransferRecord.RemoveFolder, x.Groups["f"].Value, 0, null)); continue; }
                if (rest.StartsWith("sent status Permission denied", StringComparison.Ordinal))
                {
                    // The file opened just before was refused: an upload or a download the account may not make. Other refusals
                    // (a folder outside its own, a change in download-only mode) name no file in the log and are left out.
                    if (hadPending)
                    {
                        l.Add(rec(TransferRecord.Refused, pending.Key, 0, pending.Value.Contains("WRITE") ? "upload refused" : "download refused"));
                        int index = files.FindLastIndex(o => o.Equals(pending));
                        if (index >= 0) files.RemoveAt(index);
                    }
                }
                else if (hadPending && rest.StartsWith("sent status ", StringComparison.Ordinal) && rest != "sent status Success")
                {
                    int index = files.FindLastIndex(o => o.Equals(pending));
                    if (index >= 0) files.RemoveAt(index);
                }
            }
            return l;
        }

        /// <summary>
        /// The sftp-server events of a period from the event log, oldest first. The filter on the provider's first value
        /// ("sftp-server") runs inside the event log service, so a large log is read quickly.
        /// </summary>
        public static List<SftpEvent> ReadEvents(DateTime from, DateTime to, CancellationToken cancel)
        {
            var l = new List<SftpEvent>();
            var xpath = "*[System[TimeCreated[@SystemTime>='" + from.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ", CultureInfo.InvariantCulture) + "' and @SystemTime<'" +
                        to.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ", CultureInfo.InvariantCulture) + "']]] and *[EventData[Data='sftp-server']]";
            try
            {
                using (var reader = new EventLogReader(new EventLogQuery(EventLogs.LogName, PathType.LogName, xpath)))
                {
                    EventRecord r;
                    while (!cancel.IsCancellationRequested && (r = reader.ReadEvent()) != null)
                    {
                        using (r)
                        {
                            string text = null;
                            try { if (r.Properties.Count > 1) text = Convert.ToString(r.Properties[1].Value); } catch { }
                            if (text == null) continue;
                            l.Add(new SftpEvent { Time = r.TimeCreated ?? DateTime.MinValue, Pid = r.ProcessId ?? 0, Text = text.Trim() });
                        }
                    }
                }
            }
            catch (EventLogNotFoundException) { }
            return l;
        }

        /// <summary>The transfers of a period: the event log, and the archive for what the log no longer has.</summary>
        public static List<TransferRecord> Read(DateTime from, DateTime to, CancellationToken cancel)
        {
            var fromLog = Parse(ReadEvents(from, to, cancel));
            var seen = new HashSet<string>(fromLog.Select(r => r.Key));
            var archived = TransferArchive.Read(from, to).Where(r => !seen.Contains(r.Key));
            return archived.Concat(fromLog).OrderBy(r => r.Time).ToList();
        }

        /// <summary>Totals per account, the busiest first.</summary>
        public static List<TransferTotals> Totals(IEnumerable<TransferRecord> records)
        {
            var d = new Dictionary<string, TransferTotals>(StringComparer.OrdinalIgnoreCase);
            foreach (var r in records)
            {
                TransferTotals t;
                if (!d.TryGetValue(r.User, out t)) d[r.User] = t = new TransferTotals { User = r.User };
                if (r.Action == TransferRecord.Upload) { t.Uploads++; t.UploadBytes += r.Bytes; }
                else if (r.Action == TransferRecord.Download) { t.Downloads++; t.DownloadBytes += r.Bytes; }
                else if (r.Action == TransferRecord.Refused) t.Refused++;
                else t.Changes++;
                if (r.Address.Length > 0) t.Addresses.Add(r.Address);
                if (t.Last == null || r.Time > t.Last) t.Last = r.Time;
            }
            return d.Values.OrderByDescending(t => t.UploadBytes + t.DownloadBytes).ThenBy(t => t.User, StringComparer.OrdinalIgnoreCase).ToList();
        }

        // ---------------- The report ----------------
        private static string H(string s) { return System.Net.WebUtility.HtmlEncode(s ?? ""); }

        /// <summary>
        /// The transfer report of a period as an HTML page (also the body of the monthly e-mail): totals per account with
        /// its company, the busiest days, and where the figures come from. Every name and path is HTML-encoded.
        /// </summary>
        public static string ReportHtml(List<TransferRecord> records, DateTime from, DateTime to, string server, IDictionary<string, string> companies)
        {
            var totals = Totals(records);
            var sb = new StringBuilder();
            var period = from.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) + " to " + to.AddSeconds(-1).ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
            sb.Append("<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>SFTP transfers ").Append(H(server)).Append(", ").Append(H(period)).Append("</title>");
            sb.Append("<style>body{font-family:Segoe UI,Arial,sans-serif;font-size:14px;color:#1b1b1b;margin:24px}h1{font-size:20px}h2{font-size:16px;margin-top:24px}" +
                      "table{border-collapse:collapse}th,td{border:1px solid #ccc;padding:4px 8px;text-align:left}td.n{text-align:right}th{background:#f0f0f0}p.note{color:#666}</style></head><body>");
            sb.Append("<h1>SFTP transfers of ").Append(H(server)).Append("</h1><p>").Append(H(period)).Append(": ");
            sb.Append(totals.Sum(t => t.Uploads)).Append(" file(s) uploaded (").Append(H(Ui.Bytes(totals.Sum(t => t.UploadBytes)))).Append("), ");
            sb.Append(totals.Sum(t => t.Downloads)).Append(" downloaded (").Append(H(Ui.Bytes(totals.Sum(t => t.DownloadBytes)))).Append("), by ").Append(totals.Count).Append(" account(s).</p>");
            sb.Append("<h2>Per account</h2><table><tr><th>Account</th><th>Company</th><th>Uploads</th><th>Uploaded</th><th>Downloads</th><th>Downloaded</th><th>Other changes</th><th>Refused</th><th>Addresses</th><th>Last activity</th></tr>");
            foreach (var t in totals)
            {
                string company; if (companies == null || !companies.TryGetValue(t.User, out company)) company = "";
                sb.Append("<tr><td>").Append(H(t.User)).Append("</td><td>").Append(H(company)).Append("</td><td class=n>").Append(t.Uploads).Append("</td><td class=n>").Append(H(Ui.Bytes(t.UploadBytes)))
                  .Append("</td><td class=n>").Append(t.Downloads).Append("</td><td class=n>").Append(H(Ui.Bytes(t.DownloadBytes))).Append("</td><td class=n>").Append(t.Changes)
                  .Append("</td><td class=n>").Append(t.Refused).Append("</td><td>").Append(H(string.Join(", ", t.Addresses.Take(5)) + (t.Addresses.Count > 5 ? ", ..." : "")))
                  .Append("</td><td>").Append(t.Last == null ? "" : H(t.Last.Value.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture))).Append("</td></tr>");
            }
            sb.Append("</table>");
            var days = records.Where(r => r.IsTransfer).GroupBy(r => r.Time.Date).Select(g => new { Day = g.Key, Files = g.Count(), Bytes = g.Sum(r => r.Bytes) }).OrderByDescending(d => d.Bytes).Take(5).ToList();
            if (days.Count > 0)
            {
                sb.Append("<h2>Busiest days</h2><table><tr><th>Day</th><th>Files</th><th>Size</th></tr>");
                foreach (var d in days) sb.Append("<tr><td>").Append(d.Day.ToString("yyyy-MM-dd dddd", CultureInfo.InvariantCulture)).Append("</td><td class=n>").Append(d.Files).Append("</td><td class=n>").Append(H(Ui.Bytes(d.Bytes))).Append("</td></tr>");
                sb.Append("</table>");
            }
            sb.Append("<p class=note>From the OpenSSH event log (sftp-server -l INFO) and the archive in ").Append(H(TransferArchive.Dir)).Append(". Made by ").Append(H(Program.AppName + " " + Program.AppVersion)).Append(".</p></body></html>");
            return sb.ToString();
        }

        // ---------------- CSV ----------------
        public static readonly string[] CsvHeader = { "Time", "Account", "Address", "Action", "File", "Bytes", "Detail" };

        public static string CsvLine(TransferRecord r)
        {
            return string.Join(",", new[] { r.Time.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture), r.User, r.Address, r.Action, r.File, r.Bytes.ToString(CultureInfo.InvariantCulture), r.Detail }.Select(CsvField));
        }

        /// <summary>A CSV field: quoted when needed; a leading = + - @ gets a ' so that spreadsheets do not run it as a formula.</summary>
        public static string CsvField(string s)
        {
            s = s ?? "";
            if (s.Any(char.IsControl)) s = new string(s.Select(c => char.IsControl(c) ? '?' : c).ToArray()); // one record per line in the archive
            if (s.Length > 0 && "=+-@\t\r".IndexOf(s[0]) >= 0 && !Regex.IsMatch(s, @"^-?\d+$")) s = "'" + s;
            return s.IndexOfAny(new[] { ',', '"', '\r', '\n' }) >= 0 ? "\"" + s.Replace("\"", "\"\"") + "\"" : s;
        }

        /// <summary>Splits one CSV line as CsvLine writes it.</summary>
        public static List<string> CsvSplit(string line)
        {
            var l = new List<string>(); var sb = new StringBuilder(); bool quoted = false;
            for (int i = 0; i < line.Length; i++)
            {
                char c = line[i];
                if (quoted) { if (c == '"') { if (i + 1 < line.Length && line[i + 1] == '"') { sb.Append('"'); i++; } else quoted = false; } else sb.Append(c); }
                else if (c == '"') quoted = true;
                else if (c == ',') { l.Add(sb.ToString()); sb.Clear(); }
                else sb.Append(c);
            }
            l.Add(sb.ToString());
            return l;
        }

        public static TransferRecord FromCsv(string line)
        {
            var f = CsvSplit(line);
            if (f.Count < 7) return null;
            DateTime t; long b;
            if (!DateTime.TryParseExact(f[0], "yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out t) || !long.TryParse(f[5], NumberStyles.None, CultureInfo.InvariantCulture, out b)) return null;
            Func<string, string> un = s => s.StartsWith("'") && s.Length > 1 && "=+-@\t\r".IndexOf(s[1]) >= 0 ? s.Substring(1) : s;
            return new TransferRecord { Time = t, User = un(f[1]), Address = un(f[2]), Action = un(f[3]), File = un(f[4]), Bytes = b, Detail = un(f[6]) };
        }

        // ---------------- The OpenSSH event log's size ----------------
        /// <summary>100 MB: some 200,000 events, weeks to months of a busy SFTP server (the log starts at 1 MB, about 2,000).</summary>
        public const long WantedLogBytes = 100L << 20;

        public static long LogSize()
        {
            try { using (var c = new EventLogConfiguration(EventLogs.LogName)) return c.MaximumSizeInBytes; }
            catch { return 0; }
        }

        /// <summary>Makes the OpenSSH event log keep 100 MB (older events are overwritten after that). True when it changed.</summary>
        public static bool EnlargeLog()
        {
            using (var c = new EventLogConfiguration(EventLogs.LogName))
            {
                if (c.MaximumSizeInBytes >= WantedLogBytes) return false;
                c.MaximumSizeInBytes = WantedLogBytes;
                c.SaveChanges();
                Log.Info("The " + EventLogs.LogName + " event log keeps " + Ui.Bytes(WantedLogBytes) + " now");
                return true;
            }
        }
    }

    /// <summary>
    /// The archive of transfers: one CSV file per month in %ProgramData%\ssh\transfers (administrators only), written each
    /// night by a scheduled task from the event log, kept for a year. It keeps the history when the event log overwrites
    /// its oldest events, and it is what the monthly report is made from.
    /// </summary>
    internal static class TransferArchive
    {
        public static string Dir { get { return Path.Combine(Ssh.ConfigDir, "transfers"); } }
        public const int KeepDays = 365;
        public static string FileOf(DateTime month) { return Path.Combine(Dir, "transfers-" + month.ToString("yyyy-MM", CultureInfo.InvariantCulture) + ".csv"); }

        public static List<TransferRecord> Read(DateTime from, DateTime to)
        {
            var l = new List<TransferRecord>();
            for (var m = new DateTime(from.Year, from.Month, 1); m < to; m = m.AddMonths(1))
            {
                var f = FileOf(m);
                if (!File.Exists(f)) continue;
                try
                {
                    foreach (var line in File.ReadAllLines(f, Encoding.UTF8).Skip(1))
                    {
                        var r = Transfers.FromCsv(line);
                        if (r != null && r.Time >= from && r.Time < to) l.Add(r);
                    }
                }
                catch (Exception ex) { Log.Error("Reading " + f, ex, false); }
            }
            return l;
        }
    }
}

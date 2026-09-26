// OpenSSH Server Manager for Windows: Widgets (list sorting, export)

using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Windows.Forms;

namespace OpenSSHServerManager
{
    /// <summary>Sorting of list columns by a click on the header: numbers as numbers, dates as dates, text without case.</summary>
    internal sealed class ListSorter : IComparer
    {
        private static readonly HashSet<ListView> Unsortable = new HashSet<ListView>();
        public readonly int Column; public readonly bool Ascending;
        private ListSorter(int column, bool ascending) { Column = column; Ascending = ascending; }

        /// <summary>A list whose order means something (the rules of the Authentication tab: the first match applies).</summary>
        public static void Disable(ListView lv) { Unsortable.Add(lv); lv.Disposed += (s, e) => Unsortable.Remove((ListView)s); }

        /// <summary>Sorts by the column, or the other way round when it is sorted by that column already.</summary>
        public static void Toggle(ListView lv, int column)
        {
            if (Unsortable.Contains(lv)) return;
            var cur = lv.ListViewItemSorter as ListSorter;
            lv.ListViewItemSorter = new ListSorter(column, cur == null || cur.Column != column || !cur.Ascending);
            lv.Sort();
            for (int i = 0; i < lv.Columns.Count; i++)
            {
                var t = lv.Columns[i].Text.TrimEnd(' ', '▲', '▼');
                lv.Columns[i].Text = i == column ? t + (((ListSorter)lv.ListViewItemSorter).Ascending ? " ▲" : " ▼") : t;
            }
        }

        public int Compare(object x, object y)
        {
            var a = Cell((ListViewItem)x); var b = Cell((ListViewItem)y);
            int r = CompareText(a, b);
            return Ascending ? r : -r;
        }

        private string Cell(ListViewItem i) { return Column < i.SubItems.Count ? i.SubItems[Column].Text : ""; }

        internal static int CompareText(string a, string b)
        {
            double da, db;
            if (double.TryParse(a, NumberStyles.Float, CultureInfo.InvariantCulture, out da) && double.TryParse(b, NumberStyles.Float, CultureInfo.InvariantCulture, out db)) return da.CompareTo(db);
            DateTime ta, tb;
            if (DateTime.TryParseExact(a, "yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture, DateTimeStyles.None, out ta) && DateTime.TryParseExact(b, "yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture, DateTimeStyles.None, out tb)) return ta.CompareTo(tb);
            return string.Compare(a, b, StringComparison.OrdinalIgnoreCase);
        }
    }

    /// <summary>Lists written to files: CSV (Excel, scripts), tab-separated text, or an HTML page to read or print.</summary>
    internal static class Export
    {
        public static string Csv(IList<string> header, IEnumerable<IList<string>> rows)
        {
            Func<string, string> q = v => { v = Neutralise(v); return v.IndexOfAny(new[] { ',', '"', '\r', '\n' }) >= 0 || v.StartsWith("'") || v.StartsWith("-") ? "\"" + v.Replace("\"", "\"\"") + "\"" : v; };
            var sb = new StringBuilder();
            sb.Append(string.Join(",", header.Select(q))).Append("\r\n");
            foreach (var r in rows) sb.Append(string.Join(",", r.Select(q))).Append("\r\n");
            return sb.ToString();
        }

        /// <summary>
        /// A cell that a spreadsheet would run as a formula (CSV injection: =, +, -, @, or a tab or carriage return before
        /// them) gets a leading apostrophe. Event messages contain text chosen by clients (user names), so this matters.
        /// </summary>
        internal static string Neutralise(string v)
        {
            v = v ?? "";
            return v.Length > 0 && "=+-@\t\r".IndexOf(v[0]) >= 0 && !Regexish.IsNumber(v) ? "'" + v : v;
        }

        public static string Html(string title, string intro, IList<string> header, IEnumerable<IList<string>> rows, Func<IList<string>, string> rowClass = null)
        {
            Func<string, string> h = System.Net.WebUtility.HtmlEncode;
            var sb = new StringBuilder();
            sb.Append("<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><title>").Append(h(title)).Append("</title>\n<style>")
              .Append("body{font:14px Segoe UI,sans-serif;margin:24px;color:#1b1b1b}h1{font-size:20px}table{border-collapse:collapse;width:100%}")
              .Append("th,td{border:1px solid #ccc;padding:4px 8px;text-align:left;vertical-align:top}th{background:#f0f0f0}")
              .Append("tr.ok td:nth-child(2){color:#0a7a0a}tr.warn td:nth-child(2){color:#b35900;font-weight:600}tr.error td{color:#b00000}")
              .Append("@media (prefers-color-scheme:dark){body{background:#1e1e1e;color:#e8e8e8}th{background:#333}th,td{border-color:#555}}</style></head><body>\n");
            sb.Append("<h1>").Append(h(title)).Append("</h1>\n<p>").Append(h(intro)).Append("</p>\n<table><thead><tr>");
            foreach (var c in header) sb.Append("<th>").Append(h(c)).Append("</th>");
            sb.Append("</tr></thead><tbody>\n");
            foreach (var r in rows)
            {
                var cls = rowClass == null ? null : rowClass(r);
                sb.Append(cls == null ? "<tr>" : "<tr class=\"" + cls + "\">");
                foreach (var c in r) sb.Append("<td>").Append(h(c ?? "")).Append("</td>");
                sb.Append("</tr>\n");
            }
            sb.Append("</tbody></table>\n</body></html>\n");
            return sb.ToString();
        }

        public static List<IList<string>> Rows(ListView lv)
        {
            return lv.Items.Cast<ListViewItem>().Select(i => (IList<string>)i.SubItems.Cast<ListViewItem.ListViewSubItem>().Select(s => s.Text).ToList()).ToList();
        }

        public static List<string> Header(ListView lv) { return lv.Columns.Cast<ColumnHeader>().Select(c => c.Text.TrimEnd(' ', '▲', '▼')).ToList(); }

        /// <summary>Asks for a file name and writes a list as CSV or HTML (by the extension chosen). Returns the file, or null.</summary>
        public static string SaveList(IWin32Window owner, string title, string baseName, string intro, ListView lv, Func<IList<string>, string> rowClass = null)
        {
            using (var dlg = new SaveFileDialog { Title = title, FileName = baseName + "-" + DateTime.Now.ToString("yyyyMMdd-HHmmss"), Filter = "CSV file (*.csv)|*.csv|Web page (*.html)|*.html|Text, tab-separated (*.txt)|*.txt", AddExtension = true, OverwritePrompt = true })
            {
                if (dlg.ShowDialog(owner) != DialogResult.OK) return null;
                var header = Header(lv); var rows = Rows(lv);
                var ext = Path.GetExtension(dlg.FileName).ToLowerInvariant();
                string text = ext == ".html" || ext == ".htm" ? Html(title, intro, header, rows, rowClass)
                            : ext == ".txt" ? string.Join("\t", header) + "\r\n" + string.Join("", rows.Select(r => string.Join("\t", r.Select(v => Neutralise((v ?? "").Replace('\t', ' ').Replace('\r', ' ').Replace('\n', ' ')))) + "\r\n"))
                            : Csv(header, rows);
                // UTF-8 with a byte order mark: Excel then reads non-ASCII names correctly.
                File.WriteAllText(dlg.FileName, text, new UTF8Encoding(ext == ".csv"));
                return dlg.FileName;
            }
        }
    }

    internal static class Regexish
    {
        public static bool IsNumber(string v) { double d; return double.TryParse(v, NumberStyles.Float, CultureInfo.InvariantCulture, out d); }
    }
}

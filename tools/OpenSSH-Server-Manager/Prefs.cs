// OpenSSH Server Manager for Windows: Prefs, Diff

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Microsoft.Win32;

namespace OpenSSHServerManager
{
    // ------------------------------------------------------------------------------------------
    // Preferences of the person using the manager (HKCU\Software\OpenSSH Server Manager)
    // ------------------------------------------------------------------------------------------
    internal static class Prefs
    {
        private const string KeyPath = @"Software\OpenSSH Server Manager";
        /// <summary>Unattended modes (tests, --check, --screenshot) never read or write the registry: they see the defaults and their own changes.</summary>
        private static readonly Dictionary<string, object> Memory = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);

        private static object Read(string name)
        {
            lock (Memory) { object v; if (Memory.TryGetValue(name, out v)) return v; }
            if (Program.Unattended) return null;
            try { using (var k = Registry.CurrentUser.OpenSubKey(KeyPath)) return k == null ? null : k.GetValue(name); } catch { return null; }
        }

        private static void Write(string name, object value)
        {
            if (Program.Unattended) { lock (Memory) Memory[name] = value; return; }
            try
            {
                using (var k = Registry.CurrentUser.CreateSubKey(KeyPath))
                {
                    if (value is bool) k.SetValue(name, (bool)value ? 1 : 0, RegistryValueKind.DWord);
                    else if (value is int) k.SetValue(name, (int)value, RegistryValueKind.DWord);
                    else k.SetValue(name, Convert.ToString(value), RegistryValueKind.String);
                }
            }
            catch (Exception ex) { Log.Error("Could not save the preference " + name, ex, false); }
        }

        private static bool Bool(string name, bool def) { var v = Read(name); return v is int ? (int)v != 0 : v is bool ? (bool)v : def; }
        private static int Int(string name, int def, int min, int max) { var v = Read(name); return v is int ? Math.Max(min, Math.Min(max, (int)v)) : def; }
        private static string Str(string name, string def) { var v = Read(name) as string; return string.IsNullOrEmpty(v) ? def : v; }

        /// <summary>Show the changes to sshd_config and ask before every save.</summary>
        public static bool PreviewChanges { get { return Bool("PreviewChanges", true); } set { Write("PreviewChanges", value); } }
        /// <summary>After a restart with new settings, ask to keep them and restore the previous file when nobody answers.</summary>
        public static bool ConfirmAfterRestart { get { return Bool("ConfirmAfterRestart", true); } set { Write("ConfirmAfterRestart", value); } }
        /// <summary>Seconds before the previous settings come back when the question after a restart is not answered.</summary>
        public static int ConfirmSeconds { get { return Int("ConfirmSeconds", 60, 15, 600); } set { Write("ConfirmSeconds", value); } }
        /// <summary>"system", "light" or "dark".</summary>
        public static string Theme { get { return Str("Theme", "system"); } set { Write("Theme", value); } }
        /// <summary>An icon in the notification area while the manager runs, with the service state and notifications.</summary>
        public static bool TrayIcon { get { return Bool("TrayIcon", true); } set { Write("TrayIcon", value); } }
        /// <summary>Minimizing hides the window; the icon in the notification area brings it back.</summary>
        public static bool MinimizeToTray { get { return Bool("MinimizeToTray", false); } set { Write("MinimizeToTray", value); } }
        /// <summary>Notify when this many failed logins arrive within FailedLoginMinutes (0 = never).</summary>
        public static int FailedLoginThreshold { get { return Int("FailedLoginThreshold", 10, 0, 100000); } set { Write("FailedLoginThreshold", value); } }
        public static int FailedLoginMinutes { get { return Int("FailedLoginMinutes", 5, 1, 1440); } set { Write("FailedLoginMinutes", value); } }
        /// <summary>The setup wizard was offered once already.</summary>
        public static bool WizardOffered { get { return Bool("WizardOffered", false); } set { Write("WizardOffered", value); } }
    }

    // ------------------------------------------------------------------------------------------
    // Line differences (for the preview before saving and the backup browser)
    // ------------------------------------------------------------------------------------------
    internal sealed class DiffLine { public char Kind; public string Text; public int OldNo; public int NewNo; }

    internal static class Diff
    {
        /// <summary>
        /// The lines of two texts, each marked ' ' (in both), '-' (only in the old one) or '+' (only in the new one), from the
        /// longest common subsequence of lines. Texts longer than maxLines lines are compared as wholes (every line changed).
        /// </summary>
        public static List<DiffLine> Lines(IList<string> a, IList<string> b, int maxLines = 6000)
        {
            var l = new List<DiffLine>();
            // Common head and tail first: a typical edit changes a few lines of a long file.
            int head = 0; while (head < a.Count && head < b.Count && a[head] == b[head]) head++;
            int tail = 0; while (tail < a.Count - head && tail < b.Count - head && a[a.Count - 1 - tail] == b[b.Count - 1 - tail]) tail++;
            for (int i = 0; i < head; i++) l.Add(new DiffLine { Kind = ' ', Text = a[i], OldNo = i + 1, NewNo = i + 1 });
            int n = a.Count - head - tail, m = b.Count - head - tail;
            if (n > maxLines || m > maxLines)
            {
                for (int i = 0; i < n; i++) l.Add(new DiffLine { Kind = '-', Text = a[head + i], OldNo = head + i + 1 });
                for (int j = 0; j < m; j++) l.Add(new DiffLine { Kind = '+', Text = b[head + j], NewNo = head + j + 1 });
            }
            else
            {
                var len = new int[n + 1, m + 1];
                for (int i = n - 1; i >= 0; i--)
                    for (int j = m - 1; j >= 0; j--)
                        len[i, j] = a[head + i] == b[head + j] ? len[i + 1, j + 1] + 1 : Math.Max(len[i + 1, j], len[i, j + 1]);
                int x = 0, y = 0;
                while (x < n || y < m)
                {
                    if (x < n && y < m && a[head + x] == b[head + y]) { l.Add(new DiffLine { Kind = ' ', Text = a[head + x], OldNo = head + x + 1, NewNo = head + y + 1 }); x++; y++; }
                    else if (y < m && (x == n || len[x, y + 1] > len[x + 1, y])) { l.Add(new DiffLine { Kind = '+', Text = b[head + y], NewNo = head + y + 1 }); y++; }
                    else { l.Add(new DiffLine { Kind = '-', Text = a[head + x], OldNo = head + x + 1 }); x++; }
                }
            }
            for (int i = 0; i < tail; i++) l.Add(new DiffLine { Kind = ' ', Text = a[a.Count - tail + i], OldNo = a.Count - tail + i + 1, NewNo = b.Count - tail + i + 1 });
            return l;
        }

        public static List<string> SplitLines(string text)
        {
            var l = (text ?? "").Replace("\r\n", "\n").Split('\n').ToList();
            if (l.Count > 0 && l[l.Count - 1] == "") l.RemoveAt(l.Count - 1);
            return l;
        }

        /// <summary>Only the changed lines with context lines around them; runs of unchanged lines become one "..." line (Kind '@').</summary>
        public static List<DiffLine> WithContext(List<DiffLine> all, int context = 3)
        {
            var keep = new bool[all.Count];
            for (int i = 0; i < all.Count; i++)
                if (all[i].Kind != ' ')
                    for (int j = Math.Max(0, i - context); j <= Math.Min(all.Count - 1, i + context); j++) keep[j] = true;
            var l = new List<DiffLine>();
            for (int i = 0; i < all.Count; i++)
            {
                if (keep[i]) { l.Add(all[i]); continue; }
                if (l.Count == 0 || l[l.Count - 1].Kind != '@') l.Add(new DiffLine { Kind = '@', Text = "..." });
            }
            return l;
        }

        public static int Changed(List<DiffLine> d, char kind) { return d.Count(x => x.Kind == kind); }

        /// <summary>A plain-text rendering: "+ line", "- line", "  line", "..." (for logs, tests and the clipboard).</summary>
        public static string Format(List<DiffLine> d)
        {
            var sb = new StringBuilder();
            foreach (var x in d) sb.Append(x.Kind == '@' ? "..." : x.Kind + " " + x.Text).Append("\r\n");
            return sb.ToString();
        }
    }
}

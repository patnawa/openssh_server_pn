// OpenSSH Server Manager for Windows: SshdConfig

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Windows.Forms;
using Microsoft.Win32;

namespace OpenSSHServerManager
{
    // ------------------------------------------------------------------------------------------
    // sshd_config model
    // ------------------------------------------------------------------------------------------
    internal sealed class SshdConfig
    {
        public List<string> Lines = new List<string>();
        public string NewLine = "\n";
        public string Path;
        /// <summary>
        /// SHA-256 of the file at Path when this configuration was read from it ("" when the file did not exist), or null
        /// when it was not read from Path. SaveValidated refuses to write over a file that changed since then, so an edit
        /// made meanwhile in Notepad or by another program is not lost without a question.
        /// </summary>
        public string LoadedHash;

        /// <summary>Keywords whose lines add up in sshd (servconf.c appends each line to the list): all of them count.</summary>
        public static readonly string[] CumulativeKeywords = { "AllowUsers", "AllowGroups", "DenyUsers", "DenyGroups" };
        /// <summary>Keywords that may appear several times, each line adding a value (sshd listens on every Port and ListenAddress).</summary>
        public static readonly string[] RepeatableKeywords = { "Port", "ListenAddress", "HostKey", "HostCertificate", "Subsystem", "AcceptEnv", "Include" };

        public static SshdConfig Load(string path = null)
        {
            var c = new SshdConfig { Path = path ?? Ssh.ConfigPath };
            c.LoadedHash = FileHash(c.Path);
            if (!File.Exists(c.Path))
            {
                if (File.Exists(Ssh.DefaultConfigPath)) c.Path = Ssh.DefaultConfigPath; else return c;
            }
            var text = File.ReadAllText(c.Path, Encoding.UTF8);
            c.NewLine = text.Contains("\r\n") ? "\r\n" : "\n";
            c.Lines = text.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None).ToList();
            if (c.Lines.Count > 0 && c.Lines[c.Lines.Count - 1] == "") c.Lines.RemoveAt(c.Lines.Count - 1);
            c.Path = path ?? Ssh.ConfigPath;
            return c;
        }

        /// <summary>SHA-256 of a file as hexadecimal, or "" when it does not exist.</summary>
        public static string FileHash(string path)
        {
            if (string.IsNullOrEmpty(path) || !File.Exists(path)) return "";
            using (var sha = System.Security.Cryptography.SHA256.Create())
            using (var s = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                return BitConverter.ToString(sha.ComputeHash(s)).Replace("-", "");
        }

        public string Text { get { return string.Join(NewLine, Lines) + NewLine; } }

        /// <summary>A copy to edit: changes reach the original only when the caller adopts the copy (after it was saved).</summary>
        public SshdConfig Copy() { return new SshdConfig { Lines = Lines.ToList(), NewLine = NewLine, Path = Path, LoadedHash = LoadedHash }; }

        /// <summary>A Match line, or the start of the rules section of the Authentication tab (whose first line is a comment).</summary>
        private static bool StartsMatchSection(string line)
        {
            return Regex.IsMatch(line, @"^\s*Match\b", RegexOptions.IgnoreCase) || line.Trim() == AuthConfig.RegionBegin;
        }

        /// <summary>Index of the first line after the top-level settings (a Match block or the rules section), or Lines.Count.</summary>
        public int FirstMatchIndex()
        {
            for (int i = 0; i < Lines.Count; i++) if (StartsMatchSection(Lines[i])) return i;
            return Lines.Count;
        }

        internal static bool Split(string line, out string key, out string value) { string comment; return Split(line, out key, out value, out comment); }

        /// <summary>Keyword and value of a directive line; a trailing comment ("Port 22 # note") is returned apart, as sshd ignores it.</summary>
        internal static bool Split(string line, out string key, out string value, out string comment)
        {
            key = null; value = null; comment = null;
            var t = line.Trim();
            if (t.Length == 0 || t.StartsWith("#")) return false;
            var m = Regex.Match(t, @"^([A-Za-z0-9]+)\s*(?:=|\s)\s*(.*)$");
            if (!m.Success) return false;
            key = m.Groups[1].Value;
            var rest = m.Groups[2].Value;
            int cut = CommentStart(rest);
            if (cut >= 0) { comment = rest.Substring(cut).Trim(); rest = rest.Substring(0, cut); }
            value = rest.Trim();
            return true;
        }

        /// <summary>
        /// Index of the # that starts a comment in the arguments of a line, or -1. As in sshd (argv_split in misc.c), a #
        /// at the start of an argument outside quotes ends the line; elsewhere (C:\a#b, "x #y") it is an ordinary character.
        /// </summary>
        internal static int CommentStart(string s)
        {
            char quote = '\0'; bool argStart = true;
            for (int i = 0; i < s.Length; i++)
            {
                char c = s[i];
                if (c == '\\' && i + 1 < s.Length && (s[i + 1] == '\'' || s[i + 1] == '"' || s[i + 1] == '\\' || (quote == '\0' && s[i + 1] == ' '))) { i++; argStart = false; continue; }
                if (quote != '\0') { if (c == quote) quote = '\0'; continue; }
                if (c == ' ' || c == '\t') { argStart = true; continue; }
                if (c == '#' && argStart) return i;
                if (c == '"' || c == '\'') quote = c;
                argStart = false;
            }
            return -1;
        }

        /// <summary>First top-level (before any Match block) value of a keyword, or null.</summary>
        public string Get(string keyword)
        {
            int end = FirstMatchIndex();
            for (int i = 0; i < end; i++)
            {
                string k, v;
                if (Split(Lines[i], out k, out v) && k.Equals(keyword, StringComparison.OrdinalIgnoreCase)) return v;
            }
            return null;
        }

        /// <summary>All top-level values of a keyword (for keywords that may repeat, such as ListenAddress or Subsystem).</summary>
        public List<KeyValuePair<int, string>> GetAll(string keyword)
        {
            var l = new List<KeyValuePair<int, string>>();
            int end = FirstMatchIndex();
            for (int i = 0; i < end; i++)
            {
                string k, v;
                if (Split(Lines[i], out k, out v) && k.Equals(keyword, StringComparison.OrdinalIgnoreCase)) l.Add(new KeyValuePair<int, string>(i, v));
            }
            return l;
        }

        /// <summary>
        /// Sets a top-level keyword to one value: the first line gets the value and further lines of the keyword are
        /// commented out. Empty value comments the directive out (sshd default applies).
        /// </summary>
        public void Set(string keyword, string value) { Set(keyword, value, false); }

        /// <summary>
        /// Sets only the first top-level line of a keyword that may appear several times (Port, ListenAddress): the other
        /// lines stay as they are, so sshd keeps listening on the other ports and addresses. Empty value comments out the
        /// first line only.
        /// </summary>
        public void SetFirst(string keyword, string value) { Set(keyword, value, true); }

        private void Set(string keyword, string value, bool firstOnly)
        {
            value = (value ?? "").Trim();
            // A line break inside a value would add a second directive to the file.
            if (value.Any(c => c != '\t' && char.IsControl(c))) throw new ConfigException(keyword + ": the value must be a single line.");
            var occ = GetAll(keyword);
            if (value.Length == 0)
            {
                foreach (var o in firstOnly ? occ.Take(1) : occ) Lines[o.Key] = "#" + Lines[o.Key].TrimStart();
                return;
            }
            var newLine = keyword + " " + value;
            if (occ.Count > 0)
            {
                // A comment at the end of the line stays with it.
                string k, v, comment; Split(Lines[occ[0].Key], out k, out v, out comment);
                Lines[occ[0].Key] = newLine + (string.IsNullOrEmpty(comment) ? "" : " " + comment);
                if (!firstOnly) for (int i = 1; i < occ.Count; i++) Lines[occ[i].Key] = "#" + Lines[occ[i].Key].TrimStart();
                return;
            }
            // Prefer to replace a commented-out example of the same keyword ("#Port 22" in sshd_config_default: no space
            // after the #, so prose such as "# Port forwarding ..." is never taken for one), otherwise insert before the
            // first Include (sshd takes the first value it reads, so the value set here wins over an included file) or
            // the first Match block.
            int end = FirstMatchIndex();
            for (int i = 0; i < end; i++)
            {
                if (Regex.IsMatch(Lines[i], @"^\s*#" + Regex.Escape(keyword) + @"(\s|=)", RegexOptions.IgnoreCase)) { Lines[i] = newLine; return; }
            }
            int at = end;
            var include = GetAll("Include");
            if (include.Count > 0 && !keyword.Equals("Include", StringComparison.OrdinalIgnoreCase)) at = include[0].Key;
            Lines.Insert(at, newLine);
            if (at < Lines.Count - 1 && Lines[at + 1].Trim().Length > 0 && StartsMatchSection(Lines[at + 1])) Lines.Insert(at + 1, "");
        }

        /// <summary>
        /// The arguments of every top-level line of a keyword together, as sshd collects them for the Allow and Deny lists.
        /// Null (with a message) when a line cannot be read the way sshd reads it.
        /// </summary>
        public List<string> GetCombinedArgs(string keyword, out string error)
        {
            error = null;
            var all = new List<string>();
            foreach (var o in GetAll(keyword))
            {
                var args = SshdArgs.Split(o.Value, out error);
                if (args == null) return null;
                all.AddRange(args);
            }
            return all;
        }

        /// <summary>Include lines anywhere in the file (top level or inside Match blocks): sshd reads those files as well.</summary>
        public List<string> Includes()
        {
            var l = new List<string>();
            foreach (var line in Lines)
            {
                string k, v;
                if (Split(line, out k, out v) && k.Equals("Include", StringComparison.OrdinalIgnoreCase) && v.Length > 0) l.Add(v);
            }
            return l;
        }

        public string GetSubsystem(string name)
        {
            foreach (var s in GetAll("Subsystem"))
            {
                var parts = s.Value.Split(new[] { ' ', '\t' }, 2, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length == 2 && parts[0].Equals(name, StringComparison.OrdinalIgnoreCase)) return parts[1];
            }
            return null;
        }

        public void SetSubsystem(string name, string command)
        {
            if ((command ?? "").Any(c => c != '\t' && char.IsControl(c))) throw new ConfigException("Subsystem " + name + ": the command must be a single line.");
            int idx = -1;
            foreach (var s in GetAll("Subsystem"))
            {
                var parts = s.Value.Split(new[] { ' ', '\t' }, 2, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length >= 1 && parts[0].Equals(name, StringComparison.OrdinalIgnoreCase)) { idx = s.Key; break; }
            }
            if (string.IsNullOrWhiteSpace(command)) { if (idx >= 0) Lines.RemoveAt(idx); return; }
            var line = "Subsystem\t" + name + "\t" + command.Trim();
            if (idx >= 0) { Lines[idx] = line; return; }
            var sftp = GetAll("Subsystem").FirstOrDefault();
            int at = sftp.Value != null ? sftp.Key + 1 : FirstMatchIndex();
            Lines.Insert(at, line);
        }

        public int EffectivePort
        {
            get
            {
                int p; var v = Get("Port");
                if (v != null && int.TryParse(v, out p) && p > 0 && p < 65536) return p;
                foreach (var la in GetAll("ListenAddress"))
                {
                    p = ListenPort(la.Value);
                    if (p > 0) return p;
                }
                return 22;
            }
        }

        /// <summary>
        /// The port of a ListenAddress value, or 0 when it names none: "[addr]:port" and "host:port" carry one; a bare IPv6
        /// address ("::1", "fe80::1") does not, whatever its last group (sshd: two or more colons and no brackets).
        /// </summary>
        public static int ListenPort(string value)
        {
            string err; var args = SshdArgs.Split(value, out err);
            var addr = args != null && args.Count > 0 ? args[0] : (value ?? "").Trim();
            Match m = addr.StartsWith("[") ? Regex.Match(addr, @"^\[[^\]]*\]:(\d+)$") : addr.Count(ch => ch == ':') == 1 ? Regex.Match(addr, @":(\d+)$") : Match.Empty;
            int p;
            return m.Success && int.TryParse(m.Groups[1].Value, out p) && p > 0 && p < 65536 ? p : 0;
        }

        /// <summary>
        /// Validates with sshd -t on a temporary copy, backs up the live file and writes. Returns the backup path.
        /// Throws ConfigChangedException, and writes nothing, when the file changed since it was read (LoadedHash), unless
        /// overwrite is true. The new text is written to a temporary file next to sshd_config and swapped in (ReplaceFile keeps
        /// the file's permissions), so a crash or a full disk never leaves a half-written sshd_config.
        /// </summary>
        public string SaveValidated(bool overwrite = false)
        {
            var tmp = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "sshd_config.candidate." + Guid.NewGuid().ToString("N"));
            File.WriteAllText(tmp, Text, new UTF8Encoding(false));
            try
            {
                var t = Ssh.TestConfig(tmp);
                if (!t.Ok) throw new ConfigException("The configuration was NOT saved because sshd rejected it:\n\n" + t.Output.Replace(tmp, "sshd_config"));
            }
            finally { try { File.Delete(tmp); } catch { } }
            if (!overwrite && LoadedHash != null && FileHash(Path) != LoadedHash)
                throw new ConfigChangedException(Path + " was changed by another program after this window read it.");
            Directory.CreateDirectory(System.IO.Path.GetDirectoryName(Path));
            string backup = null;
            if (File.Exists(Path))
            {
                backup = NewBackupPath(Path, DateTime.Now);
                File.Copy(Path, backup, false);
            }
            WriteReplacing(Path, Text);
            LoadedHash = FileHash(Path);
            Log.Info("Saved " + Path + (backup != null ? " (backup " + backup + ")" : ""));
            PruneBackups(Path, KeepBackups);
            return backup;
        }

        /// <summary>How many sshd_config backups are kept; older ones are deleted after a save.</summary>
        public const int KeepBackups = 50;

        /// <summary>path.bak.yyyyMMdd-HHmmss, with -2, -3 ... added when a backup of that second exists already.</summary>
        public static string NewBackupPath(string path, DateTime now)
        {
            var b = path + ".bak." + now.ToString("yyyyMMdd-HHmmss", System.Globalization.CultureInfo.InvariantCulture);
            if (!File.Exists(b)) return b;
            for (int i = 2; ; i++) if (!File.Exists(b + "-" + i)) return b + "-" + i;
        }

        private static readonly Regex BackupName = new Regex(@"\.bak\.(\d{8}-\d{6})(?:-(\d+))?$");

        /// <summary>The backups of a configuration file made by SaveValidated, newest first.</summary>
        public static List<string> ListBackups(string path)
        {
            var dir = System.IO.Path.GetDirectoryName(path); var name = System.IO.Path.GetFileName(path);
            if (!Directory.Exists(dir)) return new List<string>();
            return Directory.GetFiles(dir, name + ".bak.*")
                .Select(f => new { f, m = BackupName.Match(System.IO.Path.GetFileName(f)) })
                .Where(x => x.m.Success && System.IO.Path.GetFileName(x.f).Length == name.Length + x.m.Length)
                .OrderByDescending(x => x.m.Groups[1].Value, StringComparer.Ordinal)
                .ThenByDescending(x => x.m.Groups[2].Success ? int.Parse(x.m.Groups[2].Value) : 1)
                .Select(x => x.f).ToList();
        }

        /// <summary>Deletes all but the newest keep backups of a configuration file.</summary>
        public static int PruneBackups(string path, int keep)
        {
            int n = 0;
            foreach (var old in ListBackups(path).Skip(keep))
            {
                try { File.Delete(old); n++; } catch (Exception ex) { Log.Error("Could not delete the old backup " + old, ex, false); }
            }
            return n;
        }

        /// <summary>
        /// Writes text (UTF-8, no BOM) to a temporary file in the same folder and swaps it in with ReplaceFile, which keeps
        /// the permissions of the file it replaces. A file that does not exist yet is moved into place.
        /// </summary>
        public static void WriteReplacing(string path, string text)
        {
            var tmp = path + ".new-" + Guid.NewGuid().ToString("N").Substring(0, 8);
            File.WriteAllText(tmp, text, new UTF8Encoding(false));
            try
            {
                if (File.Exists(path)) File.Replace(tmp, path, null);
                else File.Move(tmp, path);
            }
            catch (Exception ex)
            {
                // Some file systems (network shares, FAT) cannot replace; write in place as before.
                Log.Info("ReplaceFile failed for " + path + " (" + ex.Message + "); writing in place");
                File.WriteAllText(path, text, new UTF8Encoding(false));
            }
            finally { try { if (File.Exists(tmp)) File.Delete(tmp); } catch { } }
        }
    }

    internal class ConfigException : Exception { public ConfigException(string m) : base(m) { } }

    /// <summary>sshd_config changed on disk after it was read: saving would silently undo that change.</summary>
    internal sealed class ConfigChangedException : ConfigException { public ConfigChangedException(string m) : base(m) { } }

    /// <summary>
    /// Arguments of an sshd_config line, split and quoted the way sshd reads them (misc.c argv_split): spaces and tabs
    /// separate; " and ' both quote; \" \' \\ are escapes, and so is "\ " outside quotes; any other backslash is kept, so
    /// DOMAIN\name needs no escaping; # at the start of an argument ends the line. Windows allows ' in account names, so a
    /// name written as it is typed ("o'brien") can make sshd reject the whole file. Quoting makes "#name" an argument for
    /// AllowUsers and the like, but not for Match: match_cfg_line (servconf.c) reads any Match argument that starts with #
    /// as a comment, quoted or not, so the Authentication tab refuses # in names.
    /// </summary>
    internal static class SshdArgs
    {
        /// <summary>The arguments of a value, or null with a message when sshd would reject it.</summary>
        public static List<string> Split(string value, out string error)
        {
            error = null;
            var s = value ?? ""; var args = new List<string>(); int i = 0;
            while (i < s.Length)
            {
                if (s[i] == ' ' || s[i] == '\t') { i++; continue; }
                if (s[i] == '#') break;
                var sb = new StringBuilder(); char quote = '\0';
                for (; i < s.Length; i++)
                {
                    char c = s[i];
                    if (c == '\\' && i + 1 < s.Length && (s[i + 1] == '\'' || s[i + 1] == '"' || s[i + 1] == '\\' || (quote == '\0' && s[i + 1] == ' '))) sb.Append(s[++i]);
                    else if (quote == '\0' && (c == ' ' || c == '\t')) break;
                    else if (quote == '\0' && (c == '"' || c == '\'')) quote = c;
                    else if (quote != '\0' && c == quote) quote = '\0';
                    else sb.Append(c);
                }
                if (quote != '\0') { error = "a quotation mark (" + quote + ") is not closed"; return null; }
                args.Add(sb.ToString());
            }
            return args;
        }

        /// <summary>One argument as sshd_config text that Split reads back unchanged. Plain names stay as they are.</summary>
        public static string Quote(string arg)
        {
            arg = arg ?? "";
            bool quoted = arg.Length == 0 || arg[0] == '#' || arg.IndexOfAny(new[] { ' ', '\t', '\'', '"' }) >= 0;
            var sb = new StringBuilder();
            for (int i = 0; i < arg.Length; i++)
            {
                char c = arg[i];
                if (c == '"') { sb.Append("\\\""); continue; }
                // A backslash stays literal unless sshd would read it with the next character as an escape. After the
                // last character comes the closing quote, or the space before the next argument ("\ " is an escape too).
                char next = i + 1 < arg.Length ? arg[i + 1] : (quoted ? '"' : ' ');
                if (c == '\\' && (next == '\\' || next == '\'' || next == '"' || (!quoted && next == ' '))) { sb.Append("\\\\"); continue; }
                sb.Append(c);
            }
            return quoted ? "\"" + sb + "\"" : sb.ToString();
        }

        public static string Join(IEnumerable<string> args) { return string.Join(" ", args.Select(Quote)); }

        /// <summary>
        /// A list as a person types it in a text box: separated by spaces, "double quotes" group a name with spaces, and
        /// ' and \ are ordinary characters (o'brien, DOMAIN\name). Null, with a message, for an unclosed quotation mark.
        /// </summary>
        public static List<string> ParseTyped(string text, out string error)
        {
            error = null;
            var args = new List<string>(); var sb = new StringBuilder(); bool inQuote = false, any = false;
            foreach (char c in (text ?? "") + " ")
            {
                if (c == '"') { inQuote = !inQuote; any = true; continue; }
                if (!inQuote && (c == ' ' || c == '\t')) { if (any) args.Add(sb.ToString()); sb.Clear(); any = false; continue; }
                sb.Append(c); any = true;
            }
            if (inQuote) { error = "a quotation mark (\") is not closed"; return null; }
            return args;
        }

        /// <summary>The inverse of ParseTyped, or null when an argument cannot be typed that way (it contains ").</summary>
        public static string FormatTyped(IEnumerable<string> args)
        {
            var l = args.ToList();
            if (l.Any(a => a.Length == 0 || a.IndexOf('"') >= 0)) return null;
            return string.Join(" ", l.Select(a => a.IndexOfAny(new[] { ' ', '\t' }) >= 0 ? "\"" + a + "\"" : a));
        }
    }
}

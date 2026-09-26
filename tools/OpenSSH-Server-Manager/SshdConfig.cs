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

        public static SshdConfig Load(string path = null)
        {
            var c = new SshdConfig { Path = path ?? Ssh.ConfigPath };
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

        public string Text { get { return string.Join(NewLine, Lines) + NewLine; } }

        /// <summary>A copy to edit: changes reach the original only when the caller adopts the copy (after it was saved).</summary>
        public SshdConfig Copy() { return new SshdConfig { Lines = Lines.ToList(), NewLine = NewLine, Path = Path }; }

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

        internal static bool Split(string line, out string key, out string value)
        {
            key = null; value = null;
            var t = line.Trim();
            if (t.Length == 0 || t.StartsWith("#")) return false;
            var m = Regex.Match(t, @"^([A-Za-z0-9]+)\s*(?:=|\s)\s*(.*)$");
            if (!m.Success) return false;
            key = m.Groups[1].Value; value = m.Groups[2].Value.Trim();
            return true;
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

        /// <summary>Sets a top-level keyword. Empty value comments the directive out (sshd default applies).</summary>
        public void Set(string keyword, string value)
        {
            value = (value ?? "").Trim();
            // A line break inside a value would add a second directive to the file.
            if (value.Any(c => c != '\t' && char.IsControl(c))) throw new ConfigException(keyword + ": the value must be a single line.");
            var occ = GetAll(keyword);
            if (value.Length == 0)
            {
                foreach (var o in occ) Lines[o.Key] = "#" + Lines[o.Key].TrimStart();
                return;
            }
            var newLine = keyword + " " + value;
            if (occ.Count > 0)
            {
                Lines[occ[0].Key] = newLine;
                for (int i = 1; i < occ.Count; i++) Lines[occ[i].Key] = "#" + Lines[occ[i].Key].TrimStart();
                return;
            }
            // Prefer to replace a commented-out example of the same keyword, otherwise insert before the first Match block.
            int end = FirstMatchIndex();
            for (int i = 0; i < end; i++)
            {
                if (Regex.IsMatch(Lines[i], @"^\s*#\s*" + Regex.Escape(keyword) + @"\b", RegexOptions.IgnoreCase)) { Lines[i] = newLine; return; }
            }
            Lines.Insert(end, newLine);
            if (end < Lines.Count - 1 && Lines[end + 1].Trim().Length > 0 && StartsMatchSection(Lines[end + 1])) Lines.Insert(end + 1, "");
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
                    var m = Regex.Match(la.Value, @":(\d+)$");
                    if (m.Success && int.TryParse(m.Groups[1].Value, out p)) return p;
                }
                return 22;
            }
        }

        /// <summary>Validates with sshd -t on a temporary copy, backs up the live file and writes. Returns the backup path.</summary>
        public string SaveValidated()
        {
            var tmp = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "sshd_config.candidate." + Guid.NewGuid().ToString("N"));
            File.WriteAllText(tmp, Text, new UTF8Encoding(false));
            try
            {
                var t = Ssh.TestConfig(tmp);
                if (!t.Ok) throw new ConfigException("The configuration was NOT saved because sshd rejected it:\n\n" + t.Output.Replace(tmp, "sshd_config"));
            }
            finally { try { File.Delete(tmp); } catch { } }
            Directory.CreateDirectory(Ssh.ConfigDir);
            string backup = null;
            if (File.Exists(Path))
            {
                backup = Path + ".bak." + DateTime.Now.ToString("yyyyMMdd-HHmmss");
                File.Copy(Path, backup, true);
            }
            File.WriteAllText(Path, Text, new UTF8Encoding(false));
            Log.Info("Saved " + Path + (backup != null ? " (backup " + backup + ")" : ""));
            return backup;
        }
    }

    internal sealed class ConfigException : Exception { public ConfigException(string m) : base(m) { } }

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

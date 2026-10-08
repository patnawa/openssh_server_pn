using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace OpenSSHServerPNManager
{
    /// <summary>Include contents and glob membership form part of the configuration a user reviewed.</summary>
    internal sealed class ConfigurationDependencies
    {
        private readonly Dictionary<string, string> _files = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, string[]> _selectors = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);
        private string _error;

        public static ConfigurationDependencies Capture(IEnumerable<string> lines, string includeDirectory = null)
        {
            var result = new ConfigurationDependencies();
            // sshd resolves relative Includes against SSHDIR, not against -f's directory.
            var baseDirectory = includeDirectory ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "ssh");
            try { result.Scan(lines, baseDirectory, 0, new HashSet<string>(StringComparer.OrdinalIgnoreCase)); }
            catch (Exception ex) { result._error = ex.Message; }
            return result;
        }

        private void Scan(IEnumerable<string> lines, string baseDirectory, int depth, HashSet<string> active)
        {
            if (depth > 16) throw new ConfigException("Include nesting exceeds the server's limit.");
            foreach (var line in lines)
            {
                string keyword, value, error;
                if (!SshdConfig.Split(line, out keyword, out value) || !keyword.Equals("Include", StringComparison.OrdinalIgnoreCase)) continue;
                var arguments = SshdArgs.Split(value, out error);
                if (arguments == null || arguments.Count == 0) throw new ConfigException("Cannot snapshot Include: " + (error ?? "no file pattern"));
                foreach (var argument in arguments)
                {
                    if (argument.StartsWith("~", StringComparison.Ordinal)) throw new ConfigException("Tilde Include paths depend on the service account. Use an absolute path before editing this configuration in the manager.");
                    var selector = argument.Replace("__PROGRAMDATA__", Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)).Replace('/', '\\');
                    if (!Path.IsPathRooted(selector)) selector = Path.Combine(baseDirectory, selector);
                    if (!Regex.IsMatch(selector, @"^[A-Za-z]:\\") && !selector.StartsWith(@"\\", StringComparison.Ordinal)) throw new ConfigException("Include path is not fully qualified: " + selector);
                    var files = Expand(selector);
                    _selectors[selector] = files;
                    foreach (var file in files)
                    {
                        if (!active.Add(file)) throw new ConfigException("Include cycle: " + file);
                        var bytes = File.ReadAllBytes(file);
                        _files[file] = Hash(bytes);
                        using (var reader = new StreamReader(new MemoryStream(bytes), Encoding.UTF8, true))
                        {
                            var nested = new List<string>(); string nestedLine;
                            while ((nestedLine = reader.ReadLine()) != null) nested.Add(nestedLine);
                            Scan(nested, baseDirectory, depth + 1, active);
                        }
                        active.Remove(file);
                    }
                }
            }
        }

        internal static string Hash(byte[] bytes)
        { using (var hash = System.Security.Cryptography.SHA256.Create()) return BitConverter.ToString(hash.ComputeHash(bytes)).Replace("-", ""); }

        internal static ConfigurationDependencies Combine(ConfigurationDependencies first, ConfigurationDependencies second)
        {
            var result = new ConfigurationDependencies();
            foreach (var item in new[] { first, second }.Where(x => x != null))
            {
                item.RequireUnchanged();
                foreach (var file in item._files) result._files[file.Key] = file.Value;
                foreach (var selector in item._selectors) result._selectors[selector.Key] = selector.Value.ToArray();
            }
            return result;
        }

        private static string GlobExpression(string segment)
        {
            var result = new StringBuilder("^");
            for (int i = 0; i < segment.Length; i++)
            {
                if (segment[i] == '*') result.Append(".*");
                else if (segment[i] == '?') result.Append('.');
                else if (segment[i] == '[')
                {
                    int end = segment.IndexOf(']', i + 1);
                    if (end < 0) { result.Append(@"\["); continue; }
                    var content = segment.Substring(i + 1, end - i - 1);
                    if (content.Length == 0 || content.Contains("[") || content.Contains("\\")) throw new ConfigException("Unsupported Include bracket pattern: " + segment);
                    result.Append('[');
                    if (content[0] == '!') { result.Append('^'); content = content.Substring(1); }
                    else if (content[0] == '^') result.Append('\\');
                    result.Append(content).Append(']'); i = end;
                }
                else result.Append(Regex.Escape(segment[i].ToString()));
            }
            return result.Append('$').ToString();
        }

        private static string[] Expand(string selector)
        {
            var root = Path.GetPathRoot(selector);
            var parts = selector.Substring(root.Length).Split(new[] { '\\' }, StringSplitOptions.RemoveEmptyEntries);
            var paths = new List<string> { root };
            for (int i = 0; i < parts.Length; i++)
            {
                var next = new List<string>();
                var regex = new Regex(GlobExpression(parts[i]), RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
                foreach (var path in paths)
                {
                    if (!Directory.Exists(path)) continue;
                    if (parts[i].IndexOfAny(new[] { '*', '?', '[' }) < 0)
                    {
                        var literal = Path.GetFullPath(Path.Combine(path, parts[i]));
                        if (i == parts.Length - 1 ? File.Exists(literal) || Directory.Exists(literal) : Directory.Exists(literal)) next.Add(literal);
                        continue;
                    }
                    foreach (var child in Directory.EnumerateFileSystemEntries(path))
                        if (regex.IsMatch(Path.GetFileName(child)) && (i == parts.Length - 1 || Directory.Exists(child))) next.Add(Path.GetFullPath(child));
                }
                paths = next;
            }
            if (paths.Any(Directory.Exists)) throw new ConfigException("Include resolves to a directory: " + selector);
            return paths.Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(p => p, StringComparer.OrdinalIgnoreCase).ToArray();
        }

        public void RequireUnchanged()
        {
            if (_error != null) throw new ConfigException("The included configuration could not be captured safely: " + _error);
            foreach (var selector in _selectors)
                if (!Expand(selector.Key).SequenceEqual(selector.Value, StringComparer.OrdinalIgnoreCase)) throw new ConfigChangedException("The files matched by Include changed: " + selector.Key + ". Reload before saving or restarting.");
            foreach (var file in _files)
                if (SshdConfig.FileHash(file.Key) != file.Value) throw new ConfigChangedException("An included configuration changed: " + file.Key + ". No external edits were overwritten; reload before continuing.");
        }

        internal void Store(IDictionary<string, string> values)
        {
            if (_error != null) throw new ConfigException(_error);
            int i = 0;
            foreach (var file in _files) { values["dependency.file." + i] = file.Key; values["dependency.hash." + i++] = file.Value; }
            values["dependency.files"] = i.ToString(System.Globalization.CultureInfo.InvariantCulture);
            i = 0;
            foreach (var selector in _selectors) { values["dependency.selector." + i] = selector.Key; values["dependency.matches." + i++] = string.Join("\n", selector.Value); }
            values["dependency.selectors"] = i.ToString(System.Globalization.CultureInfo.InvariantCulture);
        }

        internal static ConfigurationDependencies Read(IDictionary<string, string> values)
        {
            var result = new ConfigurationDependencies();
            if (!values.ContainsKey("dependency.files")) return result;
            int files = int.Parse(values["dependency.files"], System.Globalization.CultureInfo.InvariantCulture), selectors = int.Parse(values["dependency.selectors"], System.Globalization.CultureInfo.InvariantCulture);
            if (files < 0 || files > 10000 || selectors < 0 || selectors > 10000) throw new ConfigException("The recovery dependency list is invalid.");
            for (int i = 0; i < files; i++) result._files.Add(values["dependency.file." + i], values["dependency.hash." + i]);
            for (int i = 0; i < selectors; i++) result._selectors.Add(values["dependency.selector." + i], values["dependency.matches." + i].Split(new[] { '\n' }, StringSplitOptions.RemoveEmptyEntries));
            return result;
        }
    }
}

// OpenSSH Server PN Manager: Client (known_hosts, ssh client configuration, ssh-agent)

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace OpenSSHServerPNManager
{
    // ------------------------------------------------------------------------------------------
    // The ssh client of the account running this program: known_hosts, %USERPROFILE%\.ssh\config, ssh-agent
    // ------------------------------------------------------------------------------------------
    internal sealed class KnownHost { public int Line; public string Marker = ""; public string Hosts; public string Type; public string Fingerprint; public bool Hashed; public string Raw; public ClientFileSnapshot Snapshot; }

    internal sealed class ClientHost
    {
        /// <summary>The patterns of the Host line ("web", "*.example.com"), or "Match ..." for a Match block.</summary>
        public string Pattern;
        public bool IsMatch;
        /// <summary>First and last line of the block in the file (0-based, inclusive); the block ends before the next Host or Match.</summary>
        public int First, Last;
        public Dictionary<string, string> Values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, List<string>> AllValues = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        public string Get(string k) { string v; return Values.TryGetValue(k, out v) ? v : ""; }
        public List<string> GetAll(string k) { List<string> v; return AllValues.TryGetValue(k, out v) ? new List<string>(v) : new List<string>(); }
    }

    internal static class SshClient
    {
        public static string KnownHostsPath { get { return Path.Combine(KeyGen.SshDir, "known_hosts"); } }
        public static string ConfigPath { get { return Path.Combine(KeyGen.SshDir, "config"); } }

        /// <summary>The entries of a known_hosts file; comments and blank lines are skipped, fingerprints through ssh-keygen (cached).</summary>
        public static List<KnownHost> ReadKnownHosts(string path, bool fingerprints = true)
        {
            return ReadKnownHosts(ClientFileSnapshot.Read(path), fingerprints);
        }

        public static List<KnownHost> ReadKnownHosts(ClientFileSnapshot snapshot, bool fingerprints = true)
        {
            var l = new List<KnownHost>();
            var lines = snapshot.Lines;
            for (int i = 0; i < lines.Count; i++)
            {
                var k = ParseKnownHost(lines[i]);
                if (k == null) continue;
                k.Line = i; k.Snapshot = snapshot;
                if (fingerprints) k.Fingerprint = Keys.Fingerprint(k.Type + " " + KeyMaterial(lines[i]));
                l.Add(k);
            }
            return l;
        }

        /// <summary>One known_hosts line: [@marker] hosts keytype base64 [comment]; null for comments, blank and broken lines.</summary>
        public static KnownHost ParseKnownHost(string line)
        {
            var t = (line ?? "").Trim();
            if (t.Length == 0 || t.StartsWith("#")) return null;
            var parts = t.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
            int at = 0; var k = new KnownHost { Raw = line };
            if (parts[0].StartsWith("@")) { k.Marker = parts[0]; at = 1; }
            if (parts.Length < at + 3) return null;
            k.Hosts = parts[at]; k.Type = parts[at + 1];
            k.Hashed = k.Hosts.StartsWith("|1|");
            return k;
        }

        private static string KeyMaterial(string line)
        {
            var parts = line.Trim().Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
            int at = parts.Length > 0 && parts[0].StartsWith("@") ? 1 : 0;
            return parts.Length > at + 2 ? parts[at + 2] : "";
        }

        /// <summary>Remove exactly the displayed trust entries, only from the unchanged displayed file.</summary>
        public static int RemoveKnownHosts(string path, ICollection<KnownHost> entries)
        {
            if (entries.Count == 0) return 0;
            var snapshot = entries.First().Snapshot;
            if (snapshot == null || !string.Equals(Path.GetFullPath(path), snapshot.Path, StringComparison.OrdinalIgnoreCase)) throw new ConfigException("Refresh known hosts before removing a key.");
            snapshot.RequireUnchanged();
            foreach (var entry in entries)
                if (entry.Snapshot != snapshot || entry.Line < 0 || entry.Line >= snapshot.Lines.Count || snapshot.Lines[entry.Line] != entry.Raw)
                    throw new ConfigException("The trust selection is stale. Refresh known hosts before removing a key.");
            var lineNumbers = new HashSet<int>(entries.Select(e => e.Line));
            var lines = snapshot.Lines;
            var kept = lines.Where((l, i) => !lineNumbers.Contains(i)).ToList();
            int removed = lines.Count - kept.Count;
            if (removed == 0) return 0;
            snapshot.Write(kept, ".old", false);
            return removed;
        }

        /// <summary>Appends the offered lines whose key is not yet trusted for their host; returns how many were added.</summary>
        public static int AddKnownHosts(ClientFileSnapshot snapshot, IEnumerable<string> lines)
        {
            var known = ReadKnownHosts(snapshot, false);
            var result = snapshot.Lines.ToList(); int added = 0;
            // A key stored under a hashed name (HashKnownHosts) is the same trust: a clear-text copy would undo the hashing.
            foreach (var line in lines) if (!result.Contains(line) && !DirectlyTrusted(known, line)) { result.Add(line); added++; }
            // With nothing to write, "already trusted" still holds only if the file is the one the trust dialog showed.
            if (added > 0) snapshot.Write(result, ".old", false); else snapshot.RequireUnchanged();
            return added;
        }

        private static bool DirectlyTrusted(List<KnownHost> known, string line)
        {
            var key = ParseKnownHost(line);
            return key != null && known.Any(k => k.Marker.Length == 0 && k.Type == key.Type && KeyMaterial(k.Raw) == KeyMaterial(line) && key.Hosts.Split(',').All(host => KnownHostMatches(k.Hosts, host)));
        }

        /// <summary>Explicitly describe trust changes, including existing keys for this host/type.</summary>
        public static string TrustChanges(ClientFileSnapshot snapshot, IEnumerable<string> offered)
        {
            var known = ReadKnownHosts(snapshot, false);
            var messages = new List<string>();
            foreach (var line in offered)
            {
                var key = ParseKnownHost(line); if (key == null) continue;
                var matches = known.Where(k => key.Hosts.Split(',').Any(host => KnownHostMatches(k.Hosts, host)) && k.Type == key.Type).ToList();
                if (matches.Any(k => k.Marker == "@revoked")) messages.Add(key.Type + ": a matching entry is marked REVOKED. Adding a key does not remove this revocation.");
                if (matches.Any(k => k.Marker == "@cert-authority")) messages.Add(key.Type + ": certificate-authority trust is configured for this host. A direct host-key entry is separate from that authority.");
                var direct = matches.Where(k => k.Marker.Length == 0).ToList();
                if (direct.Any(k => KeyMaterial(k.Raw) == KeyMaterial(line))) messages.Add(key.Type + ": already present as a direct host key");
                else if (direct.Count > 0) messages.Add(key.Type + ": DIFFERENT from the stored key. Verify a planned rotation with the server administrator before adding it. Existing keys will be retained.");
                else messages.Add(key.Type + ": new trust entry");
            }
            return string.Join("\n", messages);
        }

        internal static bool KnownHostMatches(string patterns, string host)
        {
            bool matched = false;
            foreach (var pattern in patterns.Split(','))
            {
                if (pattern.StartsWith("|1|", StringComparison.Ordinal))
                {
                    var parts = pattern.Split('|');
                    if (parts.Length != 4) continue;
                    try
                    {
                        using (var hash = new HMACSHA1(Convert.FromBase64String(parts[2])))
                            if (hash.ComputeHash(Encoding.UTF8.GetBytes(host)).SequenceEqual(Convert.FromBase64String(parts[3]))) matched = true;
                    }
                    catch (FormatException) { }
                    continue;
                }
                bool negative = pattern.StartsWith("!", StringComparison.Ordinal);
                var glob = negative ? pattern.Substring(1) : pattern;
                if (!Regex.IsMatch(host, "^" + Regex.Escape(glob).Replace("\\*", ".*").Replace("\\?", ".") + "$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)) continue;
                if (negative) return false;
                matched = true;
            }
            return matched;
        }

        /// <summary>The Host and Match blocks of an ssh client configuration, in order; settings before the first block are left out.</summary>
        public static List<ClientHost> ParseConfig(IList<string> lines)
        {
            var l = new List<ClientHost>(); ClientHost cur = null;
            for (int i = 0; i < lines.Count; i++)
            {
                string k, v, comment;
                if (!SshdConfig.Split(lines[i], out k, out v, out comment)) { if (cur != null && lines[i].Trim().Length > 0) cur.Last = i; continue; }
                if (k.Equals("Host", StringComparison.OrdinalIgnoreCase) || k.Equals("Match", StringComparison.OrdinalIgnoreCase))
                {
                    cur = new ClientHost { Pattern = k.Equals("Match", StringComparison.OrdinalIgnoreCase) ? "Match " + v : v, IsMatch = k.Equals("Match", StringComparison.OrdinalIgnoreCase), First = i, Last = i };
                    l.Add(cur); continue;
                }
                if (cur == null) continue;
                cur.Last = i;
                if (!cur.Values.ContainsKey(k)) cur.Values[k] = v; // first value wins in ssh too
                if (!cur.AllValues.ContainsKey(k)) cur.AllValues[k] = new List<string>();
                cur.AllValues[k].Add(v);
            }
            return l;
        }

        /// <summary>The keywords the host editor shows; other lines of a block stay as they are.</summary>
        public static readonly string[] EditedKeywords = { "HostName", "User", "Port", "IdentityFile", "ProxyJump" };

        /// <summary>
        /// A configuration with one Host block added or changed: the Host line and the edited keywords are written, every
        /// other line of the block is kept. New profiles precede defaults. Empty supplied values remove that keyword;
        /// absent or unchanged fields preserve the original directives, including repeated IdentityFile entries.
        /// </summary>
        public static List<string> WithHost(IList<string> lines, ClientHost existing, string pattern, IDictionary<string, string> values)
        {
            pattern = (pattern ?? "").Trim();
            if (pattern.Length == 0) throw new ConfigException("Enter a name for the host (the name you type after ssh).");
            if (pattern.Any(char.IsControl)) throw new ConfigException("Host names must be a single line.");
            foreach (var pair in values)
                if ((pair.Value ?? "").Any(c => char.IsControl(c) && !(pair.Key.Equals("IdentityFile", StringComparison.OrdinalIgnoreCase) && (c == '\r' || c == '\n')))) throw new ConfigException("Values must be single lines (one identity path per line).");
            var problem = PercentProblem(existing, values);
            if (problem != null) throw new ConfigException(problem);
            var changed = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var block = new List<string> { existing != null && existing.Pattern == pattern ? lines[existing.First] : "Host " + pattern };
            // The identity lines as written: the editor shows their config text, which a rewrite must not quote a second time.
            var identityLines = new List<string>();
            if (existing != null)
                for (int i = existing.First + 1; i <= existing.Last && i < lines.Count; i++)
                {
                    string k, v; if (SshdConfig.Split(lines[i], out k, out v) && k.Equals("IdentityFile", StringComparison.OrdinalIgnoreCase)) identityLines.Add(lines[i]);
                }
            foreach (var k in EditedKeywords)
            {
                string v; if (!values.TryGetValue(k, out v)) continue;
                v = (v ?? "").Trim();
                if (existing != null && (k == "IdentityFile" ? IdentityValues(v).SequenceEqual(existing.GetAll(k)) : v == existing.Get(k))) continue;
                changed.Add(k);
                if (v.Length == 0) continue;
                if (k == "HostName") v = EscapeHostNamePercent(v);
                foreach (var item in k == "IdentityFile" ? IdentityValues(v) : new List<string> { v })
                {
                    string kept = null;
                    if (k == "IdentityFile")
                        foreach (var line in identityLines)
                        {
                            string ik, iv; SshdConfig.Split(line, out ik, out iv);
                            if (iv == item) { kept = line; identityLines.Remove(line); break; }
                        }
                    block.Add(kept ?? "    " + k + " " + Quote(item));
                }
            }
            var result = lines.ToList();
            if (existing == null)
            {
                int at = 0; string firstKey = null, firstValue;
                while (at < result.Count && !SshdConfig.Split(result[at], out firstKey, out firstValue)) at++;
                block.Add("");
                // A global option/Include must continue to apply to every host after the newly inserted profile.
                if (at < result.Count && !firstKey.Equals("Host", StringComparison.OrdinalIgnoreCase) && !firstKey.Equals("Match", StringComparison.OrdinalIgnoreCase)) block.Add("Host *");
                result.InsertRange(at, block);
                return result;
            }
            // Keep the other lines of the block (comments, options the editor does not show).
            for (int i = existing.First + 1; i <= existing.Last && i < lines.Count; i++)
            {
                string k, v;
                if (SshdConfig.Split(lines[i], out k, out v) && changed.Contains(k)) continue;
                block.Add(lines[i]);
            }
            result.RemoveRange(existing.First, existing.Last - existing.First + 1);
            result.InsertRange(existing.First, block);
            return result;
        }

        private static List<string> IdentityValues(string value) { return value.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).Select(v => v.Trim()).Where(v => v.Length > 0).ToList(); }

        /// <summary>
        /// A HostName with each % other than %h and %% doubled. ssh expands only those two there and stops on any other
        /// (fe80::1%12, an IPv6 address with its zone, is written fe80::1%%12).
        /// </summary>
        internal static string EscapeHostNamePercent(string value)
        {
            var sb = new StringBuilder();
            for (int i = 0; i < value.Length; i++)
            {
                if (value[i] == '%' && i + 1 < value.Length && (value[i + 1] == 'h' || value[i + 1] == '%')) { sb.Append(value, i, 2); i++; continue; }
                sb.Append(value[i]);
                if (value[i] == '%') sb.Append('%');
            }
            return sb.ToString();
        }

        /// <summary>
        /// Why ssh would stop on a % in an edited User or IdentityFile value (ssh.c: unknown tokens are fatal); null when every %
        /// is one ssh expands. Values that were already in the block are not checked again.
        /// </summary>
        public static string PercentProblem(ClientHost existing, IDictionary<string, string> values)
        {
            foreach (var k in new[] { "User", "IdentityFile" })
            {
                string v; if (!values.TryGetValue(k, out v)) continue;
                var old = existing == null ? new List<string>() : existing.GetAll(k);
                var tokens = k == "User" ? "Liklnpdhuj" : "CLiklnpdhujr";
                foreach (var item in IdentityValues(v ?? ""))
                {
                    if (old.Contains(item)) continue;
                    for (int i = 0; i < item.Length; i++)
                    {
                        if (item[i] != '%') continue;
                        if (i + 1 < item.Length && (item[i + 1] == '%' || tokens.IndexOf(item[i + 1]) >= 0)) { i++; continue; }
                        var variable = Regex.Match(item.Substring(i), @"^%([A-Za-z_][A-Za-z0-9_]*)%");
                        return k + " \"" + item + "\": ssh expands % in this setting and cannot expand " + (i + 1 < item.Length ? "%" + item[i + 1] : "a final %") + ". Write %% for a literal %" +
                            (variable.Success ? "; for the Windows variable %" + variable.Groups[1].Value + "% write ${" + variable.Groups[1].Value + "}" + (variable.Groups[1].Value.Equals("USERPROFILE", StringComparison.OrdinalIgnoreCase) ? " or ~" : "") : "") + ".";
                    }
                }
            }
            return null;
        }

        /// <summary>A block without its Host line and settings; comments after its last setting stay, as they usually head the next block.</summary>
        public static List<string> WithoutHost(IList<string> lines, ClientHost existing)
        {
            int end = existing.First;
            for (int i = existing.First + 1; i <= existing.Last && i < lines.Count; i++) { string k, v; if (SshdConfig.Split(lines[i], out k, out v)) end = i; }
            var result = lines.ToList();
            result.RemoveRange(existing.First, end - existing.First + 1);
            if (existing.First < result.Count && result[existing.First].Trim().Length == 0 && (existing.First == 0 || result[existing.First - 1].Trim().Length == 0)) result.RemoveAt(existing.First);
            return result;
        }

        /// <summary>A value quoted when it has spaces (paths such as C:\Users\Jane Doe\.ssh\id_ed25519).</summary>
        private static string Quote(string v)
        {
            if (v.StartsWith("\"", StringComparison.Ordinal) || v.StartsWith("'", StringComparison.Ordinal))
            {
                string error; var args = SshdArgs.Split(v, out error);
                if (args == null || args.Count != 1) throw new ConfigException("Enter one value per field (one identity path per line): " + (error ?? v));
                v = args[0];
            }
            return SshdArgs.Quote(v);
        }

        /// <summary>Writes the ssh client configuration, keeping the previous one as config.bak; the file is readable by its owner only.</summary>
        public static void WriteConfig(ClientFileSnapshot snapshot, IList<string> lines)
        {
            snapshot.Write(lines, ".bak", true);
        }

        public static bool Connectable(ClientHost host) { return ConnectProblem(host) == null; }

        /// <summary>Why Connect, SFTP and Effective settings cannot open a Host block by its name; null when they can.</summary>
        public static string ConnectProblem(ClientHost host)
        {
            // sftp reads "fe80::1" as host fe80 and remote path ":1", "a@b" as user a at b, and drops [ ]: another host.
            if (host != null && !host.IsMatch && host.Pattern.IndexOfAny(new[] { ':', '@', '[', ']' }) >= 0)
                return "\"" + host.Pattern + "\" cannot be opened by its name: sftp reads ':' as the start of a remote path, '@' as a user name and drops [ ], so it would connect to another host. Give the host a plain name (for example web1) and put the address in Host name.";
            if (host == null || host.IsMatch || !Regex.IsMatch(host.Pattern, @"^[A-Za-z0-9._%+][A-Za-z0-9._%+\-]*$")) return "Choose a host with a single plain name (no wildcards, spaces or leading -).";
            return null;
        }

        public static string EffectivePreview(string host)
        {
            if (Elevation.IsAdministrator()) throw new ConfigException("Open the standard-user Client workspace to preview this connection. SSH configuration can execute local commands, so it is never evaluated with administrator rights.");
            if (!Connectable(new ClientHost { Pattern = host })) throw new ConfigException("Choose a host with one plain name to preview.");
            var result = Proc.Run(Ssh.Exe("ssh.exe"), "-G -- " + host, 20000);
            if (!result.Ok) throw new ConfigException("Could not resolve this connection:\n" + result.Output);
            return FormatEffectivePreview(result.StdOut);
        }

        internal static string FormatEffectivePreview(string output)
        {
            var wanted = new HashSet<string>(new[] { "hostname", "user", "port", "identityfile", "proxyjump", "proxycommand", "userknownhostsfile", "stricthostkeychecking", "identityagent" }, StringComparer.OrdinalIgnoreCase);
            var result = new List<string>();
            foreach (var line in output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
            {
                int at = line.IndexOf(' ');
                if (at > 0 && wanted.Contains(line.Substring(0, at))) result.Add(line);
            }
            return "Effective connection settings (ssh -G; no network connection was made):\n\n" + string.Join("\n", result) + "\n\nIdentity paths may include defaults that do not exist on disk.";
        }

        /// <summary>The keys the agent holds: public key lines (ssh-add -L); empty with a message when it has none or does not run.</summary>
        public static List<string> AgentKeys(out string message)
        {
            var r = Proc.Run(Ssh.Exe("ssh-add.exe"), "-L", 15000);
            message = null;
            if (r.ExitCode == 1 && r.Output.IndexOf("no identities", StringComparison.OrdinalIgnoreCase) >= 0) { message = "The agent holds no keys."; return new List<string>(); }
            if (!r.Ok) { message = "The agent does not answer: " + r.Output; return new List<string>(); }
            return r.StdOut.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).Where(Keys.LooksLikePublicKey).ToList();
        }

        /// <summary>Adds a private key to the agent; the passphrase, when needed, goes through SSH_ASKPASS, never on a command line.</summary>
        public static RunResult AgentAdd(string privatePath, string passphrase)
        {
            return Proc.Run(Ssh.Exe("ssh-add.exe"), Proc.Quote(privatePath), 30000, null, KeyGen.AskpassEnvironment(string.IsNullOrEmpty(passphrase) ? null : passphrase));
        }

        /// <summary>Removes one key from the agent, given its public key line.</summary>
        public static RunResult AgentRemove(string publicLine)
        {
            var tmp = Path.Combine(Path.GetTempPath(), "osm-agent-" + Guid.NewGuid().ToString("N") + ".pub");
            try { File.WriteAllText(tmp, publicLine + "\n"); return Proc.Run(Ssh.Exe("ssh-add.exe"), "-d " + Proc.Quote(tmp), 15000); }
            finally { try { File.Delete(tmp); } catch { } }
        }

        /// <summary>The host keys a server offers (ssh-keyscan), as known_hosts lines, for adding after the fingerprints were compared.</summary>
        public static RunResult Scan(string host, int port)
        {
            return Proc.Run(Ssh.Exe("ssh-keyscan.exe"), (port != 22 ? "-p " + port + " " : "") + "-T 10 " + Proc.Quote(host), 30000);
        }

        /// <summary>A host name or address as ssh-keyscan and known_hosts need it; null when it contains anything else.</summary>
        public static string CheckHostName(string host)
        {
            host = (host ?? "").Trim();
            return Regex.IsMatch(host, @"^[A-Za-z0-9._:\-\[\]%]+$") && !host.StartsWith("-") ? host : null;
        }
    }
}

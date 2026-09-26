// OpenSSH Server Manager for Windows: Client (known_hosts, ssh client configuration, ssh-agent)

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace OpenSSHServerManager
{
    // ------------------------------------------------------------------------------------------
    // The ssh client of the account running this program: known_hosts, %USERPROFILE%\.ssh\config, ssh-agent
    // ------------------------------------------------------------------------------------------
    internal sealed class KnownHost { public int Line; public string Marker = ""; public string Hosts; public string Type; public string Fingerprint; public bool Hashed; public string Raw; }

    internal sealed class ClientHost
    {
        /// <summary>The patterns of the Host line ("web", "*.example.com"), or "Match ..." for a Match block.</summary>
        public string Pattern;
        public bool IsMatch;
        /// <summary>First and last line of the block in the file (0-based, inclusive); the block ends before the next Host or Match.</summary>
        public int First, Last;
        public Dictionary<string, string> Values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        public string Get(string k) { string v; return Values.TryGetValue(k, out v) ? v : ""; }
    }

    internal static class SshClient
    {
        public static string KnownHostsPath { get { return Path.Combine(KeyGen.SshDir, "known_hosts"); } }
        public static string ConfigPath { get { return Path.Combine(KeyGen.SshDir, "config"); } }

        /// <summary>The entries of a known_hosts file; comments and blank lines are skipped, fingerprints through ssh-keygen (cached).</summary>
        public static List<KnownHost> ReadKnownHosts(string path, bool fingerprints = true)
        {
            var l = new List<KnownHost>();
            if (!File.Exists(path)) return l;
            var lines = File.ReadAllLines(path);
            for (int i = 0; i < lines.Length; i++)
            {
                var k = ParseKnownHost(lines[i]);
                if (k == null) continue;
                k.Line = i;
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

        /// <summary>Removes lines (0-based numbers) from a known_hosts file; the previous file is kept as known_hosts.old, as ssh-keygen -R does.</summary>
        public static int RemoveLines(string path, ICollection<int> lineNumbers)
        {
            var lines = File.ReadAllLines(path).ToList();
            var kept = lines.Where((l, i) => !lineNumbers.Contains(i)).ToList();
            int removed = lines.Count - kept.Count;
            if (removed == 0) return 0;
            File.Copy(path, path + ".old", true);
            File.WriteAllText(path, string.Join("\n", kept) + (kept.Count > 0 ? "\n" : ""), new UTF8Encoding(false));
            return removed;
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
            }
            return l;
        }

        /// <summary>The keywords the host editor shows; other lines of a block stay as they are.</summary>
        public static readonly string[] EditedKeywords = { "HostName", "User", "Port", "IdentityFile", "ProxyJump" };

        /// <summary>
        /// A configuration with one Host block added or changed: the Host line and the edited keywords are written, every
        /// other line of the block is kept. existing null adds the block at the end. Empty values remove the keyword.
        /// </summary>
        public static List<string> WithHost(IList<string> lines, ClientHost existing, string pattern, IDictionary<string, string> values)
        {
            pattern = (pattern ?? "").Trim();
            if (pattern.Length == 0) throw new ConfigException("Enter a name for the host (the name you type after ssh).");
            foreach (var v in values.Values.Concat(new[] { pattern }))
                if ((v ?? "").Any(c => char.IsControl(c))) throw new ConfigException("Values must be single lines.");
            var block = new List<string> { "Host " + pattern };
            foreach (var k in EditedKeywords)
            {
                string v; if (values.TryGetValue(k, out v) && !string.IsNullOrWhiteSpace(v)) block.Add("    " + k + " " + Quote(v.Trim()));
            }
            var result = lines.ToList();
            if (existing == null)
            {
                while (result.Count > 0 && result[result.Count - 1].Trim().Length == 0) result.RemoveAt(result.Count - 1);
                if (result.Count > 0) result.Add("");
                result.AddRange(block);
                return result;
            }
            // Keep the other lines of the block (comments, options the editor does not show).
            for (int i = existing.First + 1; i <= existing.Last && i < lines.Count; i++)
            {
                string k, v;
                if (SshdConfig.Split(lines[i], out k, out v) && EditedKeywords.Contains(k, StringComparer.OrdinalIgnoreCase)) continue;
                block.Add(lines[i]);
            }
            result.RemoveRange(existing.First, existing.Last - existing.First + 1);
            result.InsertRange(existing.First, block);
            return result;
        }

        public static List<string> WithoutHost(IList<string> lines, ClientHost existing)
        {
            var result = lines.ToList();
            result.RemoveRange(existing.First, existing.Last - existing.First + 1);
            if (existing.First < result.Count && existing.First > 0 && result[existing.First].Trim().Length == 0 && result[existing.First - 1].Trim().Length == 0) result.RemoveAt(existing.First);
            return result;
        }

        /// <summary>A value quoted when it has spaces (paths such as C:\Users\Jane Doe\.ssh\id_ed25519).</summary>
        private static string Quote(string v) { return v.IndexOfAny(new[] { ' ', '\t' }) >= 0 && !v.StartsWith("\"") ? "\"" + v + "\"" : v; }

        /// <summary>Writes the ssh client configuration, keeping the previous one as config.bak; the file is readable by its owner only.</summary>
        public static void WriteConfig(IList<string> lines)
        {
            Directory.CreateDirectory(KeyGen.SshDir);
            if (File.Exists(ConfigPath)) File.Copy(ConfigPath, ConfigPath + ".bak", true);
            File.WriteAllText(ConfigPath, string.Join("\n", lines) + "\n", new UTF8Encoding(false));
            // ssh refuses a configuration that others can write (w32-sshfileperm.c): the same rule as for private keys.
            try { KeyGen.EnsurePrivateKeyAcl(ConfigPath); } catch (Exception ex) { Log.Error("Permissions of " + ConfigPath, ex, false); }
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

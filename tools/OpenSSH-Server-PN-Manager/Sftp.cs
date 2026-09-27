// OpenSSH Server PN Manager: Sftp (the SFTP subsystem, transfer logging, SFTP-only accounts)

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.RegularExpressions;

namespace OpenSSHServerPNManager
{
    /// <summary>
    /// An SFTP-only account or group: it may transfer files and do nothing else (no shell, no commands, no terminal, no
    /// forwarding), optionally confined to a folder that it sees as "/".
    /// </summary>
    internal sealed class SftpRule
    {
        public bool IsGroup;
        /// <summary>The name as sshd sees it (Accounts.Canonical): lower case, "domain\name" for domain accounts.</summary>
        public string Name;
        /// <summary>
        /// ChrootDirectory: the folder the account sees as "/", a path with a drive letter in which %u stands for the account
        /// name and %h for its profile folder; null for none (the account sees the disks as its Windows permissions allow).
        /// </summary>
        public string Folder;
        /// <summary>Downloads only: sftp-server -R refuses every request that would change a file or a folder.</summary>
        public bool ReadOnly;
        /// <summary>AuthorizedKeysFile for the accounts of the rule (the partner groups: keys that only administrators change), or null for the usual file.</summary>
        public string KeysFile;
        public string Kind { get { return IsGroup ? "Group" : "User"; } }
        public SftpRule Clone() { return new SftpRule { IsGroup = IsGroup, Name = Name, Folder = Folder, ReadOnly = ReadOnly, KeysFile = KeysFile }; }
        public bool SameAs(SftpRule o) { return o != null && IsGroup == o.IsGroup && Name == o.Name && Folder == o.Folder && ReadOnly == o.ReadOnly && KeysFile == o.KeysFile; }
        public string Describe()
        {
            return (ReadOnly ? "download only" : "upload and download") + ", " + (Folder == null ? "not confined to a folder" : "confined to " + Folder);
        }
    }

    internal sealed class SftpState
    {
        /// <summary>The command of the top-level "Subsystem sftp" line, or null when there is none: then no client can use SFTP.</summary>
        public string Subsystem;
        /// <summary>sftp-server logs every file opened, closed, renamed and removed, with the bytes read and written (-l INFO or more).</summary>
        public bool LogTransfers;
        public List<SftpRule> Rules = new List<SftpRule>();
        /// <summary>Null when the section of SFTP-only accounts can be rewritten; otherwise why it is left as it is (it was edited by hand).</summary>
        public string RulesProblem;
        /// <summary>ForceCommand and ChrootDirectory in Match blocks outside the section, e.g. "line 57, Match User bob: ForceCommand internal-sftp".</summary>
        public List<string> OtherMatchSettings = new List<string>();
        public bool Enabled { get { return Subsystem != null; } }
    }

    /// <summary>
    /// Reads and writes the SFTP settings in sshd_config: the "Subsystem sftp" line with the log level of sftp-server, and a
    /// section of Match blocks for SFTP-only accounts, written and read like the rules section of the Authentication tab.
    /// On Windows, internal-sftp runs sftp-server.exe (contrib/win32/win32compat/misc.c, build_exec_command) and
    /// ChrootDirectory applies to SFTP sessions only, so every rule forces internal-sftp.
    /// </summary>
    internal static class SftpConfig
    {
        public const string RegionBegin = "# SFTP-only accounts, managed on the SFTP tab of OpenSSH Server PN Manager.";
        public const string RegionNote = "# The first rule that matches an account applies. These accounts transfer files only: no shell, commands, terminal or forwarding.";
        public const string RegionEnd = "# End of SFTP-only accounts.";
        /// <summary>The SFTP server of the packages, next to sshd.exe; sshd finds it by its bare name.</summary>
        public const string DefaultServer = "sftp-server.exe";
        /// <summary>The sftp-server log level that records each file opened and closed with the bytes read and written, and each rename and removal.</summary>
        public const string TransferLogLevel = "INFO";
        /// <summary>Log levels of sftp-server (log.c) at which file transfers are logged.</summary>
        private static readonly string[] TransferLevels = { "INFO", "VERBOSE", "DEBUG", "DEBUG1", "DEBUG2", "DEBUG3" };
        /// <summary>What an SFTP-only account may not do besides SFTP. Each rule writes every one of them, so the first rule that matches decides.</summary>
        internal static readonly string[] Locks = { "PermitTTY", "AllowTcpForwarding", "AllowAgentForwarding", "AllowStreamLocalForwarding", "PermitTunnel", "X11Forwarding" };
        private static readonly string[] RuleKeywords = new[] { "ForceCommand", "ChrootDirectory" }.Concat(Locks).ToArray();
        /// <summary>Settings a rule may have besides those every rule writes.</summary>
        private static readonly string[] OptionalKeywords = { "AuthorizedKeysFile" };
        private static readonly string[] SftpKeywords = { "ForceCommand", "ChrootDirectory" };

        public static SftpState Read(SshdConfig cfg)
        {
            var st = new SftpState { Subsystem = cfg.GetSubsystem("sftp") };
            st.LogTransfers = st.Subsystem != null && LogsTransfers(st.Subsystem);
            int begin, end;
            st.RulesProblem = FindRegion(cfg.Lines, out begin, out end);
            if (st.RulesProblem == null && begin >= 0)
            {
                string problem;
                var rules = ParseRules(cfg.Lines, begin, end, out problem);
                if (problem != null) st.RulesProblem = problem; else st.Rules = rules;
            }
            st.OtherMatchSettings = OtherMatchSettings(cfg.Lines, st.RulesProblem == null ? begin : -1, end);
            return st;
        }

        /// <summary>The -l level given to sftp-server in a command ("sftp-server.exe -l INFO", "-lVERBOSE"), or null.</summary>
        internal static string LogLevel(string command)
        {
            string err; var args = SshdArgs.Split(command, out err);
            if (args == null) return null;
            string level = null;
            for (int i = 1; i < args.Count; i++)
            {
                if (args[i] == "-l" && i + 1 < args.Count) level = args[++i];
                else if (args[i].StartsWith("-l") && args[i].Length > 2) level = args[i].Substring(2);
            }
            return level;
        }

        internal static bool LogsTransfers(string command)
        {
            var level = LogLevel(command);
            return level != null && TransferLevels.Contains(level, StringComparer.OrdinalIgnoreCase);
        }

        /// <summary>
        /// The subsystem command with transfer logging on or off: "-l INFO" is added, or every -l option removed (sftp-server
        /// then logs errors only). The program and its other options stay; a command that already logs transfers at a
        /// more detailed level keeps it.
        /// </summary>
        internal static string WithLogging(string command, bool log)
        {
            string err; var args = SshdArgs.Split(command, out err);
            if (args == null || args.Count == 0) throw new ConfigException("The Subsystem sftp line cannot be read (" + (err ?? "no program") + "). Correct it on the sshd_config (text) tab.");
            if (LogsTransfers(command) == log) return command;
            var kept = new List<string> { args[0] };
            for (int i = 1; i < args.Count; i++)
            {
                if (args[i] == "-l") { i++; continue; }
                if (args[i].StartsWith("-l") && args[i].Length > 2) continue;
                kept.Add(args[i]);
            }
            if (log) { kept.Add("-l"); kept.Add(TransferLogLevel); }
            return SshdArgs.Join(kept);
        }

        /// <summary>A line that starts the section (trimmed).</summary>
        public static bool IsRegionBegin(string trimmed) { return trimmed == RegionBegin; }

        /// <summary>Finds the section (its start and end lines). Returns why it cannot be used, or null.</summary>
        private static string FindRegion(List<string> lines, out int begin, out int end)
        {
            begin = end = -1;
            for (int i = 0; i < lines.Count; i++)
            {
                var t = lines[i].Trim();
                if (t == RegionBegin)
                {
                    if (begin >= 0) return "its start line appears twice, lines " + (begin + 1) + " and " + (i + 1);
                    begin = i;
                }
                else if (t == RegionEnd)
                {
                    if (begin < 0 || end >= 0) return "line " + (i + 1) + " ends a section of SFTP-only accounts that was not started";
                    end = i;
                }
            }
            if (begin >= 0 && end < 0) return "the section that starts at line " + (begin + 1) + " has no end line";
            return null;
        }

        /// <summary>Reads the rules exactly as Apply writes them; anything else is reported and the section is left alone.</summary>
        private static List<SftpRule> ParseRules(List<string> lines, int begin, int end, out string problem)
        {
            problem = null;
            var rules = new List<SftpRule>();
            SftpRule cur = null; var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            bool closed = false;
            Func<string> incomplete = () => "the rule for " + cur.Kind.ToLowerInvariant() + " " + cur.Name + " does not set all of " + string.Join(", ", RuleKeywords);
            for (int i = begin + 1; i < end && problem == null; i++)
            {
                var t = lines[i].Trim();
                if (t.Length == 0 || t.StartsWith("#")) continue;
                var at = "line " + (i + 1) + ": ";
                if (closed) { problem = at + "text after \"Match all\""; break; }
                var m = Regex.Match(t, @"^Match\s+(User|Group)\s+(.+)$", RegexOptions.IgnoreCase);
                string argError; var names = m.Success ? SshdArgs.Split(m.Groups[2].Value, out argError) : null;
                // One account or group, as Apply writes it: a list ("bob,alice") or a pattern ("sftp*", "!x") is a hand edit.
                if (names == null || names.Count != 1 || names[0].IndexOfAny(Accounts.ForbiddenNameChars) >= 0) m = System.Text.RegularExpressions.Match.Empty;
                bool matchAll = Regex.IsMatch(t, @"^Match\s+all$", RegexOptions.IgnoreCase);
                if (m.Success || matchAll)
                {
                    if (cur != null && !RuleKeywords.All(seen.Contains)) { problem = incomplete() + " (before line " + (i + 1) + ")"; break; }
                    cur = null;
                    if (matchAll) { closed = true; continue; }
                    cur = new SftpRule { IsGroup = m.Groups[1].Value.Equals("Group", StringComparison.OrdinalIgnoreCase), Name = names[0] };
                    rules.Add(cur); seen.Clear();
                    continue;
                }
                if (Regex.IsMatch(t, @"^Match\b", RegexOptions.IgnoreCase)) { problem = at + "a Match line this program does not write (" + t + ")"; break; }
                if (cur == null) { problem = at + "a setting outside a rule"; break; }
                string k, v;
                if (!SshdConfig.Split(t, out k, out v)) { problem = at + "unreadable line"; break; }
                var kw = RuleKeywords.Concat(OptionalKeywords).FirstOrDefault(x => x.Equals(k, StringComparison.OrdinalIgnoreCase));
                if (kw == null) { problem = at + k + " is not a setting of an SFTP-only account"; break; }
                if (!seen.Add(kw)) { problem = at + kw + " appears twice in one rule"; break; }
                if (kw == "ForceCommand")
                {
                    bool readOnly; var why = ParseForceCommand(v, out readOnly);
                    if (why != null) { problem = at + why; break; }
                    cur.ReadOnly = readOnly;
                }
                else if (kw == "ChrootDirectory")
                {
                    var folder = SshdArgs.Split(v, out argError);
                    if (folder == null || folder.Count != 1) { problem = at + "ChrootDirectory must name one folder"; break; }
                    cur.Folder = folder[0].Equals("none", StringComparison.OrdinalIgnoreCase) ? null : folder[0];
                }
                else if (kw == "AuthorizedKeysFile")
                {
                    var files = SshdArgs.Split(v, out argError);
                    if (files == null || files.Count != 1) { problem = at + "AuthorizedKeysFile must name one file"; break; }
                    cur.KeysFile = files[0];
                }
                else if (!v.Equals("no", StringComparison.OrdinalIgnoreCase)) { problem = at + kw + " must be no"; break; }
            }
            if (problem == null && cur != null && !closed && !RuleKeywords.All(seen.Contains)) problem = incomplete();
            if (problem == null && !closed) problem = "the section does not end with \"Match all\"";
            return problem == null ? rules : null;
        }

        /// <summary>Why a ForceCommand value is not one this program writes ("internal-sftp", -l level, -R), or null.</summary>
        private static string ParseForceCommand(string v, out bool readOnly)
        {
            readOnly = false;
            string err; var args = SshdArgs.Split(v, out err);
            if (args == null || args.Count == 0 || args[0] != "internal-sftp") return "ForceCommand must be internal-sftp";
            for (int i = 1; i < args.Count; i++)
            {
                if (args[i] == "-R") readOnly = true;
                else if (args[i] == "-l" && i + 1 < args.Count && TransferLevels.Concat(new[] { "QUIET", "FATAL", "ERROR" }).Contains(args[i + 1], StringComparer.OrdinalIgnoreCase)) i++;
                else return "ForceCommand internal-sftp has an option this program does not write (" + args[i] + ")";
            }
            return null;
        }

        private static List<string> OtherMatchSettings(List<string> lines, int begin, int end)
        {
            var l = new List<string>(); string match = null;
            for (int i = 0; i < lines.Count; i++)
            {
                if (begin >= 0 && i >= begin && i <= end) { match = i == end ? "Match all (after the section of SFTP-only accounts)" : null; continue; }
                var t = lines[i].Trim();
                if (t.Length == 0 || t.StartsWith("#")) continue;
                if (Regex.IsMatch(t, @"^Match\b", RegexOptions.IgnoreCase)) { match = t; continue; }
                string k, v;
                if (!SshdConfig.Split(t, out k, out v) || !SftpKeywords.Any(x => x.Equals(k, StringComparison.OrdinalIgnoreCase))) continue;
                // At the top level these apply to every account: noted as well, since they decide before any rule.
                l.Add("line " + (i + 1) + ", " + (match ?? "all accounts") + ": " + k + " " + v);
            }
            return l;
        }

        /// <summary>Why a folder cannot be used for ChrootDirectory on Windows, or null. Accepts %u, and %h at the start.</summary>
        public static string FolderError(string folder)
        {
            if (string.IsNullOrWhiteSpace(folder)) return "Enter the folder, for example C:\\SFTP\\%u.";
            if (folder != folder.Trim() || folder.Any(char.IsControl) || folder.IndexOf('"') >= 0) return "The folder must be one line without quotation marks or spaces around it.";
            // sshd for Windows (misc.c, chroot) takes a path that starts with a drive letter only; %h, the profile folder
            // (C:\Users\name), is one, so it can only stand at the start.
            bool home = Regex.IsMatch(folder, @"^%h([\\/]|$)");
            if (!home && !Regex.IsMatch(folder, @"^[A-Za-z]:[\\/]")) return "The folder must be a full path that starts with a drive letter or with %h, for example C:\\SFTP\\%u.";
            if (folder.IndexOf("%h", home ? 2 : 0, StringComparison.Ordinal) >= 0) return "%h, the profile folder, can only stand at the start of the folder, as in %h\\sftp.";
            var rest = Regex.Replace(folder, "%[uh%]", "x");
            if (rest.IndexOf('%') >= 0) return "Only %u (the account name) and %h (its profile folder) can stand in the folder.";
            if (rest.IndexOfAny(new[] { '*', '?', '<', '>', '|' }) >= 0 || (home ? rest.IndexOf(':') : rest.IndexOf(':', 2)) >= 0) return "The folder contains a character Windows does not allow in a path.";
            return null;
        }

        /// <summary>
        /// Writes the SFTP subsystem (with or without transfer logging, or none) and, unless rules is null, rewrites the
        /// section of SFTP-only accounts: one Match block per rule, in order, before the first other Match block so that the
        /// rules take precedence, closed by "Match all".
        /// </summary>
        public static void Apply(SshdConfig cfg, bool enabled, bool logTransfers, List<SftpRule> rules)
        {
            if (rules != null)
            {
                if (!enabled && rules.Count > 0) throw new ConfigException("SFTP-only accounts need SFTP: remove their rules, or keep SFTP on.");
                var keys = new HashSet<string>(StringComparer.Ordinal);
                foreach (var r in rules)
                {
                    var who = r.Kind.ToLowerInvariant() + " " + r.Name;
                    if (string.IsNullOrWhiteSpace(r.Name) || r.Name != r.Name.Trim() || r.Name.Any(char.IsControl) || r.Name.IndexOfAny(Accounts.ForbiddenNameChars) >= 0)
                        throw new ConfigException("\"" + r.Name + "\" is not a valid account name for a rule.");
                    if (r.Folder != null) { var e = FolderError(r.Folder); if (e != null) throw new ConfigException("The rule for " + who + ": " + e); }
                    if (!keys.Add(r.Kind + "\n" + r.Name)) throw new ConfigException("There are two rules for " + who + ".");
                }
            }
            int begin, end;
            var problem = FindRegion(cfg.Lines, out begin, out end);
            if (problem == null && begin >= 0) ParseRules(cfg.Lines, begin, end, out problem); // never overwrite lines added by hand
            if (rules != null && problem != null) throw new ConfigException("The section of SFTP-only accounts in sshd_config was changed by hand (" + problem + "). Correct or delete it on the sshd_config (text) tab first.");
            // sshd refuses the subsystem request when there is no Subsystem sftp line, whatever ForceCommand says, so the
            // accounts of a section this tab cannot read (edited by hand) would lose SFTP as well.
            if (!enabled && rules == null && (begin >= 0 || problem != null)) throw new ConfigException("SFTP-only accounts need SFTP, and sshd_config has a section of them that was changed by hand. Delete it on the sshd_config (text) tab first, or keep SFTP on.");
            var current = cfg.GetSubsystem("sftp");
            if (!enabled) { if (current != null) cfg.SetSubsystem("sftp", null); }
            else
            {
                var wanted = WithLogging(current ?? DefaultServer, logTransfers);
                if (wanted != current) cfg.SetSubsystem("sftp", wanted);
            }
            if (rules == null) return;
            FindRegion(cfg.Lines, out begin, out end); // the subsystem line may have moved the section
            int at;
            if (begin >= 0)
            {
                cfg.Lines.RemoveRange(begin, end - begin + 1);
                at = begin;
                if (at > 0 && at < cfg.Lines.Count && cfg.Lines[at - 1].Trim().Length == 0 && cfg.Lines[at].Trim().Length == 0) cfg.Lines.RemoveAt(at);
            }
            else at = cfg.FirstMatchIndex();
            if (rules.Count == 0) return;
            var force = "internal-sftp" + (logTransfers ? " -l " + TransferLogLevel : "");
            var block = new List<string> { RegionBegin, RegionNote };
            foreach (var r in rules)
            {
                block.Add("Match " + r.Kind + " " + SshdArgs.Quote(r.Name));
                block.Add("\tForceCommand " + force + (r.ReadOnly ? " -R" : ""));
                block.Add("\tChrootDirectory " + (r.Folder == null ? "none" : SshdArgs.Quote(r.Folder)));
                if (r.KeysFile != null) block.Add("\tAuthorizedKeysFile " + SshdArgs.Quote(r.KeysFile));
                foreach (var k in Locks) block.Add("\t" + k + " no");
            }
            block.Add("Match all");
            block.Add(RegionEnd);
            if (at > 0 && cfg.Lines[at - 1].Trim().Length > 0) block.Insert(0, "");
            if (at < cfg.Lines.Count && cfg.Lines[at].Trim().Length > 0) block.Add("");
            cfg.Lines.InsertRange(at, block);
        }

        /// <summary>
        /// The folder of a rule for one account, as sshd works it out (session.c: %u the account name, %h its profile folder,
        /// %% a percent sign), or null when the account has no profile folder yet and the path needs one.
        /// </summary>
        public static string ExpandFolder(string folder, string account, string home)
        {
            if (folder == null) return null;
            if (folder.Contains("%h") && home == null) return null;
            var sb = new System.Text.StringBuilder();
            for (int i = 0; i < folder.Length; i++)
            {
                if (folder[i] == '%' && i + 1 < folder.Length)
                {
                    char c = folder[++i];
                    if (c == 'u') { sb.Append(account); continue; }
                    if (c == 'h') { sb.Append(home); continue; }
                    if (c == '%') { sb.Append('%'); continue; }
                    sb.Append('%');
                }
                sb.Append(folder[i]);
            }
            return sb.ToString().Replace('/', '\\');
        }

        private static readonly SecurityIdentifier Admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        private static readonly SecurityIdentifier LocalSystem = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        private static readonly SecurityIdentifier TrustedInstaller = new SecurityIdentifier("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");

        /// <summary>SYSTEM and Administrators in full control, for this folder and everything in it; nobody else.</summary>
        private static DirectorySecurity AdminsOnly()
        {
            var inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
            var ds = new DirectorySecurity();
            ds.SetAccessRuleProtection(true, false);
            ds.AddAccessRule(new FileSystemAccessRule(LocalSystem, FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
            ds.AddAccessRule(new FileSystemAccessRule(Admins, FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
            ds.SetOwner(Admins);
            return ds;
        }

        /// <summary>
        /// Creates the folder of an SFTP-only account or group when it does not exist, and gives it access to it: modify
        /// rights (read and write, not the permissions), or read rights for a download-only rule; SYSTEM and Administrators
        /// keep full control, and other accounts get no access. Missing parent folders (C:\SFTP for C:\SFTP\%u) are made for
        /// SYSTEM and Administrators only, so that no account can create the folder of another one next to its own; the
        /// account passes through them with the right every account has to traverse folders. An existing folder keeps its
        /// permissions and only gets the account or group added (FolderNote says what to look at). Returns what was done.
        /// </summary>
        public static string PrepareFolder(string path, SecurityIdentifier who, bool readOnly)
        {
            if (who == null) throw new ConfigException("The account or group was not found, so its folder cannot be prepared.");
            var rights = readOnly ? FileSystemRights.ReadAndExecute : FileSystemRights.Modify;
            var inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
            path = Path.GetFullPath(path);
            if (!Directory.Exists(path))
            {
                // One folder at a time: Directory.CreateDirectory(path, security) of the .NET Framework gives every
                // missing parent the same permissions, and so the account its rights on the parent too.
                var missing = new Stack<string>();
                for (var d = path; !string.IsNullOrEmpty(d) && !Directory.Exists(d); d = Path.GetDirectoryName(d)) missing.Push(d);
                while (missing.Count > 1) Directory.CreateDirectory(missing.Pop(), AdminsOnly());
                var ds = AdminsOnly();
                ds.AddAccessRule(new FileSystemAccessRule(who, rights, inherit, PropagationFlags.None, AccessControlType.Allow));
                Directory.CreateDirectory(path, ds);
                return "created " + path;
            }
            var cur = Directory.GetAccessControl(path);
            bool has = cur.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>()
                          .Any(r => r.AccessControlType == AccessControlType.Allow && who.Equals(r.IdentityReference) && (r.FileSystemRights & rights) == rights);
            var note = FolderNote(path, who);
            if (has) return path + " exists, with access" + (note == null ? "" : " (" + note + ")");
            cur.AddAccessRule(new FileSystemAccessRule(who, rights, inherit, PropagationFlags.None, AccessControlType.Allow));
            Directory.SetAccessControl(path, cur);
            return path + " exists; " + (readOnly ? "read" : "modify") + " rights added" + (note == null ? "" : " (" + note + ")");
        }

        /// <summary>
        /// What to look at in the permissions of an existing folder before an SFTP-only account gets it: an owner other than
        /// SYSTEM, Administrators, TrustedInstaller or the account (the owner can change the permissions at any time), and
        /// other accounts that can open it. Null when there is nothing to say.
        /// </summary>
        public static string FolderNote(string path, SecurityIdentifier who)
        {
            try
            {
                var ds = Directory.GetAccessControl(path);
                var notes = new List<string>();
                var owner = ds.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
                Func<SecurityIdentifier, bool> trusted = s => s == Admins || s == LocalSystem || s == TrustedInstaller || s.Equals(who);
                if (owner != null && !trusted(owner)) notes.Add("owned by " + Name(owner) + ", who can change its permissions");
                var others = ds.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>()
                               .Where(r => r.AccessControlType == AccessControlType.Allow && (r.PropagationFlags & PropagationFlags.InheritOnly) == 0)
                               .Select(r => (SecurityIdentifier)r.IdentityReference).Where(s => !trusted(s) && !IsCreatorOwner(s)).Distinct().Select(Name).ToList();
                if (others.Count > 0) notes.Add("also open to " + string.Join(", ", others.Take(4)) + (others.Count > 4 ? ", ..." : ""));
                return notes.Count == 0 ? null : string.Join("; ", notes);
            }
            catch (Exception ex) { return "its permissions could not be read: " + ex.Message; }
        }

        private static bool IsCreatorOwner(SecurityIdentifier s) { return s.IsWellKnown(WellKnownSidType.CreatorOwnerSid); }
        private static string Name(SecurityIdentifier sid) { try { return sid.Translate(typeof(NTAccount)).Value; } catch { return sid.Value; } }
    }
}

// OpenSSH Server Manager for Windows: Auth

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
    // Login methods: Windows authentication, public key and Kerberos, for everyone and per user or group
    // ------------------------------------------------------------------------------------------

    /// <summary>The login methods a set of accounts may use (the Authentication tab).</summary>
    internal sealed class AuthMethods
    {
        /// <summary>Windows authentication: the Windows account name and password, checked by Windows (PasswordAuthentication).</summary>
        public bool Password = true;
        /// <summary>A key in the account's authorized_keys file (PubkeyAuthentication).</summary>
        public bool PublicKey = true;
        /// <summary>Kerberos single sign-on for domain accounts through SSPI (GSSAPIAuthentication).</summary>
        public bool Kerberos;
        /// <summary>The public key first, then the Windows password (AuthenticationMethods publickey,password).</summary>
        public bool RequireBoth;
        /// <summary>An AuthenticationMethods value this program does not model; it is kept as written.</summary>
        public string Custom;
        /// <summary>Only read from sshd -T; this program never switches them on.</summary>
        public bool KbdInteractive, Hostbased;

        public AuthMethods Clone() { return (AuthMethods)MemberwiseClone(); }
        public bool AnyEnabled { get { return Password || PublicKey || Kerberos; } }
        public bool BothRequired { get { return Custom == null && RequireBoth && Password && PublicKey; } }

        /// <summary>The AuthenticationMethods value for these methods ("any": one method is enough).</summary>
        public string Requirement
        {
            get
            {
                if (Custom != null) return Custom;
                return BothRequired ? "publickey,password" + (Kerberos ? " gssapi-with-mic" : "") : "any";
            }
        }

        /// <summary>Takes an AuthenticationMethods value. Set the method flags first: whether a value is modelled depends on them.</summary>
        public void SetRequirement(string value)
        {
            RequireBoth = false; Custom = null;
            var lists = (value ?? "").Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries).Select(x => x.ToLowerInvariant()).Distinct().OrderBy(x => x, StringComparer.Ordinal).ToList();
            if (lists.Count == 0 || (lists.Count == 1 && lists[0] == "any")) return;
            bool both = Password && PublicKey;
            if (both && lists.Count == 1 && lists[0] == "publickey,password") { RequireBoth = true; return; }
            if (both && Kerberos && lists.Count == 2 && lists[0] == "gssapi-with-mic" && lists[1] == "publickey,password") { RequireBoth = true; return; }
            Custom = value.Trim();
        }

        private static List<List<string>> Lists(string requirement)
        {
            return requirement.ToLowerInvariant().Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries)
                .Select(l => l.Split(',').Select(m => m.Split(':')[0]).ToList()).ToList();
        }

        /// <summary>
        /// The methods a client is offered before it has logged in, as "Permission denied (...)" lists them. With
        /// AuthenticationMethods, sshd offers the first method of every list whose methods are all enabled.
        /// </summary>
        public SortedSet<string> Offered()
        {
            var enabled = new Dictionary<string, bool>
            {
                { "publickey", PublicKey }, { "password", Password }, { "gssapi-with-mic", Kerberos },
                { "keyboard-interactive", KbdInteractive }, { "hostbased", Hostbased },
            };
            var s = new SortedSet<string>(StringComparer.Ordinal);
            var req = Requirement;
            if (req == "any") { foreach (var kv in enabled) if (kv.Value) s.Add(kv.Key); return s; }
            foreach (var list in Lists(req))
            {
                bool on;
                if (list.All(m => enabled.TryGetValue(m, out on) && on)) s.Add(list[0]);
            }
            return s;
        }

        /// <summary>True when an account can log in without a key: by password, or by Kerberos where Kerberos can work.</summary>
        public bool WorksWithoutKey(bool kerberosUsable)
        {
            Func<string, bool> usable = m => (m == "password" && Password) || (m == "gssapi-with-mic" && Kerberos && kerberosUsable);
            var req = Requirement;
            if (req == "any") return usable("password") || usable("gssapi-with-mic");
            return Lists(req).Any(list => !list.Contains("publickey") && list.All(usable));
        }

        /// <summary>Plain-language summary, e.g. "Windows authentication or public key".</summary>
        public string Describe()
        {
            var parts = new List<string>();
            if (Password) parts.Add("Windows authentication");
            if (PublicKey) parts.Add("public key");
            if (Kerberos) parts.Add("Kerberos");
            if (Custom != null) return (parts.Count == 0 ? "no method" : string.Join(", ", parts)) + ", combined by the custom rule AuthenticationMethods " + Custom;
            if (BothRequired) return "public key and then Windows authentication, both required" + (Kerberos ? "; or Kerberos" : "");
            if (parts.Count == 0) return "no login method: nobody can log in";
            return parts.Count == 1 ? parts[0] + " only" : string.Join(" or ", parts);
        }

        public bool SameAs(AuthMethods o) { return o != null && Password == o.Password && PublicKey == o.PublicKey && Kerberos == o.Kerberos && Requirement == o.Requirement; }
    }

    /// <summary>Login methods for one user or one group: a Match block in the rules section of sshd_config.</summary>
    internal sealed class AuthRule
    {
        public bool IsGroup;
        /// <summary>The name as sshd sees it (Accounts.Canonical): lower case, "domain\name" for domain accounts.</summary>
        public string Name;
        public AuthMethods Methods = new AuthMethods();
        public string Kind { get { return IsGroup ? "Group" : "User"; } }
        public AuthRule Clone() { return new AuthRule { IsGroup = IsGroup, Name = Name, Methods = Methods.Clone() }; }
        public bool SameAs(AuthRule o) { return o != null && IsGroup == o.IsGroup && Name == o.Name && Methods.SameAs(o.Methods); }
    }

    internal sealed class AuthState
    {
        public AuthMethods Global = new AuthMethods();
        public List<AuthRule> Rules = new List<AuthRule>();
        /// <summary>Null when the rules section can be rewritten; otherwise why it is left as it is (it was edited by hand).</summary>
        public string RulesProblem;
        /// <summary>Login-method settings in Match blocks outside the rules section, e.g. "line 57, Match User bob: PasswordAuthentication yes".</summary>
        public List<string> OtherMatchSettings = new List<string>();
    }

    /// <summary>Windows accounts in the form sshd uses them (win32compat pwd.c and win32_groupaccess.c).</summary>
    internal static class Accounts
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct USER_INFO_1 { public string Name; public string Password; public int PasswordAge; public int Priv; public string HomeDir; public string Comment; public int Flags; public string ScriptPath; }

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool LookupAccountName(string system, string account, byte[] sid, ref int sidSize, StringBuilder domain, ref int domainSize, out int use);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool LookupAccountSid(string system, byte[] sid, StringBuilder name, ref int nameSize, StringBuilder domain, ref int domainSize, out int use);
        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)] private static extern int NetGetJoinInformation(string server, out IntPtr name, out int status);
        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)] private static extern int NetUserEnum(string server, int level, int filter, out IntPtr buf, int prefMaxLen, out int read, out int total, ref int resume);
        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)] private static extern int NetLocalGroupEnum(string server, int level, out IntPtr buf, int prefMaxLen, out int read, out int total, ref IntPtr resume);
        [DllImport("netapi32.dll")] private static extern int NetApiBufferFree(IntPtr buf);

        private const int SidTypeUser = 1, SidTypeGroup = 2, SidTypeAlias = 4, SidTypeWellKnownGroup = 5;
        /// <summary>Characters that sshd reads as pattern syntax or that cmd.exe would expand (% in the SYSTEM check).</summary>
        public static readonly char[] ForbiddenNameChars = { '"', ',', '*', '?', '!', '#', '%' };

        /// <summary>sshd lower-cases account names with the C locale, which changes A-Z only.</summary>
        public static string AsciiLower(string s)
        {
            var sb = new StringBuilder(s ?? "");
            for (int i = 0; i < sb.Length; i++) if (sb[i] >= 'A' && sb[i] <= 'Z') sb[i] = (char)(sb[i] + 32);
            return sb.ToString();
        }

        public static bool DomainJoined()
        {
            try
            {
                IntPtr name; int status;
                if (NetGetJoinInformation(null, out name, out status) != 0) return false;
                NetApiBufferFree(name);
                return status == 3; // NetSetupDomainName
            }
            catch { return false; }
        }

        private static string UseText(int use)
        {
            switch (use)
            {
                case 1: return "a user account";
                case 2: case 4: return "a group";
                case 3: return "a domain";
                case 5: return "a well-known group";
                case 9: return "a computer account";
                default: return "not an account";
            }
        }

        /// <summary>
        /// The name sshd uses for an account in Match User and Match Group: "name" for local accounts and built-in groups,
        /// "domain\name" for domain accounts, with A-Z lower-cased. Null, with a message, when the name is not a user
        /// account, or not a group sshd can see (it matches local, built-in and domain groups; not Everyone and the like).
        /// </summary>
        public static string Canonical(string typed, bool group, out string error)
        {
            error = null;
            var kind = group ? "group" : "user";
            var name = (typed ?? "").Trim().Replace('/', '\\');
            if (name.StartsWith(".\\")) name = Environment.MachineName + name.Substring(1);
            if (name.Length == 0) { error = "Enter a " + kind + " name."; return null; }
            if (name.Any(char.IsControl) || name.IndexOfAny(ForbiddenNameChars) >= 0) { error = "\"" + typed + "\" is not a valid " + kind + " name (quotation marks, commas, # and % and the wildcards * ? ! are not allowed)."; return null; }
            var sid = new byte[68]; int sidSize = sid.Length, domSize = 256, use;
            var dom = new StringBuilder(domSize);
            if (!LookupAccountName(null, name, sid, ref sidSize, dom, ref domSize, out use))
            {
                error = (group ? "Group" : "User") + " \"" + typed + "\" was not found on this computer" + (DomainJoined() ? " or in the domain" : "") + ".";
                return null;
            }
            var s = new SecurityIdentifier(sid, 0).Value;
            if (group && use != SidTypeGroup && use != SidTypeAlias)
            {
                error = "\"" + typed + "\" is " + UseText(use) + (use == SidTypeWellKnownGroup ? ", which sshd cannot match: it matches local, built-in and domain groups only." : ", not a group.");
                return null;
            }
            if (group && !s.StartsWith("S-1-5-32-") && !s.StartsWith("S-1-5-21-")) { error = "\"" + typed + "\" is not a local, built-in or domain group, so sshd cannot match it."; return null; }
            if (!group && use != SidTypeUser) { error = "\"" + typed + "\" is " + UseText(use) + ", not a user account."; return null; }
            int nmSize = 256; domSize = 256;
            var nm = new StringBuilder(nmSize); dom = new StringBuilder(domSize);
            if (!LookupAccountSid(null, sid, nm, ref nmSize, dom, ref domSize, out use)) { error = "Could not look up \"" + typed + "\"."; return null; }
            bool local = s.StartsWith("S-1-5-32-") || string.Equals(dom.ToString(), Environment.MachineName, StringComparison.OrdinalIgnoreCase);
            return AsciiLower(local ? nm.ToString() : dom + "\\" + nm);
        }

        /// <summary>Enabled local user accounts, for suggestions.</summary>
        public static List<string> LocalUsers()
        {
            var l = new List<string>(); IntPtr buf = IntPtr.Zero; int read, total, resume = 0;
            try
            {
                if (NetUserEnum(null, 1, 2 /*FILTER_NORMAL_ACCOUNT*/, out buf, -1, out read, out total, ref resume) != 0) return l;
                int size = Marshal.SizeOf(typeof(USER_INFO_1));
                for (int i = 0; i < read; i++)
                {
                    var u = (USER_INFO_1)Marshal.PtrToStructure(new IntPtr(buf.ToInt64() + (long)i * size), typeof(USER_INFO_1));
                    if ((u.Flags & 0x2 /*UF_ACCOUNTDISABLE*/) == 0) l.Add(u.Name);
                }
            }
            catch { }
            finally { if (buf != IntPtr.Zero) NetApiBufferFree(buf); }
            l.Sort(StringComparer.OrdinalIgnoreCase);
            return l;
        }

        /// <summary>Local and built-in groups, for suggestions.</summary>
        public static List<string> LocalGroups()
        {
            var l = new List<string>(); IntPtr buf = IntPtr.Zero, resume = IntPtr.Zero; int read, total;
            try
            {
                if (NetLocalGroupEnum(null, 0, out buf, -1, out read, out total, ref resume) != 0) return l;
                for (int i = 0; i < read; i++) l.Add(Marshal.PtrToStringUni(Marshal.ReadIntPtr(buf, i * IntPtr.Size)));
            }
            catch { }
            finally { if (buf != IntPtr.Zero) NetApiBufferFree(buf); }
            l.Sort(StringComparer.OrdinalIgnoreCase);
            return l;
        }

        /// <summary>Profile folder of an account (ProfileList registry key), or null when it has never logged on.</summary>
        public static string ProfileDir(SecurityIdentifier sid)
        {
            if (sid == null) return null;
            try
            {
                using (var k = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default).OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\" + sid.Value))
                {
                    var p = k == null ? null : k.GetValue("ProfileImagePath") as string;
                    return string.IsNullOrEmpty(p) ? null : Environment.ExpandEnvironmentVariables(p);
                }
            }
            catch { return null; }
        }
    }

    /// <summary>Reads and writes the login methods in sshd_config, and asks sshd what they mean for an account.</summary>
    internal static class AuthConfig
    {
        public const string RegionBegin = "# Login methods by user and group, managed on the Authentication tab of OpenSSH Server Manager.";
        public const string RegionNote = "# The first rule that matches an account applies; all other accounts use the methods set above.";
        public const string RegionEnd = "# End of login methods by user and group.";
        private static readonly string[] RuleKeywords = { "PasswordAuthentication", "PubkeyAuthentication", "GSSAPIAuthentication", "AuthenticationMethods" };
        private static readonly string[] MethodKeywords = { "PasswordAuthentication", "PubkeyAuthentication", "GSSAPIAuthentication", "AuthenticationMethods", "KbdInteractiveAuthentication", "ChallengeResponseAuthentication", "HostbasedAuthentication" };

        private static bool? Flag(string v)
        {
            if (v == null) return null;
            v = v.Trim().ToLowerInvariant();
            if (v == "yes") return true;
            if (v == "no") return false;
            return null;
        }
        private static string YesNo(bool b) { return b ? "yes" : "no"; }

        public static AuthState Read(SshdConfig cfg)
        {
            var st = new AuthState();
            var g = st.Global;
            g.Password = Flag(cfg.Get("PasswordAuthentication")) ?? true;
            g.PublicKey = Flag(cfg.Get("PubkeyAuthentication")) ?? true;
            g.Kerberos = Flag(cfg.Get("GSSAPIAuthentication")) ?? false;
            g.KbdInteractive = Flag(cfg.Get("KbdInteractiveAuthentication") ?? cfg.Get("ChallengeResponseAuthentication")) ?? true;
            g.Hostbased = Flag(cfg.Get("HostbasedAuthentication")) ?? false;
            g.SetRequirement(cfg.Get("AuthenticationMethods"));
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

        /// <summary>Finds the rules section (its start and end lines). Returns why it cannot be used, or null.</summary>
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
                    if (begin < 0 || end >= 0) return "line " + (i + 1) + " ends a rules section that was not started";
                    end = i;
                }
            }
            if (begin >= 0 && end < 0) return "the section that starts at line " + (begin + 1) + " has no end line";
            return null;
        }

        /// <summary>Reads the rules exactly as Apply writes them; anything else is reported and the section is left alone.</summary>
        private static List<AuthRule> ParseRules(List<string> lines, int begin, int end, out string problem)
        {
            problem = null;
            var rules = new List<AuthRule>();
            AuthRule cur = null; string curRequirement = null; var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            bool closed = false;
            for (int i = begin + 1; i < end && problem == null; i++)
            {
                var t = lines[i].Trim();
                if (t.Length == 0 || t.StartsWith("#")) continue;
                var at = "line " + (i + 1) + ": ";
                if (closed) { problem = at + "text after \"Match all\""; break; }
                // One user or group name, quoted and escaped as sshd reads it (SshdArgs).
                var m = Regex.Match(t, @"^Match\s+(User|Group)\s+(.+)$", RegexOptions.IgnoreCase);
                string argError; var names = m.Success ? SshdArgs.Split(m.Groups[2].Value, out argError) : null;
                if (names == null || names.Count != 1) m = System.Text.RegularExpressions.Match.Empty;
                bool matchAll = Regex.IsMatch(t, @"^Match\s+all$", RegexOptions.IgnoreCase);
                if (m.Success || matchAll)
                {
                    if (cur != null)
                    {
                        if (seen.Count != RuleKeywords.Length) { problem = "the rule for " + cur.Kind.ToLowerInvariant() + " " + cur.Name + " (before line " + (i + 1) + ") does not set all of " + string.Join(", ", RuleKeywords); break; }
                        cur.Methods.SetRequirement(curRequirement);
                    }
                    cur = null;
                    if (matchAll) { closed = true; continue; }
                    cur = new AuthRule { IsGroup = m.Groups[1].Value.Equals("Group", StringComparison.OrdinalIgnoreCase), Name = names[0] };
                    rules.Add(cur); curRequirement = null; seen.Clear();
                    continue;
                }
                if (Regex.IsMatch(t, @"^Match\b", RegexOptions.IgnoreCase)) { problem = at + "a Match line this program does not write (" + t + ")"; break; }
                if (cur == null) { problem = at + "a setting outside a rule"; break; }
                string k, v;
                if (!SshdConfig.Split(t, out k, out v)) { problem = at + "unreadable line"; break; }
                var kw = RuleKeywords.FirstOrDefault(x => x.Equals(k, StringComparison.OrdinalIgnoreCase));
                if (kw == null) { problem = at + k + " is not a login-method setting"; break; }
                if (!seen.Add(kw)) { problem = at + kw + " appears twice in one rule"; break; }
                if (kw == "AuthenticationMethods") { curRequirement = v; continue; }
                var f = Flag(v);
                if (f == null) { problem = at + kw + " must be yes or no"; break; }
                if (kw == "PasswordAuthentication") cur.Methods.Password = f.Value;
                else if (kw == "PubkeyAuthentication") cur.Methods.PublicKey = f.Value;
                else cur.Methods.Kerberos = f.Value;
            }
            if (problem == null && !closed) problem = "the section does not end with \"Match all\"";
            return problem == null ? rules : null;
        }

        private static List<string> OtherMatchSettings(List<string> lines, int begin, int end)
        {
            var l = new List<string>(); string match = null;
            for (int i = 0; i < lines.Count; i++)
            {
                // Lines after the section and before the next Match line belong to its closing "Match all" block.
                if (begin >= 0 && i >= begin && i <= end) { match = i == end ? "Match all (after the rules section)" : null; continue; }
                var t = lines[i].Trim();
                if (t.Length == 0 || t.StartsWith("#")) continue;
                if (Regex.IsMatch(t, @"^Match\b", RegexOptions.IgnoreCase)) { match = t; continue; }
                if (match == null) continue;
                string k, v;
                if (SshdConfig.Split(t, out k, out v) && MethodKeywords.Any(x => x.Equals(k, StringComparison.OrdinalIgnoreCase)))
                    l.Add("line " + (i + 1) + ", " + match + ": " + k + " " + v);
            }
            return l;
        }

        /// <summary>
        /// Writes the methods for all accounts (top of the file) and, unless rules is null, rewrites the rules section: one
        /// Match block per rule, in order, before the first other Match block so that the rules take precedence, closed by
        /// "Match all". Keyboard-interactive is switched off: OpenSSH for Windows has no keyboard-interactive back end, so it
        /// never logs anyone in, and each client attempt at it counts against MaxAuthTries. Windows passwords use the
        /// password method.
        /// </summary>
        public static void Apply(SshdConfig cfg, AuthMethods global, List<AuthRule> rules)
        {
            if (!global.AnyEnabled) throw new ConfigException("Tick at least one login method for all accounts.");
            if (rules != null)
            {
                var keys = new HashSet<string>(StringComparer.Ordinal);
                foreach (var r in rules)
                {
                    var who = r.Kind.ToLowerInvariant() + " " + r.Name;
                    if (string.IsNullOrWhiteSpace(r.Name) || r.Name != r.Name.Trim() || r.Name.Any(char.IsControl) || r.Name.IndexOfAny(Accounts.ForbiddenNameChars) >= 0)
                        throw new ConfigException("\"" + r.Name + "\" is not a valid account name for a rule.");
                    if (!r.Methods.AnyEnabled) throw new ConfigException("The rule for " + who + " has no login method.");
                    if (!keys.Add(r.Kind + "\n" + r.Name)) throw new ConfigException("There are two rules for " + who + ".");
                }
            }
            int begin, end;
            var problem = FindRegion(cfg.Lines, out begin, out end);
            if (problem == null && begin >= 0) ParseRules(cfg.Lines, begin, end, out problem); // never overwrite lines added by hand
            if (rules != null && problem != null) throw new ConfigException("The rules section in sshd_config was changed by hand (" + problem + "). Correct or delete it on the sshd_config (text) tab first.");
            cfg.Set("PasswordAuthentication", YesNo(global.Password));
            cfg.Set("PubkeyAuthentication", YesNo(global.PublicKey));
            cfg.Set("GSSAPIAuthentication", YesNo(global.Kerberos));
            cfg.Set("KbdInteractiveAuthentication", "no");
            cfg.Set("ChallengeResponseAuthentication", ""); // older name of KbdInteractiveAuthentication; its first value would win
            var req = global.Requirement;
            cfg.Set("AuthenticationMethods", req == "any" ? "" : req);
            if (rules == null) return;
            FindRegion(cfg.Lines, out begin, out end); // Set may have inserted lines above the section
            int at;
            if (begin >= 0)
            {
                cfg.Lines.RemoveRange(begin, end - begin + 1);
                at = begin;
                if (at > 0 && at < cfg.Lines.Count && cfg.Lines[at - 1].Trim().Length == 0 && cfg.Lines[at].Trim().Length == 0) cfg.Lines.RemoveAt(at);
            }
            else at = cfg.FirstMatchIndex();
            if (rules.Count == 0) return;
            var block = new List<string> { RegionBegin, RegionNote };
            foreach (var r in rules)
            {
                block.Add("Match " + r.Kind + " " + SshdArgs.Quote(r.Name));
                block.Add("\tPasswordAuthentication " + YesNo(r.Methods.Password));
                block.Add("\tPubkeyAuthentication " + YesNo(r.Methods.PublicKey));
                block.Add("\tGSSAPIAuthentication " + YesNo(r.Methods.Kerberos));
                block.Add("\tAuthenticationMethods " + r.Methods.Requirement);
            }
            block.Add("Match all");
            block.Add(RegionEnd);
            if (at > 0 && cfg.Lines[at - 1].Trim().Length > 0) block.Insert(0, "");
            if (at < cfg.Lines.Count && cfg.Lines[at].Trim().Length > 0) block.Add("");
            cfg.Lines.InsertRange(at, block);
        }

        /// <summary>sshd -T for one account with Match blocks applied: lower-case keyword => value. Null, with a message, on failure.</summary>
        public static Dictionary<string, string> EffectiveSettingsFor(string user, string configPath, int port, out string error)
        {
            var spec = "user=" + user + ",host=localhost,addr=127.0.0.1,laddr=127.0.0.1,lport=" + port;
            // Run by an administrator, sshd sees the groups of the administrator's own account only; for another account a
            // "Match Group" never applies. Run as SYSTEM, like the service, it gives the running server's answer.
            bool asSystem = user != Accounts.AsciiLower(KeyGen.LoginName()) && UsesGroupMatch(configPath ?? Ssh.ConfigPath);
            var r = asSystem ? SystemTasks.SshdTest(configPath ?? Ssh.ConfigPath, spec, 60000)
                             : Proc.Run(Ssh.Exe("sshd.exe"), "-T" + (configPath != null ? " -f " + Proc.Quote(configPath) : "") + " -C " + Proc.Quote(spec), 20000);
            if (!r.Ok) { error = "sshd -T failed" + (r.TimedOut ? " (timed out)" : " (exit " + r.ExitCode + ")") + ": " + r.Output; return null; }
            error = null;
            var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var line in r.StdOut.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
            {
                var i = line.IndexOf(' ');
                if (i <= 0) continue;
                var k = line.Substring(0, i).ToLowerInvariant(); var v = line.Substring(i + 1).Trim();
                d[k] = d.ContainsKey(k) ? d[k] + " " + v : v;
            }
            return d;
        }

        /// <summary>True when a configuration has a Match block with a Group condition, or includes files that may have one.</summary>
        public static bool UsesGroupMatch(string path)
        {
            try { return File.ReadAllLines(path).Any(l => Regex.IsMatch(l, @"^\s*(Match\s.*\bGroup\b|Include\s)", RegexOptions.IgnoreCase)); }
            catch { return true; }
        }

        public static AuthMethods MethodsFrom(Dictionary<string, string> d)
        {
            Func<string, bool> yes = k => { string v; return d.TryGetValue(k, out v) && v.Trim().Equals("yes", StringComparison.OrdinalIgnoreCase); };
            var m = new AuthMethods { Password = yes("passwordauthentication"), PublicKey = yes("pubkeyauthentication"), Kerberos = yes("gssapiauthentication"), KbdInteractive = yes("kbdinteractiveauthentication"), Hostbased = yes("hostbasedauthentication") };
            string req; d.TryGetValue("authenticationmethods", out req);
            m.SetRequirement(req);
            return m;
        }

        /// <summary>The login methods sshd works out for an account (sshd -T -C). user must be in sshd's form (Accounts.Canonical).</summary>
        public static AuthMethods EffectiveFor(string user, string configPath, int port, out string error)
        {
            var d = EffectiveSettingsFor(user, configPath, port, out error);
            return d == null ? null : MethodsFrom(d);
        }

        /// <summary>
        /// Asks a running server which methods it offers an account, as a client sees them: a connection that sends only the
        /// user name (the "none" method: no password, no key) and reads the list from "Permission denied (...)". The host
        /// key is pinned to this server's own keys. Null, with a message, when there is no such answer.
        /// </summary>
        public static SortedSet<string> Probe(string user, string host, int port, out string error)
        {
            var kh = Path.Combine(Path.GetTempPath(), "osm-known_hosts-" + Guid.NewGuid().ToString("N"));
            try
            {
                Ssh.WriteKnownHosts(kh, host, port);
                var args = "-F none -T -o PreferredAuthentications=none -o BatchMode=yes -o IdentityAgent=none -o StrictHostKeyChecking=yes" +
                           " -o UserKnownHostsFile=" + Proc.Quote(kh) + " -o GlobalKnownHostsFile=" + Proc.Quote(kh) + " -o ConnectTimeout=10" +
                           " -p " + port + " -l " + Proc.Quote(user) + " " + host + " exit";
                var r = Proc.Run(Ssh.Exe("ssh.exe"), args, 30000, null, new Dictionary<string, string> { { "SSH_ASKPASS_REQUIRE", "never" } });
                var m = Regex.Match(r.StdErr, @"Permission denied \(([^)]*)\)");
                if (!m.Success) { error = r.TimedOut ? "no answer from " + host + " port " + port : (r.Output.Length > 0 ? r.Output : "ssh exit code " + r.ExitCode); return null; }
                error = null;
                return new SortedSet<string>(m.Groups[1].Value.Split(',').Select(x => x.Trim().ToLowerInvariant()).Where(x => x.Length > 0), StringComparer.Ordinal);
            }
            catch (Exception ex) { error = ex.Message; return null; }
            finally { try { File.Delete(kh); } catch { } }
        }

        public static string MethodNames(IEnumerable<string> methods)
        {
            var names = methods.Select(m => m == "password" ? "password (Windows authentication)" : m == "publickey" ? "public key" : m == "gssapi-with-mic" ? "Kerberos (gssapi-with-mic)" : m).ToList();
            return names.Count == 0 ? "no method" : string.Join(", ", names);
        }

        /// <summary>
        /// Why the account running this program could not log in over SSH any more with a candidate configuration, or null:
        /// it would need a key (no method without one can work; Kerberos counts only on a domain member) and has none.
        /// </summary>
        public static string LockoutWarning(string configPath, int port)
        {
            var me = Accounts.AsciiLower(KeyGen.LoginName());
            string err; var d = EffectiveSettingsFor(me, configPath, port, out err);
            if (d == null) return "sshd could not work out the login methods for " + me + " (you): " + err;
            var eff = MethodsFrom(d);
            if (eff.WorksWithoutKey(Accounts.DomainJoined())) return null;
            if (!eff.PublicKey) return "With these settings " + me + " (you) has no login method that can work on this computer" + (eff.Kerberos ? " (Kerberos needs an Active Directory domain)" : "") + ".";
            string value; d.TryGetValue("authorizedkeysfile", out value);
            var file = Ssh.ResolveKeysFile(value, me, Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));
            int n = 0;
            try { if (file != null) n = Keys.Read(file).Count(k => k.Type != "?"); } catch { }
            if (n > 0) return null;
            return "With these settings " + me + " (you) can log in over SSH only with a public key" + (eff.BothRequired ? " plus the Windows password" : "") +
                   ", but no key is authorized for this account" + (file != null ? " in\n" + file : "") + ".\n\nCreate a key on the Key generator tab (tick \"Allow this key to log in\") and test it first.";
        }
    }

    /// <summary>
    /// One-off scheduled tasks that run a program from System32 or the installation folder as SYSTEM. Everything they read
    /// or write lies in a folder only SYSTEM and Administrators can change.
    /// </summary>
    internal static class SystemTasks
    {
        private static string Schtasks { get { return Path.Combine(Environment.SystemDirectory, "schtasks.exe"); } }

        /// <summary>
        /// The task definition. A startup task waits two minutes after boot: started at once, a profile-removal task found
        /// WMI or the User Profile Service not ready, did nothing and still reported success (seen 26 Sep 2026).
        /// </summary>
        internal static string TaskXml(string description, string command, string arguments, bool atStartup)
        {
            Func<string, string> x = System.Security.SecurityElement.Escape;
            return "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\r\n<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">" +
                      "<RegistrationInfo><Description>" + x(description) + "</Description></RegistrationInfo>" +
                      (atStartup ? "<Triggers><BootTrigger><Enabled>true</Enabled><Delay>PT2M</Delay></BootTrigger></Triggers>" : "") +
                      "<Principals><Principal id=\"Author\"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>" +
                      "<Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>" +
                      "<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><AllowHardTerminate>true</AllowHardTerminate><AllowStartOnDemand>true</AllowStartOnDemand>" +
                      "<Enabled>true</Enabled><ExecutionTimeLimit>PT10M</ExecutionTimeLimit></Settings>" +
                      "<Actions Context=\"Author\"><Exec><Command>" + x(command) + "</Command><Arguments>" + x(arguments) + "</Arguments></Exec></Actions></Task>";
        }

        private static void Register(string name, string description, string command, string arguments, bool atStartup)
        {
            var xml = TaskXml(description, command, arguments, atStartup);
            var file = Path.Combine(Path.GetTempPath(), "osm-task-" + Guid.NewGuid().ToString("N") + ".xml");
            File.WriteAllText(file, xml, Encoding.Unicode);
            try
            {
                var r = Proc.Run(Schtasks, "/Create /TN " + Proc.Quote(name) + " /XML " + Proc.Quote(file) + " /F", 30000);
                if (!r.Ok) throw new Exception("schtasks /Create failed: " + r.Output);
            }
            finally { try { File.Delete(file); } catch { } }
        }

        public static bool Delete(string name) { return Proc.Run(Schtasks, "/Delete /TN " + Proc.Quote(name) + " /F", 30000).Ok; }
        public static bool Exists(string name) { return Proc.Run(Schtasks, "/Query /TN " + Proc.Quote(name), 15000).Ok; }

        private static string ReadShared(string path)
        {
            using (var f = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            using (var r = new StreamReader(f)) return r.ReadToEnd();
        }

        /// <summary>
        /// sshd -T -f configPath -C spec, run as SYSTEM. sshd evaluates "Match Group" for an account only when it can create a
        /// token for that account, which it does only as SYSTEM (win32_usertoken_utils.c, get_user_token): run by an
        /// administrator it sees no groups for any other account, so group rules would silently not apply.
        /// </summary>
        public static RunResult SshdTest(string configPath, string spec, int timeoutMs)
        {
            var r = new RunResult { ExitCode = -1 };
            if (spec.IndexOfAny(new[] { '"', '%', '\r', '\n' }) >= 0) { r.StdErr = "the account name contains a character that cannot be passed to sshd as SYSTEM"; return r; }
            var id = Guid.NewGuid().ToString("N").Substring(0, 12);
            var dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "osm-check-" + id);
            var task = "OpenSSH Server Manager check " + id;
            bool registered = false;
            try
            {
                Acl.CreatePrivateFolder(dir);
                var cfg = Path.Combine(dir, "sshd_config"); File.Copy(configPath, cfg);
                var output = Path.Combine(dir, "output.txt"); var exit = Path.Combine(dir, "exit.txt");
                // cmd.exe only redirects the output; with /s it runs the quoted command line exactly as written.
                var args = "/d /s /c \"\"" + Ssh.Exe("sshd.exe") + "\" -T -f \"" + cfg + "\" -C \"" + spec + "\" > \"" + output + "\" 2>&1" +
                           " & if errorlevel 1 ((echo 1)> \"" + exit + "\") else ((echo 0)> \"" + exit + "\")\"";
                Register(task, "OpenSSH Server Manager: sshd -T as SYSTEM for one account (temporary)", Path.Combine(Environment.SystemDirectory, "cmd.exe"), args, false);
                registered = true;
                var run = Proc.Run(Schtasks, "/Run /TN " + Proc.Quote(task), 30000);
                if (!run.Ok) { r.StdErr = "schtasks /Run failed: " + run.Output; return r; }
                var sw = Stopwatch.StartNew(); string code = null;
                while (sw.ElapsedMilliseconds < timeoutMs)
                {
                    try { if (File.Exists(exit)) { code = ReadShared(exit).Trim(); if (code.Length > 0) break; } } catch (IOException) { }
                    Thread.Sleep(100);
                }
                if (string.IsNullOrEmpty(code)) { r.TimedOut = true; r.StdErr = "sshd -T as SYSTEM did not finish within " + (timeoutMs / 1000) + " s"; return r; }
                var text = ReadShared(output);
                r.ExitCode = code == "0" ? 0 : 1;
                if (r.ExitCode == 0) r.StdOut = text; else r.StdErr = text;
                return r;
            }
            catch (Exception ex) { r.StdErr = ex.Message; return r; }
            finally
            {
                if (registered) Delete(task);
                try { Directory.Delete(dir, true); } catch { }
            }
        }

        /// <summary>
        /// Deletes a profile at the next startup, and at every startup until it is gone; the task then removes itself. For the
        /// profile of a deleted test account that Windows keeps loaded: sshd loads the profile at login and never unloads it.
        /// </summary>
        public static string ScheduleProfileRemoval(SecurityIdentifier sid, string account)
        {
            var task = "OpenSSH Server Manager remove test profile " + account;
            var script = ProfileRemovalScript(sid.Value, task);
            Register(task, "Deletes the profile of " + account + ", a temporary test account of OpenSSH Server Manager --authtest that no longer exists, then removes this task.",
                     Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe"),
                     "-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand " + Convert.ToBase64String(Encoding.Unicode.GetBytes(script)), true);
            return task;
        }

        /// <summary>
        /// The removal script. It retries for six minutes while WMI or the profile service does not answer, and exits 1 while
        /// the profile remains (a loaded profile waits for the next startup), so the task result shows whether it worked;
        /// the first version ignored every error and reported success.
        /// </summary>
        internal static string ProfileRemovalScript(string sid, string task)
        {
            return "$sid = '" + sid + "'; $task = '" + task.Replace("'", "''") + "'; " +
                   "for ($i = 0; $i -lt 18; $i++) { " +
                   "try { " +
                   "$p = @(Get-WmiObject Win32_UserProfile -Filter \"SID='$sid'\" -ErrorAction Stop); " +
                   "if ($p.Count -eq 0) { schtasks.exe /Delete /TN $task /F | Out-Null; exit 0 }; " +
                   "if ($p[0].Loaded) { exit 1 }; " +
                   "$p[0].Delete() " +
                   "} catch { }; " +
                   "Start-Sleep -Seconds 20 }; " +
                   "exit 1";
        }
    }
}

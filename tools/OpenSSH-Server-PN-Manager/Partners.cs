// OpenSSH Server PN Manager: Partners (SFTP partner accounts)

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace OpenSSHServerPNManager
{
    // ------------------------------------------------------------------------------------------
    // SFTP partners: local accounts of people outside the company who exchange files over SFTP. Three local groups carry
    // everything sshd needs, written once into sshd_config (the SFTP and login-method sections of the other tabs):
    //   SFTP-Partners           SFTP only, confined to <root>\<account>, upload and download
    //   SFTP-Partners-ReadOnly  the same, download only
    //   SFTP-Partners-KeyOnly   public key only (every other partner: Windows password, or a key when it has one)
    // Their keys live in %ProgramData%\ssh\partner_keys\<account>, which only administrators change. Adding, changing or
    // removing a partner then touches the account, its groups, its folder and its keys, never sshd_config or the service.
    // ------------------------------------------------------------------------------------------

    /// <summary>The names the partner feature uses (fixed in the program; other values only in tests).</summary>
    internal sealed class PartnerGroups
    {
        public string Full = "SFTP-Partners", ReadOnly = "SFTP-Partners-ReadOnly", KeyOnly = "SFTP-Partners-KeyOnly";
        /// <summary>The folder of the partners' keys, one file per account (named as sshd names the account, %u).</summary>
        public string KeysDir = Path.Combine(Ssh.ConfigDir, "partner_keys");
        public static PartnerGroups Default { get { return new PartnerGroups(); } }

        /// <summary>The AuthorizedKeysFile value for the rules: the %ProgramData% form for the real folder, a full path in tests.</summary>
        public string KeysFileSetting
        {
            get
            {
                var real = Path.Combine(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "ssh"), "partner_keys");
                return string.Equals(Path.GetFullPath(KeysDir), real, StringComparison.OrdinalIgnoreCase) ? "__PROGRAMDATA__/ssh/partner_keys/%u" : KeysDir.Replace('\\', '/') + "/%u";
            }
        }

        public string[] All { get { return new[] { Full, ReadOnly, KeyOnly }; } }
        public static string Sshd(string group) { return Accounts.AsciiLower(group); }
    }

    /// <summary>One partner, as the Partners tab shows it.</summary>
    internal sealed class PartnerAccount
    {
        public string Name, FullName = "", Company = ""; public SecurityIdentifier Sid;
        public bool ReadOnly, KeyOnly, Disabled, LockedOut;
        public DateTime? Expires, LastLogon; public int KeyCount;
        public bool Expired { get { return Expires != null && Expires.Value <= DateTime.Now; } }
        public string Status { get { return Disabled ? "disabled" : Expired ? "expired" : LockedOut ? "locked out" : "active"; } }
        public bool Active { get { return !Disabled && !Expired && !LockedOut; } }
        public string Access { get { return ReadOnly ? "download only" : "full"; } }
        public string Login { get { return KeyOnly ? (KeyCount == 0 ? "key only (no key yet)" : "key only") : KeyCount > 0 ? "password or key" : "password"; } }
    }

    /// <summary>What a partner account needs from sshd_config, and whether it is there (PartnerSetup.Check).</summary>
    internal sealed class PartnerSetupState
    {
        public List<string> MissingGroups = new List<string>();
        /// <summary>What sshd_config lacks, in words ("the SFTP rule for group sftp-partners"); empty when it is complete.</summary>
        public List<string> Missing = new List<string>();
        /// <summary>Reasons the sections cannot be rewritten (edited by hand), or settings that keep partners out (AllowUsers).</summary>
        public List<string> Problems = new List<string>();
        /// <summary>The folder under which each partner gets a folder of its own (from the rules), or null before the setup.</summary>
        public string Root;
        /// <summary>Why the root lets other accounts in (PartnerSetup.RootProblem), or null; also in Problems. RootFixable: the setup can correct it.</summary>
        public string RootProblem; public bool RootFixable;
        /// <summary>Why partners cannot be made on this computer at all (a domain controller), or null.</summary>
        public string HostError;
        public bool Complete { get { return MissingGroups.Count == 0 && Missing.Count == 0; } }
    }

    internal static class PartnerSetup
    {
        public static string DefaultRoot { get { return Path.Combine(Path.GetPathRoot(Environment.SystemDirectory) ?? "C:\\", "SFTP"); } }

        private static SftpRule SftpRuleFor(string group, string root, bool readOnly, PartnerGroups g)
        {
            return new SftpRule { IsGroup = true, Name = PartnerGroups.Sshd(group), Folder = root.TrimEnd('\\') + "\\%u", ReadOnly = readOnly, KeysFile = g.KeysFileSetting };
        }

        /// <summary>The login-method rules: key-only partners first (they are in an access group too, and the first rule that matches applies).</summary>
        private static List<AuthRule> AuthRules(PartnerGroups g)
        {
            return new List<AuthRule>
            {
                new AuthRule { IsGroup = true, Name = PartnerGroups.Sshd(g.KeyOnly), Methods = new AuthMethods { Password = false, PublicKey = true } },
                new AuthRule { IsGroup = true, Name = PartnerGroups.Sshd(g.Full), Methods = new AuthMethods { Password = true, PublicKey = true } },
                new AuthRule { IsGroup = true, Name = PartnerGroups.Sshd(g.ReadOnly), Methods = new AuthMethods { Password = true, PublicKey = true } },
            };
        }

        public static PartnerSetupState Check(SshdConfig cfg, PartnerGroups g)
        {
            var st = new PartnerSetupState();
            st.HostError = Partners.HostError(LocalAccounts.IsDomainController());
            // The local group itself: a domain group or a well-known name would pass a name lookup, but NetLocalGroupAddMembers needs the local group.
            foreach (var n in g.All) if (!LocalAccounts.GroupExists(n)) st.MissingGroups.Add(n);
            var sftp = SftpConfig.Read(cfg);
            var auth = AuthConfig.Read(cfg);
            if (sftp.RulesProblem != null) st.Problems.Add("the section of SFTP-only accounts was changed by hand (" + sftp.RulesProblem + ")");
            if (auth.RulesProblem != null) st.Problems.Add("the rules section of the Authentication tab was changed by hand (" + auth.RulesProblem + ")");
            if (!sftp.Enabled) st.Missing.Add("SFTP (the Subsystem sftp line)");
            else if (!sftp.LogTransfers) st.Problems.Add("file transfers are not logged (SFTP tab), so the transfer history of partners stays empty");
            var full = sftp.Rules.FirstOrDefault(r => r.IsGroup && r.Name == PartnerGroups.Sshd(g.Full));
            var ro = sftp.Rules.FirstOrDefault(r => r.IsGroup && r.Name == PartnerGroups.Sshd(g.ReadOnly));
            if (full != null && full.Folder != null && full.Folder.EndsWith("\\%u", StringComparison.Ordinal)) st.Root = Path.GetDirectoryName(full.Folder);
            foreach (var want in new[] { SftpRuleFor(g.Full, st.Root ?? DefaultRoot, false, g), SftpRuleFor(g.ReadOnly, st.Root ?? DefaultRoot, true, g) })
            {
                var have = want.ReadOnly ? ro : full;
                if (have == null || !have.SameAs(want)) st.Missing.Add("the SFTP rule for group " + want.Name + " (" + want.Describe() + ", keys in " + g.KeysFileSetting + ")");
            }
            var rules = auth.Rules;
            var wanted = AuthRules(g);
            for (int i = 0; i < wanted.Count; i++)
            {
                int at = rules.FindIndex(r => r.IsGroup && r.Name == wanted[i].Name);
                if (at < 0 || !rules[at].Methods.SameAs(wanted[i].Methods)) st.Missing.Add("the login-method rule for group " + wanted[i].Name + " (" + wanted[i].Methods.Describe() + ")");
            }
            int keyOnlyAt = rules.FindIndex(r => r.IsGroup && r.Name == wanted[0].Name);
            if (keyOnlyAt > 0 && rules.Take(keyOnlyAt).Any(r => r.IsGroup && (r.Name == wanted[1].Name || r.Name == wanted[2].Name)))
                st.Missing.Add("the rule for " + wanted[0].Name + " before the rules for the other partner groups");
            // The first rule that matches applies: a rule above a partner rule that also covers partners gives them its settings.
            var partnerRules = new HashSet<string>(g.All.Select(PartnerGroups.Sshd));
            List<string> members = null;
            Func<bool, string, bool> covers = (isGroup, n) =>
            {
                if (isGroup) { var sid = Acl.SidOfAccount(n); return sid != null && !sid.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid); }
                if (n.Contains("\\")) return false; // a domain account, never a partner
                if (members == null) members = LocalAccounts.GroupMembers(g.Full).Concat(LocalAccounts.GroupMembers(g.ReadOnly)).Select(Accounts.AsciiLower).ToList();
                return members.Contains(Accounts.AsciiLower(n));
            };
            int lastSftp = sftp.Rules.FindLastIndex(r => r.IsGroup && partnerRules.Contains(r.Name));
            foreach (var r in sftp.Rules.Take(Math.Max(0, lastSftp)).Where(r => !(r.IsGroup && partnerRules.Contains(r.Name)) && covers(r.IsGroup, r.Name)))
                st.Problems.Add("the SFTP rule for " + r.Kind.ToLowerInvariant() + " " + r.Name + " comes before a partner rule, so " + (r.IsGroup ? "partners in that group get" : "the partner " + r.Name + " gets") + " its folder and access instead (move it below the partner rules on the SFTP tab)");
            int lastAuth = rules.FindLastIndex(r => r.IsGroup && partnerRules.Contains(r.Name));
            foreach (var r in rules.Take(Math.Max(0, lastAuth)).Where(r => !(r.IsGroup && partnerRules.Contains(r.Name)) && covers(r.IsGroup, r.Name)))
                st.Problems.Add("the login-method rule for " + r.Kind.ToLowerInvariant() + " " + r.Name + " comes before a partner rule, so " + (r.IsGroup ? "partners in that group log" : "the partner " + r.Name + " logs") + " in by its methods instead (move it below the partner rules on the Authentication tab)");
            if (st.Root != null && Directory.Exists(st.Root))
            {
                st.RootProblem = RootProblem(st.Root, out st.RootFixable);
                if (st.RootProblem != null) st.Problems.Add("the partners' folder is not for administrators only: " + st.RootProblem + ". Another account could make the folder of a future partner, or put a folder of its own in place of one" + (st.RootFixable ? " (Set up partner accounts can make it a folder for administrators only)" : ""));
            }
            string err;
            var allowGroups = cfg.GetCombinedArgs("AllowGroups", out err);
            if (allowGroups != null && allowGroups.Count > 0 && !new[] { g.Full, g.ReadOnly }.All(n => allowGroups.Contains(PartnerGroups.Sshd(n), StringComparer.OrdinalIgnoreCase)))
                st.Missing.Add("the partner groups in AllowGroups (" + SshdArgs.FormatTyped(allowGroups) + ")");
            var allowUsers = cfg.GetCombinedArgs("AllowUsers", out err);
            if (allowUsers != null && allowUsers.Count > 0) st.Problems.Add("AllowUsers lets only the accounts listed there log in (" + SshdArgs.FormatTyped(allowUsers) + "), so partners cannot log in unless they are listed");
            var denyGroups = cfg.GetCombinedArgs("DenyGroups", out err);
            if (denyGroups != null && g.All.Select(PartnerGroups.Sshd).Any(n => denyGroups.Contains(n, StringComparer.OrdinalIgnoreCase))) st.Problems.Add("DenyGroups names a partner group");
            return st;
        }

        /// <summary>
        /// Writes what the partner groups need into a candidate sshd_config: the SFTP rules (first in their section), the
        /// login-method rules (first in theirs), SFTP with transfer logging, and the groups in AllowGroups when that is set.
        /// Rules of other accounts and groups stay as they are, after these.
        /// </summary>
        public static void Apply(SshdConfig cand, PartnerGroups g, string root)
        {
            var e = SftpConfig.FolderError(root.TrimEnd('\\') + "\\%u");
            if (e != null) throw new ConfigException("The partners' folder: " + e);
            var sftp = SftpConfig.Read(cand);
            var auth = AuthConfig.Read(cand);
            if (sftp.RulesProblem != null) throw new ConfigException("The section of SFTP-only accounts in sshd_config was changed by hand (" + sftp.RulesProblem + "). Correct it on the sshd_config (text) tab first.");
            if (auth.RulesProblem != null) throw new ConfigException("The rules section of the Authentication tab was changed by hand (" + auth.RulesProblem + "). Correct it on the sshd_config (text) tab first.");
            var names = new HashSet<string>(g.All.Select(PartnerGroups.Sshd));
            var sftpRules = new List<SftpRule> { SftpRuleFor(g.ReadOnly, root, true, g), SftpRuleFor(g.Full, root, false, g) };
            sftpRules.AddRange(sftp.Rules.Where(r => !(r.IsGroup && names.Contains(r.Name))));
            SftpConfig.Apply(cand, true, true, sftpRules);
            var authRules = AuthRules(g);
            authRules.AddRange(AuthConfig.Read(cand).Rules.Where(r => !(r.IsGroup && names.Contains(r.Name))));
            AuthConfig.Apply(cand, null, authRules); // the rules only: never rewrite the login methods of every account
            string err;
            var allowGroups = cand.GetCombinedArgs("AllowGroups", out err);
            if (allowGroups != null && allowGroups.Count > 0)
            {
                foreach (var n in new[] { g.Full, g.ReadOnly }.Select(PartnerGroups.Sshd)) if (!allowGroups.Contains(n, StringComparer.OrdinalIgnoreCase)) allowGroups.Add(n);
                cand.Set("AllowGroups", SshdArgs.Join(allowGroups));
            }
        }

        private static readonly SecurityIdentifier Admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        private static readonly SecurityIdentifier LocalSystem = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        private static readonly SecurityIdentifier TrustedInstaller = new SecurityIdentifier("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");
        // write data, add a folder, write EA, delete child, write attributes, DELETE, WRITE_DAC, WRITE_OWNER, GENERIC_ALL, GENERIC_WRITE
        private const int RootWriteMask = 0x2 | 0x4 | 0x10 | 0x40 | 0x100 | 0x10000 | 0x40000 | 0x80000 | 0x10000000 | 0x40000000;
        // Above the root, making files and folders is fine (C:\ allows it); deleting or renaming what a folder holds, or the
        // folder itself, or changing its permissions is not: that puts another folder in place of the root.
        private const int AboveRootMask = 0x40 | 0x10000 | 0x40000 | 0x80000 | 0x10000000 | 0x40000000;

        private static bool TrustedSid(SecurityIdentifier s)
        {
            return s == Admins || s == LocalSystem || s == TrustedInstaller || s.IsWellKnown(WellKnownSidType.CreatorOwnerSid) || s.Value == "S-1-3-4" /*OWNER RIGHTS*/;
        }
        private static string NameOf(SecurityIdentifier sid) { try { return sid.Translate(typeof(NTAccount)).Value; } catch { return sid.Value; } }

        /// <summary>
        /// Why the folder of the partners' folders lets other accounts in, or null: an owner other than SYSTEM, Administrators
        /// or TrustedInstaller, of it or of a folder above it; another account that can change what it holds (and so make the
        /// folder of a future partner first); or another account that can rename, delete or take over a folder above it (and
        /// so put a folder of its own in its place). canHarden: only the root itself is concerned, so making it a folder for
        /// administrators only (HardenRoot) corrects it; never for a drive root, a link or a folder that does not exist.
        /// </summary>
        public static string RootProblem(string root, out bool canHarden)
        {
            canHarden = false;
            try
            {
                // Read by its name, a link has permissions of its own: those of the folder it leads to, and of the folders
                // above that one, are never checked. A drive root is never a link.
                var full = Path.GetFullPath(root);
                if (full.Length > 3) full = full.TrimEnd('\\');
                for (var d = full; d != null && d != Path.GetPathRoot(d); d = Path.GetDirectoryName(d))
                {
                    var kind = Directory.Exists(d) ? SftpConfig.LinkKind(d) : null;
                    if (kind != null) return (d == full ? d : d + " (above it)") + " is " + kind + ", so the partners' folders would be wherever it leads, with permissions that were not checked";
                }
                return RootProblem(root, d => Directory.Exists(d) ? Directory.GetAccessControl(d, AccessControlSections.Owner | AccessControlSections.Access) : null, out canHarden);
            }
            catch (Exception ex) { canHarden = false; return "the permissions of " + root + " and of the folders above it were not checked (" + ex.Message + ")"; }
        }

        /// <param name="read">The permissions of a folder, or null when it does not exist.</param>
        internal static string RootProblem(string root, Func<string, DirectorySecurity> read, out bool canHarden)
        {
            canHarden = false;
            var full = Path.GetFullPath(root);
            if (full.Length > 3) full = full.TrimEnd('\\');
            var problems = new List<string>(); bool exists = false, aboveOnly = true;
            for (var d = full; d != null; d = Path.GetDirectoryName(d))
            {
                var ds = read(d);
                if (ds == null) continue; // made for administrators only by the setup
                bool isRoot = d == full;
                if (isRoot) exists = true;
                var owner = ds.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
                // A volume root cannot be renamed or deleted: DELETE there (Authenticated Users have Modify on the root of a
                // Windows 10/11 data drive) puts nothing in a partner folder's place.
                int mask = isRoot ? RootWriteMask : AboveRootMask;
                if (!isRoot && string.Equals(Path.GetPathRoot(d), d, StringComparison.OrdinalIgnoreCase)) mask &= ~0x10000;
                var who = ds.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>()
                            .Where(r => r.AccessControlType == AccessControlType.Allow && (r.PropagationFlags & PropagationFlags.InheritOnly) == 0 && ((int)r.FileSystemRights & mask) != 0)
                            .Select(r => (SecurityIdentifier)r.IdentityReference).Where(s => !TrustedSid(s)).Distinct().Select(NameOf).ToList();
                var where = isRoot ? d : d + " (above it)";
                if (owner == null || !TrustedSid(owner)) problems.Add(where + " is owned by " + (owner == null ? "an unknown account" : NameOf(owner)));
                if (who.Count > 0) problems.Add(string.Join(", ", who) + (isRoot ? " can change what " + d + " holds" : " can rename or take over " + where));
                if (!isRoot && (who.Count > 0 || owner == null || !TrustedSid(owner))) aboveOnly = false;
            }
            if (problems.Count == 0) return null;
            canHarden = exists && aboveOnly && !string.Equals(Path.GetPathRoot(full), full, StringComparison.OrdinalIgnoreCase);
            return string.Join("; ", problems);
        }

        /// <summary>Makes an existing root a folder for administrators only: owner Administrators, SYSTEM and Administrators in full control, nothing inherited.</summary>
        public static void HardenRoot(string root)
        {
            Directory.SetAccessControl(root, SftpConfig.AdminsOnly());
            bool canHarden; var left = RootProblem(root, out canHarden);
            if (left != null) throw new ConfigException("The permissions of " + root + " were changed, but it still lets other accounts in: " + left + ".");
            Log.Info("Partners' folder " + root + " made a folder for administrators only");
        }

        /// <summary>
        /// The order of the setup: the groups and folders first (when that fails, sshd_config stays as it was), then
        /// sshd_config when it changes, then sshd restarted with it: also for a first sshd_config, where save returns no
        /// backup. Returns whether sshd runs with the result.
        /// </summary>
        internal static async Task<bool> Run(bool changed, Func<Task> create, Func<Task<string>> save, Func<string, Task<bool>> useAndRestart)
        {
            await create();
            if (!changed) return true;
            var backup = await save();
            return await useAndRestart(backup);
        }

        /// <summary>Creates the partner groups that do not exist yet. Returns the names created.</summary>
        public static List<string> CreateGroups(PartnerGroups g)
        {
            var host = Partners.HostError(LocalAccounts.IsDomainController());
            if (host != null) throw new ConfigException(host);
            var made = new List<string>();
            var comments = new Dictionary<string, string>
            {
                { g.Full, "SFTP partners of OpenSSH Server PN: file exchange only, each in a folder of its own" },
                { g.ReadOnly, "SFTP partners of OpenSSH Server PN who may only download" },
                { g.KeyOnly, "SFTP partners of OpenSSH Server PN who log in with a public key only" },
            };
            foreach (var n in g.All)
            {
                if (LocalAccounts.GroupExists(n)) continue;
                LocalAccounts.CreateGroup(n, comments[n]);
                made.Add(n);
            }
            return made;
        }
    }

    /// <summary>Partners.Create found the partner's folder there already: the new account takes it only when asked to (reuseFolder).</summary>
    internal sealed class PartnerFolderExistsException : ConfigException
    {
        public readonly string Folder, Details;
        public PartnerFolderExistsException(string folder, string details)
            : base("The folder " + folder + " exists already (" + details + "). A new partner gets a folder of its own: move or rename the existing one first, or choose another name.")
        { Folder = folder; Details = details; }
    }

    internal static class Partners
    {
        /// <summary>Why a new partner account name cannot be used, or null. Letters, digits, - _ and . only, at most 20 characters.</summary>
        public static string NameError(string name)
        {
            if (string.IsNullOrEmpty(name)) return "Enter the account name the partner logs in with.";
            if (name.Length > 20) return "An account name has at most 20 characters.";
            if (!Regex.IsMatch(name, @"^[A-Za-z0-9][A-Za-z0-9._-]*$") || name.EndsWith(".")) return "Use letters, digits, - _ and . only, starting with a letter or digit (the name also names the partner's folder).";
            if (Regex.IsMatch(name, @"^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|\z)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
                return "Choose another account name: Windows reserves this name for a device, so it cannot name the partner's folder or keys file.";
            // sshd reads partner_keys\%u, and versions before 2.3.2 kept the previous keys of the partner "name" as name.bak there.
            if (name.EndsWith(".bak", StringComparison.OrdinalIgnoreCase)) return "Choose a name that does not end in .bak: earlier versions kept a partner's previous keys as partner_keys\\<name>.bak, and sshd would read such a file as this account's keys.";
            if (Acl.SidOfAccount(name) != null) return "An account or group called " + name + " exists already on this computer.";
            return null;
        }

        /// <summary>The partner's folder: the root and the account name as sshd writes it (%u).</summary>
        public static string FolderOf(string root, string name) { return Path.Combine(root, Accounts.AsciiLower(name)); }
        public static string KeysFileOf(PartnerGroups g, string name) { return Path.Combine(g.KeysDir, Accounts.AsciiLower(name)); }

        /// <summary>
        /// The files of a partner in partner_keys: its keys, and the backup of its previous keys (name.bak) unless an account
        /// of that name exists (earlier versions allowed such names): sshd reads that file as that account's keys.
        /// </summary>
        internal static List<string> KeysFilesOf(PartnerGroups g, string name, Func<string, bool> accountExists)
        {
            var l = new List<string> { KeysFileOf(g, name) };
            if (!accountExists(name + ".bak")) l.Add(KeysFileOf(g, name) + ".bak");
            return l;
        }
        private static List<string> KeysFilesOf(PartnerGroups g, string name) { return KeysFilesOf(g, name, n => Acl.SidOfAccount(n) != null); }

        public static List<PartnerAccount> List(PartnerGroups g) { return List(g, false); }

        /// <summary>The partners; strict: a group that cannot be read (other than one that does not exist) is an error, not an empty list.</summary>
        public static List<PartnerAccount> List(PartnerGroups g, bool strict)
        {
            Func<string, List<string>> members = n => strict ? LocalAccounts.GroupMembersStrict(n) : LocalAccounts.GroupMembers(n);
            var full = members(g.Full); var ro = members(g.ReadOnly); var keyOnly = new HashSet<string>(members(g.KeyOnly), StringComparer.OrdinalIgnoreCase);
            var l = new List<PartnerAccount>();
            foreach (var n in full.Concat(ro).Distinct(StringComparer.OrdinalIgnoreCase))
            {
                var p = Get(g, n);
                if (p == null) continue;
                p.ReadOnly = ro.Contains(n, StringComparer.OrdinalIgnoreCase);
                p.KeyOnly = keyOnly.Contains(n);
                l.Add(p);
            }
            return l.OrderBy(p => p.Name, StringComparer.OrdinalIgnoreCase).ToList();
        }

        /// <summary>The account's details (not its groups), or null when it is not a local user account.</summary>
        public static PartnerAccount Get(PartnerGroups g, string name)
        {
            var u = LocalAccounts.GetUser(name);
            if (u == null) return null;
            var p = new PartnerAccount
            {
                Name = u.Name, FullName = u.FullName ?? "", Company = u.Comment ?? "", Sid = Acl.SidOfAccount(u.Name),
                Disabled = (u.Flags & LocalAccounts.UF_ACCOUNTDISABLE) != 0, LockedOut = (u.Flags & LocalAccounts.UF_LOCKOUT) != 0,
                Expires = u.Expires, LastLogon = u.LastLogon,
            };
            try { p.KeyCount = Keys.Read(KeysFileOf(g, u.Name)).Count(k => k.Type != "?"); } catch { }
            return p;
        }

        /// <summary>Why partners cannot be made on this computer, or null: a domain controller has no local accounts.</summary>
        public static string HostError(bool isDomainController)
        {
            return isDomainController
                ? "This computer is a domain controller. Partner accounts are local accounts, and a domain controller has none: a partner made here would be a domain account, valid on every computer of the domain. Set up SFTP partners on a member server instead (groups SFTP-Partners* or partner accounts made here by an earlier version are in Active Directory: remove them there)."
                : null;
        }

        public static string Create(PartnerGroups g, string root, string name, string fullName, string company, bool readOnly, bool keyOnly, DateTime? expires) { return Create(g, root, name, fullName, company, readOnly, keyOnly, expires, false); }

        /// <summary>
        /// Creates a partner: the local account (password never expires, the partner cannot change it: over SFTP it could not
        /// anyway; hidden from the sign-in screen), its groups, and its folder with access for it alone. Returns the generated
        /// password, which is not stored anywhere. When a step fails, the account is removed again.
        /// An existing folder (a deleted partner's, kept) is a PartnerFolderExistsException, unless reuseFolder: then the new
        /// account gets it, with its permissions and those of everything in it reset for that account alone.
        /// </summary>
        public static string Create(PartnerGroups g, string root, string name, string fullName, string company, bool readOnly, bool keyOnly, DateTime? expires, bool reuseFolder)
        {
            var e = NameError(name);
            if (e != null) throw new ConfigException(e);
            e = HostError(LocalAccounts.IsDomainController());
            if (e != null) throw new ConfigException(e);
            if ((fullName ?? "").Any(char.IsControl) || (company ?? "").Any(char.IsControl) || (fullName ?? "").Length > 100 || (company ?? "").Length > 100) throw new ConfigException("The name and the company are one line each, at most 100 characters.");
            LocalAccounts.ExpiryValue(expires); // a date the account cannot store is refused before anything is made
            // An existing folder is never taken silently: it holds someone else's files, and its owner and other entries in
            // its permissions would keep control over what the partner exchanges.
            var folder = FolderOf(root, name);
            if (File.Exists(folder)) throw new ConfigException("A file " + folder + " is where the partner's folder would be: move or rename it first, or choose another name.");
            bool reuse = reuseFolder && Directory.Exists(folder), made = false;
            if (Directory.Exists(folder))
            {
                string kind; var link = SftpConfig.FirstLink(folder, out kind);
                if (link != null) throw new ConfigException("The folder " + folder + " exists already, and " + (link == folder ? "it is " : "it holds " + link + ", ") + kind + ": whoever made it decides what the partner would reach through it. Move or rename the folder first, or choose another name.");
                if (!reuse) throw new PartnerFolderExistsException(folder, FolderDetails(folder));
            }
            // A folder made for administrators only is no protection inside a root another account can rename or control: it
            // could put a folder of its own in the partner's place. The Partners tab reports this; here it stops the creation.
            bool fixable; var rootProblem = PartnerSetup.RootProblem(root, out fixable);
            if (rootProblem != null)
                throw new ConfigException("No partner was created: the folder of the partners' folders is not for administrators only (" + rootProblem + ")." +
                    (fixable ? "\n\nRun \"Set up partner accounts\" again: it offers to restrict " + root + " to administrators." : "\n\nMove the partners' folders to a folder only administrators can change (\"Set up partner accounts\")."));
            if (!Directory.Exists(folder))
            {
                // Made before the account, for administrators only, in one step that fails when someone made the folder in
                // the meantime: no other account can make it first once the name is known.
                SftpConfig.CreateNewFolder(folder);
                made = true;
            }
            string password;
            try
            {
                RetireKeys(g, name);
                password = NewPassword();
                LocalAccounts.CreateUser(name, password, company ?? "", LocalAccounts.UF_DONT_EXPIRE_PASSWD | LocalAccounts.UF_PASSWD_CANT_CHANGE);
            }
            catch
            {
                if (made) try { Directory.Delete(folder, false); } catch (Exception ex) { Log.Error("Removing the new folder " + folder, ex, false); }
                throw;
            }
            try
            {
                if (!string.IsNullOrEmpty(fullName)) LocalAccounts.SetFullName(name, fullName);
                LocalAccounts.SetExpiry(name, expires);
                var sid = Acl.SidOfAccount(name);
                if (sid == null) throw new Exception("the new account " + name + " has no SID");
                LocalAccounts.AddToGroup(readOnly ? g.ReadOnly : g.Full, sid);
                if (keyOnly) LocalAccounts.AddToGroup(g.KeyOnly, sid);
                LocalAccounts.HideFromSignIn(name, true);
                var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
                if (reuse) SftpConfig.ResetFolder(folder, sid, readOnly, admins);
                else SetFolderAccess(folder, sid, readOnly);
                var wrong = FolderProblem(Directory.GetAccessControl(folder, AccessControlSections.Owner | AccessControlSections.Access), sid, admins);
                if (wrong != null) throw new ConfigException("The folder " + folder + " is not as it was made for " + name + ": " + wrong + ".");
                Log.Info("SFTP partner created: " + name + (readOnly ? ", download only" : "") + (keyOnly ? ", key only" : "") + (expires != null ? ", expires " + expires.Value.ToString("yyyy-MM-dd") : "") + (reuse ? ", with the existing folder " + folder : ""));
                return password;
            }
            catch
            {
                try { LocalAccounts.DeleteUser(name); } catch (Exception ex) { Log.Error("Removing the half-made partner account " + name, ex, false); }
                try { LocalAccounts.HideFromSignIn(name, false); } catch { }
                if (made) try { Directory.Delete(folder, false); } catch (Exception ex) { Log.Error("Removing the new folder " + folder, ex, false); }
                throw;
            }
        }

        /// <summary>
        /// Creates a partner, then saves who is told about its uploads: once the account exists, a failure of that second
        /// step only becomes notifyError, so the only copy of the password is not lost.
        /// </summary>
        internal static string CreateKeepingPassword(Func<string> create, Action notify, out string notifyError)
        {
            notifyError = null;
            var password = create();
            try { notify(); }
            catch (Exception ex) { notifyError = ex.Message; Log.Error("Saving the upload notifications of a new partner", ex, false); }
            return password;
        }

        /// <summary>What the question before a new partner takes an existing folder names: its owner, its files, and who else can open it.</summary>
        internal static string FolderDetails(string folder)
        {
            var parts = new List<string>();
            try
            {
                var ds = Directory.GetAccessControl(folder, AccessControlSections.Owner | AccessControlSections.Access);
                var owner = ds.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
                parts.Add("owner " + (owner == null ? "unknown" : NameOf(owner)));
                var others = ds.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>()
                               .Where(r => r.AccessControlType == AccessControlType.Allow && (r.PropagationFlags & PropagationFlags.InheritOnly) == 0)
                               .Select(r => (SecurityIdentifier)r.IdentityReference)
                               .Where(s => !s.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid) && !s.IsWellKnown(WellKnownSidType.LocalSystemSid) && !s.IsWellKnown(WellKnownSidType.CreatorOwnerSid))
                               .Distinct().Select(NameOf).ToList();
                parts.Add(others.Count == 0 ? "no account other than SYSTEM and Administrators has access" : "also open to " + string.Join(", ", others.Take(6)) + (others.Count > 6 ? ", ..." : ""));
            }
            catch (Exception ex) { parts.Add("its permissions could not be read: " + ex.Message); }
            try
            {
                var files = SftpConfig.Contents(folder).OfType<FileInfo>().ToList();
                parts.Insert(Math.Min(1, parts.Count), files.Count + " file(s), " + Ui.Bytes(files.Sum(f => f.Length)));
            }
            catch (Exception ex) { parts.Add("its files could not be counted: " + ex.Message); }
            return string.Join("; ", parts);
        }

        /// <summary>
        /// Why a partner's folder is not the one made for it, or null: it must be owned by the given owner (Administrators),
        /// inherit nothing from above, and be open to SYSTEM, Administrators and the partner only.
        /// </summary>
        internal static string FolderProblem(DirectorySecurity ds, SecurityIdentifier partner, SecurityIdentifier owner)
        {
            var l = new List<string>();
            var o = ds.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
            if (o == null || o != owner) l.Add("owned by " + (o == null ? "an unknown account" : NameOf(o)));
            if (!ds.AreAccessRulesProtected) l.Add("it inherits permissions from the folder above");
            var others = ds.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>()
                           .Where(r => r.AccessControlType == AccessControlType.Allow).Select(r => (SecurityIdentifier)r.IdentityReference)
                           .Where(s => !s.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid) && !s.IsWellKnown(WellKnownSidType.LocalSystemSid) && s != partner)
                           .Distinct().Select(NameOf).ToList();
            if (others.Count > 0) l.Add("also open to " + string.Join(", ", others));
            return l.Count == 0 ? null : string.Join(", ", l);
        }

        private static string NameOf(SecurityIdentifier sid) { try { return sid.Translate(typeof(NTAccount)).Value; } catch { return sid.Value; } }

        /// <summary>The name and company shown for a partner, its access and login method, and its expiry date.</summary>
        public static void Update(PartnerGroups g, string root, PartnerAccount before, string fullName, string company, bool readOnly, bool keyOnly, DateTime? expires)
        {
            var name = before.Name; var sid = before.Sid ?? Acl.SidOfAccount(name);
            if (sid == null) throw new ConfigException("The account " + name + " was not found.");
            if ((fullName ?? "") != before.FullName) LocalAccounts.SetFullName(name, fullName ?? "");
            if ((company ?? "") != before.Company) LocalAccounts.SetComment(name, company ?? "");
            if (expires != LocalAccounts.LastDay(before.Expires)) LocalAccounts.SetExpiry(name, expires);
            if (readOnly != before.ReadOnly)
            {
                LocalAccounts.AddToGroup(readOnly ? g.ReadOnly : g.Full, sid);
                LocalAccounts.RemoveFromGroup(readOnly ? g.Full : g.ReadOnly, sid);
                var folder = FolderOf(root, name);
                if (Directory.Exists(folder)) SetFolderAccess(folder, sid, readOnly);
            }
            if (keyOnly != before.KeyOnly) { if (keyOnly) LocalAccounts.AddToGroup(g.KeyOnly, sid); else LocalAccounts.RemoveFromGroup(g.KeyOnly, sid); }
            Log.Info("SFTP partner changed: " + name + ", " + (readOnly ? "download only" : "upload and download") + (keyOnly ? ", key only" : "") + ", expires " + (expires == null ? "never" : expires.Value.ToString("yyyy-MM-dd")));
        }

        /// <summary>The account's rights on its folder: read, or modify; any earlier right of the account there is replaced.</summary>
        private static void SetFolderAccess(string folder, SecurityIdentifier sid, bool readOnly)
        {
            var ds = Directory.GetAccessControl(folder);
            ds.PurgeAccessRules(sid);
            ds.AddAccessRule(new FileSystemAccessRule(sid, readOnly ? FileSystemRights.ReadAndExecute : FileSystemRights.Modify, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
            Directory.SetAccessControl(folder, ds);
        }

        public static string ResetPassword(string name)
        {
            var password = NewPassword();
            LocalAccounts.SetPassword(name, password);
            // A new password also ends a lockout: the partner can try again at once.
            LocalAccounts.SetFlags(name, f => f & ~LocalAccounts.UF_LOCKOUT);
            Log.Info("SFTP partner password reset: " + name);
            return password;
        }

        public static void SetDisabled(string name, bool disabled)
        {
            LocalAccounts.SetFlags(name, f => disabled ? f | LocalAccounts.UF_ACCOUNTDISABLE : f & ~LocalAccounts.UF_ACCOUNTDISABLE);
            Log.Info("SFTP partner " + (disabled ? "disabled" : "enabled") + ": " + name);
        }

        public static void Unlock(string name) { LocalAccounts.SetFlags(name, f => f & ~LocalAccounts.UF_LOCKOUT); Log.Info("SFTP partner unlocked: " + name); }

        /// <summary>
        /// Ends the partner's open SSH sessions (a disabled or deleted partner would keep them otherwise). Returns how many;
        /// problem says why some may still be open (the sessions could not be listed, or one did not end), or is null.
        /// </summary>
        public static int Disconnect(string name, int port, out string problem)
        {
            int n = 0;
            foreach (var pid in SessionsOf(name, Sessions.List(port), out problem))
            {
                try { Sessions.Disconnect(pid); n++; }
                catch (Exception ex) { Log.Error("Disconnecting " + name + " (PID " + pid + ")", ex, false); problem = (problem == null ? "" : problem + "; ") + "the session with PID " + pid + " did not end: " + ex.Message; }
            }
            return n;
        }

        /// <summary>
        /// The processes of a partner's sessions in a list from Sessions.List (its account, local to this computer). error:
        /// why the list may lack some, from its error entry or from sessions whose account could not be read, or null.
        /// </summary>
        internal static List<int> SessionsOf(string name, IEnumerable<SessionInfo> sessions, out string error)
        {
            var me = Accounts.AsciiLower(name); var pids = new List<int>(); int unknown = 0; error = null;
            foreach (var s in sessions)
            {
                var user = s.User ?? "";
                if (s.Pid == 0 && user.StartsWith("error: ", StringComparison.Ordinal)) { error = "the open sessions could not be listed (" + user.Substring(7) + ")"; continue; }
                if (user == "?") { unknown++; continue; }
                user = Accounts.AsciiLower(user);
                int slash = user.IndexOf('\\');
                if (slash >= 0 && !string.Equals(user.Substring(0, slash), Environment.MachineName, StringComparison.OrdinalIgnoreCase)) continue; // a domain account of that name
                if (user.Substring(slash + 1) == me) pids.Add(s.Pid);
            }
            if (error == null && unknown > 0) error = unknown + " open session(s) whose account could not be read were left open";
            return pids;
        }

        /// <summary>
        /// Deletes a partner: its account (and so its group memberships), its profile, its keys, and its folder when asked.
        /// Returns what could not be done, or null.
        /// </summary>
        public static string Delete(PartnerGroups g, string root, PartnerAccount p, bool deleteFolder, out string note)
        {
            var problems = new List<string>();
            var r = LocalAccounts.DeleteUser(p.Name, p.Sid, out note);
            if (r != null) problems.Add(r);
            try { LocalAccounts.HideFromSignIn(p.Name, false); } catch { }
            foreach (var k in KeysFilesOf(g, p.Name))
                try { if (File.Exists(k)) File.Delete(k); } catch (Exception ex) { problems.Add("keys file: " + ex.Message); }
            if (deleteFolder)
            {
                var folder = FolderOf(root, p.Name);
                try { if (Directory.Exists(folder)) Directory.Delete(folder, true); } catch (Exception ex) { problems.Add("folder " + folder + ": " + ex.Message); }
            }
            Log.Info("SFTP partner deleted: " + p.Name + (deleteFolder ? ", with its folder" : ", its folder kept"));
            return problems.Count == 0 ? null : string.Join("; ", problems);
        }

        /// <summary>
        /// Moves keys left in partner_keys by an earlier account of this name (deleted outside this program, or a backup that
        /// earlier versions kept on delete) to partner_keys.removed, which sshd never reads: they must not log in to the new account.
        /// </summary>
        internal static void RetireKeys(PartnerGroups g, string name)
        {
            var stale = KeysFilesOf(g, name).Where(File.Exists).ToList();
            if (stale.Count == 0) return;
            var removed = g.KeysDir.TrimEnd('\\') + ".removed";
            if (!Directory.Exists(removed)) Acl.CreatePrivateFolder(removed);
            var stamp = DateTime.UtcNow.ToString("yyyyMMdd'T'HHmmss'Z'", System.Globalization.CultureInfo.InvariantCulture);
            foreach (var f in stale)
            {
                var target = Path.Combine(removed, Path.GetFileName(f) + "." + stamp);
                File.Move(f, target);
                Log.Info("Keys left by an earlier account " + name + " moved from " + f + " to " + target);
            }
        }

        /// <summary>The partner's authorized keys file, created with the permissions of administrators_authorized_keys when needed.</summary>
        public static string EnsureKeysFile(PartnerGroups g, string name)
        {
            if (!Directory.Exists(g.KeysDir)) Acl.CreatePrivateFolder(g.KeysDir);
            return KeysFileOf(g, name);
        }

        private const string PasswordUpper = "ABCDEFGHJKLMNPQRSTUVWXYZ", PasswordLower = "abcdefghijkmnpqrstuvwxyz", PasswordDigits = "23456789", PasswordSymbols = "!#%+-=?@_";
        public const int PasswordLength = 20;

        /// <summary>
        /// A password of 20 characters with capitals, small letters, digits and symbols (Windows' complexity rule), without
        /// characters that are easy to confuse (I l 1 O 0 o), drawn without bias from a cryptographic random source.
        /// </summary>
        public static string NewPassword()
        {
            var all = PasswordUpper + PasswordLower + PasswordDigits + PasswordSymbols;
            using (var rng = new RNGCryptoServiceProvider())
            {
                Func<int, int> pick = n =>
                {
                    var b = new byte[1];
                    while (true) { rng.GetBytes(b); if (b[0] < 256 - 256 % n) return b[0] % n; }
                };
                var c = new List<char> { PasswordUpper[pick(PasswordUpper.Length)], PasswordLower[pick(PasswordLower.Length)], PasswordDigits[pick(PasswordDigits.Length)], PasswordSymbols[pick(PasswordSymbols.Length)] };
                while (c.Count < PasswordLength) c.Add(all[pick(all.Length)]);
                for (int i = c.Count - 1; i > 0; i--) { int j = pick(i + 1); var t = c[i]; c[i] = c[j]; c[j] = t; }
                return new string(c.ToArray());
            }
        }
    }

    // ------------------------------------------------------------------------------------------
    // Local accounts and groups through the NetAPI (what Computer Management and net user use)
    // ------------------------------------------------------------------------------------------
    internal static class LocalAccounts
    {
        public const int UF_SCRIPT = 0x0001, UF_ACCOUNTDISABLE = 0x0002, UF_LOCKOUT = 0x0010, UF_PASSWD_CANT_CHANGE = 0x0040, UF_DONT_EXPIRE_PASSWD = 0x10000;
        private const uint TIMEQ_FOREVER = 0xFFFFFFFF;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct USER_INFO_2
        {
            public string Name, Password; public uint PasswordAge, Priv; public string HomeDir, Comment; public uint Flags; public string ScriptPath;
            public uint AuthFlags; public string FullName, UsrComment, Parms, Workstations; public uint LastLogon, LastLogoff, AcctExpires, MaxStorage, UnitsPerWeek;
            public IntPtr LogonHours; public uint BadPwCount, NumLogons; public string LogonServer; public uint CountryCode, CodePage;
        }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] private struct USER_INFO_1003 { public string Password; }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] private struct USER_INFO_1007 { public string Comment; }
        [StructLayout(LayoutKind.Sequential)] private struct USER_INFO_1008 { public uint Flags; }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] private struct USER_INFO_1011 { public string FullName; }
        [StructLayout(LayoutKind.Sequential)] private struct USER_INFO_1017 { public uint AcctExpires; }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] private struct LOCALGROUP_INFO_1 { public string Name, Comment; }
        [StructLayout(LayoutKind.Sequential)] private struct LOCALGROUP_MEMBERS_INFO_0 { public IntPtr Sid; }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] private struct LOCALGROUP_MEMBERS_INFO_2 { public IntPtr Sid; public int SidUsage; public string DomainAndName; }

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)] private static extern int NetUserAdd(string server, int level, ref Accounts.USER_INFO_1 info, out int parmError);
        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)] private static extern int NetUserDel(string server, string user);
        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)] private static extern int NetUserGetInfo(string server, string user, int level, out IntPtr buf);
        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)] private static extern int NetUserSetInfo(string server, string user, int level, ref USER_INFO_1003 info, out int parmError);
        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)] private static extern int NetUserSetInfo(string server, string user, int level, ref USER_INFO_1007 info, out int parmError);
        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)] private static extern int NetUserSetInfo(string server, string user, int level, ref USER_INFO_1008 info, out int parmError);
        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)] private static extern int NetUserSetInfo(string server, string user, int level, ref USER_INFO_1011 info, out int parmError);
        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)] private static extern int NetUserSetInfo(string server, string user, int level, ref USER_INFO_1017 info, out int parmError);
        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)] private static extern int NetLocalGroupAdd(string server, int level, ref LOCALGROUP_INFO_1 info, out int parmError);
        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)] private static extern int NetLocalGroupDel(string server, string group);
        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)] private static extern int NetLocalGroupAddMembers(string server, string group, int level, ref LOCALGROUP_MEMBERS_INFO_0 members, int count);
        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)] private static extern int NetLocalGroupDelMembers(string server, string group, int level, ref LOCALGROUP_MEMBERS_INFO_0 members, int count);
        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)] private static extern int NetLocalGroupGetMembers(string server, string group, int level, out IntPtr buf, int prefMaxLen, out int read, out int total, IntPtr resume);
        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)] private static extern int NetLocalGroupGetInfo(string server, string group, int level, out IntPtr buf);
        [DllImport("netapi32.dll")] private static extern int NetApiBufferFree(IntPtr buf);
        [DllImport("userenv.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool DeleteProfile(string sid, string profilePath, string computer);

        /// <summary>A local account as the NetAPI reports it.</summary>
        internal sealed class UserInfo { public string Name, FullName, Comment; public int Flags; public DateTime? Expires, LastLogon; }

        private static Exception Error(string what, int rc)
        {
            string why;
            switch (rc)
            {
                case 5: why = "access denied (run the manager as administrator)"; break;
                case 2224: why = "the account exists already"; break;
                case 2221: why = "the account was not found"; break;
                case 2245: why = "the password does not meet the password policy of this computer"; break;
                case 2220: why = "the group was not found"; break;
                case 1379: why = "the group exists already"; break;
                case 1387: why = "the account was not found"; break;
                default: why = "error " + rc; break;
            }
            return new ConfigException(what + ": " + why + ".");
        }

        public static void CreateUser(string name, string password, string comment, int flags)
        {
            var info = new Accounts.USER_INFO_1 { Name = name, Password = password, Priv = 1 /*USER_PRIV_USER*/, Comment = comment, Flags = UF_SCRIPT | flags };
            int parm; int rc = NetUserAdd(null, 1, ref info, out parm);
            if (rc != 0) throw Error("The account " + name + " could not be created", rc);
        }

        public static UserInfo GetUser(string name)
        {
            IntPtr buf;
            if (NetUserGetInfo(null, name, 2, out buf) != 0) return null;
            try
            {
                var u = (USER_INFO_2)Marshal.PtrToStructure(buf, typeof(USER_INFO_2));
                var epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
                return new UserInfo
                {
                    Name = u.Name, FullName = u.FullName, Comment = u.Comment, Flags = (int)u.Flags,
                    Expires = u.AcctExpires == TIMEQ_FOREVER ? (DateTime?)null : epoch.AddSeconds(u.AcctExpires).ToLocalTime(),
                    LastLogon = u.LastLogon == 0 ? (DateTime?)null : epoch.AddSeconds(u.LastLogon).ToLocalTime(),
                };
            }
            finally { NetApiBufferFree(buf); }
        }

        public static void SetPassword(string name, string password)
        {
            var i = new USER_INFO_1003 { Password = password }; int parm;
            int rc = NetUserSetInfo(null, name, 1003, ref i, out parm);
            if (rc != 0) throw Error("The password of " + name + " could not be set", rc);
        }

        public static void SetComment(string name, string comment)
        {
            var i = new USER_INFO_1007 { Comment = comment }; int parm;
            int rc = NetUserSetInfo(null, name, 1007, ref i, out parm);
            if (rc != 0) throw Error("The description of " + name + " could not be set", rc);
        }

        public static void SetFullName(string name, string fullName)
        {
            var i = new USER_INFO_1011 { FullName = fullName }; int parm;
            int rc = NetUserSetInfo(null, name, 1011, ref i, out parm);
            if (rc != 0) throw Error("The full name of " + name + " could not be set", rc);
        }

        public static void SetFlags(string name, Func<int, int> change)
        {
            var u = GetUser(name);
            if (u == null) throw new ConfigException("The account " + name + " was not found.");
            var i = new USER_INFO_1008 { Flags = (uint)(change(u.Flags) | UF_SCRIPT) }; int parm;
            int rc = NetUserSetInfo(null, name, 1008, ref i, out parm);
            if (rc != 0) throw Error("The settings of " + name + " could not be changed", rc);
        }

        /// <summary>The account can log on until the end of the given day (local time); null: no expiry.</summary>
        public static void SetExpiry(string name, DateTime? lastDay)
        {
            var i = new USER_INFO_1017 { AcctExpires = ExpiryValue(lastDay) }; int parm;
            int rc = NetUserSetInfo(null, name, 1017, ref i, out parm);
            if (rc != 0) throw Error("The expiry date of " + name + " could not be set", rc);
        }

        /// <summary>The latest last day every time zone can store: the NetAPI counts seconds since 1970 in 32 bits, until 2106-02-07 06:28 UTC.</summary>
        public static readonly DateTime MaxLastDay = new DateTime(2106, 2, 5);

        /// <summary>
        /// The NetAPI expiry of an account that can log on until the end of lastDay (local time): seconds since 1970 (UTC), or
        /// TIMEQ_FOREVER for null. A day it cannot store is refused (an unchecked cast would wrap it to a date long past).
        /// </summary>
        internal static uint ExpiryValue(DateTime? lastDay)
        {
            if (lastDay == null) return TIMEQ_FOREVER;
            var day = lastDay.Value.Date;
            double secs = day.Year > 2106 ? double.MaxValue : (day.AddDays(1).ToUniversalTime() - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds;
            if (secs >= TIMEQ_FOREVER) throw new ConfigException("The last day to log in can be " + MaxLastDay.ToString("yyyy-MM-dd") + " at the latest. Untick the date for an account that does not expire.");
            return (uint)Math.Max(1, secs);
        }

        /// <summary>The last day an account set with SetExpiry may log on: the day before the moment it expires.</summary>
        public static DateTime? LastDay(DateTime? expires) { return expires == null ? (DateTime?)null : expires.Value.AddSeconds(-1).Date; }

        /// <summary>Whether this computer is a domain controller: its account database is the domain's, so it has no local accounts.</summary>
        public static bool IsDomainController()
        {
            try { using (var k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\ProductOptions")) return IsDcProductType(k == null ? null : k.GetValue("ProductType") as string); }
            catch { return false; }
        }
        internal static bool IsDcProductType(string productType) { return string.Equals(productType, "LanmanNT", StringComparison.OrdinalIgnoreCase); }

        public static void CreateGroup(string name, string comment)
        {
            var i = new LOCALGROUP_INFO_1 { Name = name, Comment = comment }; int parm;
            int rc = NetLocalGroupAdd(null, 1, ref i, out parm);
            if (rc != 0 && rc != 1379 /*ERROR_ALIAS_EXISTS*/) throw Error("The group " + name + " could not be created", rc);
        }

        public static string DeleteGroup(string name) { int rc = NetLocalGroupDel(null, name); return rc == 0 || rc == 2220 || rc == 1376 ? null : "NetLocalGroupDel error " + rc; }

        private static int WithSid(SecurityIdentifier sid, Func<LOCALGROUP_MEMBERS_INFO_0, int> call)
        {
            var bytes = new byte[sid.BinaryLength]; sid.GetBinaryForm(bytes, 0);
            var p = Marshal.AllocHGlobal(bytes.Length);
            try { Marshal.Copy(bytes, 0, p, bytes.Length); return call(new LOCALGROUP_MEMBERS_INFO_0 { Sid = p }); }
            finally { Marshal.FreeHGlobal(p); }
        }

        public static void AddToGroup(string group, SecurityIdentifier sid)
        {
            int rc = WithSid(sid, m => NetLocalGroupAddMembers(null, group, 0, ref m, 1));
            if (rc != 0 && rc != 1378 /*ERROR_MEMBER_IN_ALIAS*/) throw Error("The account could not be added to " + group, rc);
        }

        public static void RemoveFromGroup(string group, SecurityIdentifier sid)
        {
            int rc = WithSid(sid, m => NetLocalGroupDelMembers(null, group, 0, ref m, 1));
            if (rc != 0 && rc != 1377 /*ERROR_MEMBER_NOT_IN_ALIAS*/) throw Error("The account could not be removed from " + group, rc);
        }

        /// <summary>Whether a local group of that name exists: the local account database only, where AddToGroup looks (a name lookup also finds domain groups and well-known names).</summary>
        public static bool GroupExists(string name)
        {
            IntPtr buf;
            int rc = NetLocalGroupGetInfo(null, name, 0, out buf);
            if (rc == 0) NetApiBufferFree(buf);
            return rc == 0;
        }

        /// <summary>The local user accounts in a local group (names without the computer name); empty when the group does not exist, or cannot be read.</summary>
        public static List<string> GroupMembers(string group) { return Members(group, false); }

        /// <summary>As GroupMembers, but a group that cannot be read (for a reason other than that it does not exist) is an error.</summary>
        public static List<string> GroupMembersStrict(string group) { return Members(group, true); }

        /// <summary>Why the members of a group could not be read, from the NetAPI's return code; null when they were, or when the group does not exist.</summary>
        internal static Exception MembersError(string group, int rc)
        {
            return rc == 0 || rc == 2220 /*NERR_GroupNotFound*/ || rc == 1376 /*ERROR_NO_SUCH_ALIAS*/ ? null : Error("The members of " + group + " could not be read", rc);
        }

        private static List<string> Members(string group, bool strict)
        {
            var l = new List<string>(); IntPtr buf; int read, total;
            int rc = NetLocalGroupGetMembers(null, group, 2, out buf, -1, out read, out total, IntPtr.Zero);
            if (rc != 0)
            {
                var e = MembersError(group, rc);
                if (strict && e != null) throw e;
                return l;
            }
            try
            {
                int size = Marshal.SizeOf(typeof(LOCALGROUP_MEMBERS_INFO_2));
                for (int i = 0; i < read; i++)
                {
                    var m = (LOCALGROUP_MEMBERS_INFO_2)Marshal.PtrToStructure(new IntPtr(buf.ToInt64() + (long)i * size), typeof(LOCALGROUP_MEMBERS_INFO_2));
                    if (m.SidUsage != 1 /*SidTypeUser*/ || m.DomainAndName == null) continue;
                    int slash = m.DomainAndName.IndexOf('\\');
                    if (slash > 0 && !string.Equals(m.DomainAndName.Substring(0, slash), Environment.MachineName, StringComparison.OrdinalIgnoreCase)) continue; // domain accounts are not partners
                    l.Add(slash > 0 ? m.DomainAndName.Substring(slash + 1) : m.DomainAndName);
                }
            }
            finally { NetApiBufferFree(buf); }
            return l;
        }

        /// <summary>
        /// Deletes an account and its profile. sshd loads the profile at login and never unloads it (win32_usertoken_utils.c),
        /// so Windows keeps it loaded, and undeletable, until the next restart: then a one-time startup task deletes it.
        /// Returns what could not be done, or null; note says what happened to the profile.
        /// </summary>
        public static string DeleteUser(string name, SecurityIdentifier sid, out string note)
        {
            note = null;
            var problems = new List<string>();
            var profile = sid == null ? null : Accounts.ProfileDir(sid);
            // The account first: one that cannot be deleted keeps its profile. DeleteProfile works with the SID of a deleted account.
            int rc = NetUserDel(null, name);
            if (rc != 0 && rc != 2221 /*NERR_UserNotFound*/) return "NetUserDel error " + rc;
            bool profileGone = profile == null || DeleteProfile(sid.Value, null, null) || Accounts.ProfileDir(sid) == null;
            if (!profileGone)
            {
                try
                {
                    var task = SystemTasks.ScheduleProfileRemoval(sid, name);
                    note = "Windows keeps its profile " + profile + " loaded (sshd does not unload profiles), so the one-time task \"" + task + "\" deletes it at the next restart";
                }
                catch (Exception ex) { problems.Add("the profile " + profile + " is still loaded and its removal could not be scheduled: " + ex.Message); }
            }
            else if (profile != null) note = "its profile " + profile + " is deleted";
            return problems.Count == 0 ? null : string.Join("; ", problems);
        }

        public static void DeleteUser(string name) { string note; var r = DeleteUser(name, Acl.SidOfAccount(name), out note); if (r != null) throw new Exception(r); }

        /// <summary>Hides an account from the Windows sign-in screen (Winlogon SpecialAccounts), or shows it again.</summary>
        public static void HideFromSignIn(string name, bool hide)
        {
            const string key = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList";
            if (hide) using (var k = Registry.LocalMachine.CreateSubKey(key)) k.SetValue(name, 0, RegistryValueKind.DWord);
            else using (var k = Registry.LocalMachine.OpenSubKey(key, true)) { if (k != null && k.GetValue(name) != null) k.DeleteValue(name, false); }
        }
    }
}

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
            foreach (var n in g.All) if (Acl.SidOfAccount(n) == null) st.MissingGroups.Add(n);
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
            AuthConfig.Apply(cand, AuthConfig.Read(cand).Global, authRules);
            string err;
            var allowGroups = cand.GetCombinedArgs("AllowGroups", out err);
            if (allowGroups != null && allowGroups.Count > 0)
            {
                foreach (var n in new[] { g.Full, g.ReadOnly }.Select(PartnerGroups.Sshd)) if (!allowGroups.Contains(n, StringComparer.OrdinalIgnoreCase)) allowGroups.Add(n);
                cand.Set("AllowGroups", SshdArgs.Join(allowGroups));
            }
        }

        /// <summary>Creates the partner groups that do not exist yet. Returns the names created.</summary>
        public static List<string> CreateGroups(PartnerGroups g)
        {
            var made = new List<string>();
            var comments = new Dictionary<string, string>
            {
                { g.Full, "SFTP partners of OpenSSH Server PN: file exchange only, each in a folder of its own" },
                { g.ReadOnly, "SFTP partners of OpenSSH Server PN who may only download" },
                { g.KeyOnly, "SFTP partners of OpenSSH Server PN who log in with a public key only" },
            };
            foreach (var n in g.All)
            {
                if (Acl.SidOfAccount(n) != null) continue;
                LocalAccounts.CreateGroup(n, comments[n]);
                made.Add(n);
            }
            return made;
        }
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
            if (Acl.SidOfAccount(name) != null) return "An account or group called " + name + " exists already on this computer.";
            return null;
        }

        /// <summary>The partner's folder: the root and the account name as sshd writes it (%u).</summary>
        public static string FolderOf(string root, string name) { return Path.Combine(root, Accounts.AsciiLower(name)); }
        public static string KeysFileOf(PartnerGroups g, string name) { return Path.Combine(g.KeysDir, Accounts.AsciiLower(name)); }

        public static List<PartnerAccount> List(PartnerGroups g)
        {
            var full = LocalAccounts.GroupMembers(g.Full); var ro = LocalAccounts.GroupMembers(g.ReadOnly); var keyOnly = new HashSet<string>(LocalAccounts.GroupMembers(g.KeyOnly), StringComparer.OrdinalIgnoreCase);
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

        /// <summary>
        /// Creates a partner: the local account (password never expires, the partner cannot change it: over SFTP it could not
        /// anyway; hidden from the sign-in screen), its groups, and its folder with access for it alone. Returns the generated
        /// password, which is not stored anywhere. When a step fails, the account is removed again.
        /// </summary>
        public static string Create(PartnerGroups g, string root, string name, string fullName, string company, bool readOnly, bool keyOnly, DateTime? expires)
        {
            var e = NameError(name);
            if (e != null) throw new ConfigException(e);
            if ((fullName ?? "").Any(char.IsControl) || (company ?? "").Any(char.IsControl) || (fullName ?? "").Length > 100 || (company ?? "").Length > 100) throw new ConfigException("The name and the company are one line each, at most 100 characters.");
            var password = NewPassword();
            LocalAccounts.CreateUser(name, password, company ?? "", LocalAccounts.UF_DONT_EXPIRE_PASSWD | LocalAccounts.UF_PASSWD_CANT_CHANGE);
            try
            {
                if (!string.IsNullOrEmpty(fullName)) LocalAccounts.SetFullName(name, fullName);
                LocalAccounts.SetExpiry(name, expires);
                var sid = Acl.SidOfAccount(name);
                if (sid == null) throw new Exception("the new account " + name + " has no SID");
                LocalAccounts.AddToGroup(readOnly ? g.ReadOnly : g.Full, sid);
                if (keyOnly) LocalAccounts.AddToGroup(g.KeyOnly, sid);
                LocalAccounts.HideFromSignIn(name, true);
                SftpConfig.PrepareFolder(FolderOf(root, name), sid, readOnly);
                Log.Info("SFTP partner created: " + name + (readOnly ? ", download only" : "") + (keyOnly ? ", key only" : "") + (expires != null ? ", expires " + expires.Value.ToString("yyyy-MM-dd") : ""));
                return password;
            }
            catch
            {
                try { LocalAccounts.DeleteUser(name); } catch (Exception ex) { Log.Error("Removing the half-made partner account " + name, ex, false); }
                try { LocalAccounts.HideFromSignIn(name, false); } catch { }
                throw;
            }
        }

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

        /// <summary>Ends the partner's open SSH sessions (a disabled or deleted partner would keep them otherwise). Returns how many.</summary>
        public static int Disconnect(string name, int port)
        {
            var me = Accounts.AsciiLower(name); int n = 0;
            foreach (var s in Sessions.List(port))
            {
                var user = Accounts.AsciiLower(s.User ?? ""); var bare = user.Contains("\\") ? user.Substring(user.IndexOf('\\') + 1) : user;
                if (bare != me) continue;
                try { Sessions.Disconnect(s.Pid); n++; } catch (Exception ex) { Log.Error("Disconnecting " + name + " (PID " + s.Pid + ")", ex, false); }
            }
            return n;
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
            try { var k = KeysFileOf(g, p.Name); if (File.Exists(k)) File.Delete(k); } catch (Exception ex) { problems.Add("keys file: " + ex.Message); }
            if (deleteFolder)
            {
                var folder = FolderOf(root, p.Name);
                try { if (Directory.Exists(folder)) Directory.Delete(folder, true); } catch (Exception ex) { problems.Add("folder " + folder + ": " + ex.Message); }
            }
            Log.Info("SFTP partner deleted: " + p.Name + (deleteFolder ? ", with its folder" : ", its folder kept"));
            return problems.Count == 0 ? null : string.Join("; ", problems);
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
            uint value = TIMEQ_FOREVER;
            if (lastDay != null)
            {
                var end = lastDay.Value.Date.AddDays(1).ToUniversalTime();
                value = (uint)Math.Max(1, (end - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds);
            }
            var i = new USER_INFO_1017 { AcctExpires = value }; int parm;
            int rc = NetUserSetInfo(null, name, 1017, ref i, out parm);
            if (rc != 0) throw Error("The expiry date of " + name + " could not be set", rc);
        }

        /// <summary>The last day an account set with SetExpiry may log on: the day before the moment it expires.</summary>
        public static DateTime? LastDay(DateTime? expires) { return expires == null ? (DateTime?)null : expires.Value.AddSeconds(-1).Date; }

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

        /// <summary>The local user accounts in a local group (names without the computer name); empty when the group does not exist.</summary>
        public static List<string> GroupMembers(string group)
        {
            var l = new List<string>(); IntPtr buf; int read, total;
            if (NetLocalGroupGetMembers(null, group, 2, out buf, -1, out read, out total, IntPtr.Zero) != 0) return l;
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
            bool profileGone = profile == null || DeleteProfile(sid.Value, null, null) || Accounts.ProfileDir(sid) == null;
            int rc = NetUserDel(null, name);
            if (rc != 0 && rc != 2221 /*NERR_UserNotFound*/) problems.Add("NetUserDel error " + rc);
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

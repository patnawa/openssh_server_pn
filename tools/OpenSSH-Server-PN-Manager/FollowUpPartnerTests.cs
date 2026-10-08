using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading.Tasks;
using System.Windows.Forms;
using Microsoft.Win32.SafeHandles;

namespace OpenSSHServerPNManager
{
    /// <summary>Regressions for SFTP partner accounts (October 2026 follow-up review).</summary>
    internal static class FollowUpPartnerTests
    {
        internal static void Run(Action<string, Func<string>> test, string tmpDir)
        {
            test("partners: an existing folder is refused before any account is made", () =>
            {
                var id = Id();
                var g = Groups(tmpDir, id);
                var root = Path.Combine(tmpDir, "root-" + id); var name = "osmtc" + id;
                var folder = Partners.FolderOf(root, name);
                Directory.CreateDirectory(folder); File.WriteAllText(Path.Combine(folder, "left.txt"), "x");
                try { Partners.Create(g, root, name, "", "", false, false, null); throw new Exception("a partner was created with the existing folder"); }
                catch (PartnerFolderExistsException ex)
                {
                    if (ex.Message.IndexOf("exists already", StringComparison.Ordinal) < 0 || ex.Folder != folder || ex.Details.IndexOf("1 file(s)", StringComparison.Ordinal) < 0 || ex.Details.IndexOf("owner ", StringComparison.Ordinal) < 0)
                        throw new Exception("the refusal does not name the folder, its owner and its files: " + ex.Message);
                }
                if (Acl.SidOfAccount(name) != null) throw new Exception("the account " + name + " was made");
                return null;
            });
            test("partners: a folder that is or holds a link is never offered to a new partner", () =>
            {
                var id = Id();
                var g = Groups(tmpDir, id);
                var root = Path.Combine(tmpDir, "lroot-" + id); var target = Path.Combine(tmpDir, "ltarget-" + id);
                Directory.CreateDirectory(root); Directory.CreateDirectory(target);
                var inside = "osmti" + id; var itself = "osmtj" + id;
                var links = new[] { Path.Combine(Partners.FolderOf(root, inside), "j"), Partners.FolderOf(root, itself) };
                Directory.CreateDirectory(Partners.FolderOf(root, inside));
                try
                {
                    foreach (var l in links) Junction(l, target);
                    foreach (var n in new[] { inside, itself })
                    {
                        foreach (var reuse in new[] { false, true })
                        {
                            try { Partners.Create(g, root, n, "", "", false, false, null, reuse); throw new Exception("accepted"); }
                            catch (PartnerFolderExistsException) { throw new Exception("offered to " + n + " although it is or holds a link"); }
                            catch (ConfigException ex) { if (ex.Message.IndexOf("link", StringComparison.Ordinal) < 0) throw new Exception(n + ": " + ex.Message); }
                        }
                        if (Acl.SidOfAccount(n) != null) throw new Exception("the account " + n + " was made");
                    }
                }
                finally { RemoveLinks(links); }
                return null;
            });
            test("partners: a folder that holds a hard link is never offered nor reset, and the linked file keeps its permissions", () =>
            {
                var id = Id();
                var g = Groups(tmpDir, id); var me = WindowsIdentity.GetCurrent().User;
                var root = Path.Combine(tmpDir, "hroot-" + id); var name = "osmth" + id; var folder = Partners.FolderOf(root, name);
                var outside = Path.Combine(tmpDir, "hout-" + id); var secret = Path.Combine(outside, "ssh_host_ed25519_key");
                Directory.CreateDirectory(Path.Combine(folder, "sub")); Directory.CreateDirectory(outside); File.WriteAllText(secret, "x");
                var fs = File.GetAccessControl(secret); fs.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.WorldSid, null), FileSystemRights.Read, AccessControlType.Allow)); File.SetAccessControl(secret, fs);
                HardLink(Path.Combine(Path.Combine(folder, "sub"), "report.pdf"), secret);
                Func<FileSystemSecurity, string> sddl = s => s.GetSecurityDescriptorSddlForm(AccessControlSections.Owner | AccessControlSections.Access);
                var before = sddl(File.GetAccessControl(secret)); var folderBefore = sddl(Directory.GetAccessControl(folder));
                foreach (var reuse in new[] { false, true })
                {
                    try { Partners.Create(g, root, name, "", "", false, false, null, reuse); throw new Exception("accepted"); }
                    catch (PartnerFolderExistsException) { throw new Exception("a folder that holds a hard link was offered to a new partner"); }
                    catch (ConfigException ex) { if (ex.Message.IndexOf("hard link", StringComparison.Ordinal) < 0) throw new Exception(ex.Message); }
                }
                if (Acl.SidOfAccount(name) != null) throw new Exception("the account " + name + " was made");
                try { SftpConfig.ResetFolder(folder, me, false, me); throw new Exception("a folder that holds a hard link was reset"); }
                catch (ConfigException ex) { if (ex.Message.IndexOf("hard link", StringComparison.Ordinal) < 0) throw new Exception(ex.Message); }
                if (sddl(File.GetAccessControl(secret)) != before) throw new Exception("the permissions of the linked file changed: " + before + " became " + sddl(File.GetAccessControl(secret)));
                if (sddl(Directory.GetAccessControl(folder)) != folderBefore) throw new Exception("the folder was changed before the refusal");
                return null;
            });
            test("partners: a reparse point that only keeps a file's data elsewhere is a file like others, not a link", () =>
            {
                var id = Id();
                var g = Groups(tmpDir, id); var me = WindowsIdentity.GetCurrent().User;
                var root = Path.Combine(tmpDir, "droot-" + id); var name = "osmtd" + id; var folder = Partners.FolderOf(root, name);
                var file = Path.Combine(folder, "report.pdf");
                Directory.CreateDirectory(folder); File.WriteAllText(file, "x");
                var fs = File.GetAccessControl(file); fs.SetAccessRuleProtection(true, true); File.SetAccessControl(file, fs);
                DataReparsePoint(file); // as deduplication, compression or a cloud file would
                if ((File.GetAttributes(file) & FileAttributes.ReparsePoint) == 0) throw new Exception("no reparse point was set");
                if (SftpConfig.LinkKind(file) != null) throw new Exception("taken for " + SftpConfig.LinkKind(file));
                try { Partners.Create(g, root, name, "", "", false, false, null); throw new Exception("accepted"); }
                catch (PartnerFolderExistsException) { }
                catch (ConfigException ex) { throw new Exception("refused as if it held a link: " + ex.Message); }
                SftpConfig.ResetFolder(folder, me, false, me);
                var s = File.GetAccessControl(file);
                if (s.AreAccessRulesProtected || s.GetAccessRules(true, false, typeof(SecurityIdentifier)).Count > 0) throw new Exception("the file was not reset");
                return null;
            });
            test("partners: a link above the partners' folder is reported (its own permissions are not those of where it leads)", () =>
            {
                var id = Id();
                var target = Path.Combine(tmpDir, "rtarget-" + id); var link = Path.Combine(tmpDir, "rlink-" + id);
                Directory.CreateDirectory(Path.Combine(target, "partners"));
                try
                {
                    Junction(link, target);
                    bool canHarden;
                    var above = PartnerSetup.RootProblem(Path.Combine(link, "partners"), out canHarden);
                    if (above == null || above.IndexOf("(above it) is a link", StringComparison.Ordinal) < 0 || canHarden) throw new Exception("a junction above the root: " + (above ?? "no problem") + ", can be hardened: " + canHarden);
                    var itself = PartnerSetup.RootProblem(link, out canHarden);
                    if (itself == null || itself.IndexOf(" is a link", StringComparison.Ordinal) < 0 || itself.IndexOf("(above it)", StringComparison.Ordinal) >= 0 || canHarden) throw new Exception("a junction as the root: " + (itself ?? "no problem"));
                }
                finally { RemoveLinks(new[] { link }); }
                return null;
            });
            test("partners: a new folder is made in one step that fails when it exists", () =>
            {
                var path = Path.Combine(tmpDir, "made-" + Id());
                Directory.CreateDirectory(path); // as another account would, first
                try { SftpConfig.CreateNewFolder(path); }
                catch (IOException ex) { if (ex.Message.IndexOf("exists already", StringComparison.Ordinal) < 0) throw new Exception("refused for another reason: " + ex.Message); return null; }
                throw new Exception("an existing folder was taken as new");
            });
            test("partners: a reused folder inherits only its new permissions, and a link in it stops the reset", () =>
            {
                var me = WindowsIdentity.GetCurrent().User; var everyone = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
                var inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
                var top = Path.Combine(tmpDir, "reuse-" + Id()); var sub = Path.Combine(top, "sub"); var file = Path.Combine(sub, "f.txt");
                Directory.CreateDirectory(sub); File.WriteAllText(file, "x");
                var ds = new DirectorySecurity(); ds.SetAccessRuleProtection(true, false);
                ds.AddAccessRule(new FileSystemAccessRule(me, FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
                ds.AddAccessRule(new FileSystemAccessRule(everyone, FileSystemRights.Modify, inherit, PropagationFlags.None, AccessControlType.Allow));
                Directory.SetAccessControl(sub, ds);
                var fs = File.GetAccessControl(file); fs.AddAccessRule(new FileSystemAccessRule(everyone, FileSystemRights.Read, AccessControlType.Allow)); File.SetAccessControl(file, fs);
                SftpConfig.ResetFolder(top, me, false, me);
                var problem = Partners.FolderProblem(Directory.GetAccessControl(top), me, me);
                if (problem != null) throw new Exception("the folder: " + problem);
                Func<FileSystemSecurity, string> wrong = s => s.AreAccessRulesProtected ? "protected" : s.GetAccessRules(true, false, typeof(SecurityIdentifier)).Count > 0 ? "explicit entries kept" :
                    s.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().Any(r => everyone.Equals(r.IdentityReference)) ? "Everyone kept" : null;
                var bad = wrong(Directory.GetAccessControl(sub)) ?? wrong(File.GetAccessControl(file));
                if (bad != null) throw new Exception("what the folder holds: " + bad);

                var target = Path.Combine(tmpDir, "outside-" + Id()); var deep = Path.Combine(target, "deep");
                Directory.CreateDirectory(deep);
                var own = new DirectorySecurity(); own.SetAccessRuleProtection(true, false); own.AddAccessRule(new FileSystemAccessRule(me, FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
                Directory.SetAccessControl(deep, own);
                var top2 = Path.Combine(tmpDir, "reuse-" + Id()); Directory.CreateDirectory(top2);
                var link = Path.Combine(top2, "j");
                try
                {
                    Junction(link, target);
                    try { SftpConfig.ResetFolder(top2, me, false, me); throw new Exception("a folder with a junction was reset without a word"); }
                    catch (ConfigException ex) { if (ex.Message.IndexOf("link", StringComparison.Ordinal) < 0) throw new Exception(ex.Message); }
                    if (!Directory.GetAccessControl(deep).AreAccessRulesProtected) throw new Exception("the reset went through the junction and changed " + deep);
                }
                finally { RemoveLinks(new[] { link }); }
                return null;
            });
            test("partners: a partner's folder passes only when owned by Administrators, protected and open to the partner alone", () =>
            {
                const string partner = "S-1-5-21-1-2-3-1001";
                var p = new SecurityIdentifier(partner); var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
                if (Partners.FolderProblem(Sd("O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;" + partner + ")"), p, admins) != null) throw new Exception("the folder as made was refused");
                foreach (var sddl in new[] { "O:BAD:AI(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICI;0x1301bf;;;" + partner + ")", "O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;" + partner + ")(A;OICI;0x1200a9;;;AU)", "O:" + partner + "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;" + partner + ")" })
                    if (Partners.FolderProblem(Sd(sddl), p, admins) == null) throw new Exception("accepted " + sddl);
                return null;
            });
            test("partners: RetireKeys moves a partner's keys and its .bak to partner_keys.removed", () =>
            {
                var id = Id();
                var g = Groups(tmpDir, id); var name = "osmtk" + id;
                Directory.CreateDirectory(g.KeysDir); Directory.CreateDirectory(g.KeysDir + ".removed"); // CreatePrivateFolder would need elevation
                var keys = Partners.KeysFileOf(g, name);
                File.WriteAllText(keys, "ssh-ed25519 AAAA old"); File.WriteAllText(keys + ".bak", "ssh-ed25519 AAAA older");
                Partners.RetireKeys(g, name.ToUpperInvariant());
                if (File.Exists(keys) || File.Exists(keys + ".bak")) throw new Exception("keys of the earlier account are still read by sshd");
                var moved = Directory.GetFiles(g.KeysDir + ".removed").Select(Path.GetFileName).OrderBy(x => x, StringComparer.Ordinal).ToList();
                if (moved.Count != 2 || !moved[0].StartsWith(name + ".", StringComparison.Ordinal) || !moved[1].StartsWith(name + ".bak.", StringComparison.Ordinal)) throw new Exception("partner_keys.removed holds " + string.Join(", ", moved));
                return null;
            });
            test("partners: name.bak in partner_keys is the partner's backup only when no account has that name", () =>
            {
                var g = new PartnerGroups { KeysDir = @"C:\ProgramData\ssh\partner_keys" };
                var mine = Partners.KeysFilesOf(g, "Alice", n => false);
                if (mine.Count != 2 || mine[1] != @"C:\ProgramData\ssh\partner_keys\alice.bak") throw new Exception("without such an account: " + string.Join(", ", mine));
                var theirs = Partners.KeysFilesOf(g, "Alice", n => n.Equals("Alice.bak", StringComparison.OrdinalIgnoreCase));
                if (theirs.Count != 1) throw new Exception("the keys of the account alice.bak would be moved or deleted with alice: " + string.Join(", ", theirs));
                return null;
            });
            test("partners: the generated password survives a failed notification setting", () =>
            {
                string error;
                var pw = Partners.CreateKeepingPassword(() => "pw", () => { throw new IOException("locked"); }, out error);
                if (pw != "pw" || error != "locked") throw new Exception("returned " + pw + ", error " + error);
                bool notified = false;
                try { Partners.CreateKeepingPassword(() => { throw new ConfigException("no account"); }, () => notified = true, out error); throw new Exception("a failed creation passed"); }
                catch (ConfigException ex) { if (ex.Message != "no account") throw; }
                if (notified) throw new Exception("notifications were saved for an account that was not made");
                return null;
            });
            test("partners: the root check flags open roots and folders above them, and passes admin-only ones", () =>
            {
                const string drive = "O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;;LC;;;AU)(A;OICIIO;SDGXGWGR;;;AU)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)";
                const string serverDrive = "O:BAD:PAI(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICIIO;GA;;;CO)(A;OICI;0x1200a9;;;BU)(A;CI;LC;;;BU)(A;CIIO;DC;;;BU)";
                const string programData = "O:SYD:PAI(A;OICIIO;GA;;;CO)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;CI;DCLCRPCR;;;BU)";
                const string adminsOnly = "O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
                const string win11Made = "O:BAD:AI(A;OICIID;0x1301bf;;;AU)(A;OICIID;FA;;;BA)(A;OICIID;FA;;;SY)";
                Func<string, string, bool?, string> check = (root, layout, fixable) =>
                {
                    var map = layout.Split('|').Select(x => x.Split(new[] { '=' }, 2)).ToDictionary(x => x[0], x => x[1], StringComparer.OrdinalIgnoreCase);
                    bool canHarden;
                    var problem = PartnerSetup.RootProblem(root, d => { string s; return map.TryGetValue(d, out s) ? Sd(s) : null; }, out canHarden);
                    if ((problem != null) != (fixable != null)) return root + " (" + layout + "): " + (problem ?? "no problem found");
                    if (fixable != null && canHarden != fixable.Value) return root + " (" + layout + "): can be hardened " + canHarden + ", " + problem;
                    return null;
                };
                var fails = new[]
                {
                    check(@"X:\SFTP", @"X:\=" + drive + @"|X:\SFTP=" + win11Made, true), // made in Explorer under C:\
                    check(@"X:\SFTP", @"X:\=" + serverDrive + @"|X:\SFTP=O:BAD:AI(A;CIID;0x4;;;BU)(A;OICIID;FA;;;BA)", true),
                    check(@"X:\SFTP", @"X:\=" + drive + @"|X:\SFTP=O:S-1-5-21-1-2-3-1001D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", true),
                    check(@"X:\SFTP", @"X:\=" + drive + @"|X:\SFTP=" + adminsOnly, null),
                    check(@"X:\SFTP", @"X:\=" + drive + @"|X:\SFTP=O:BAD:PAI(A;OICIIO;GA;;;AU)(A;OICI;FA;;;BA)", null), // for what it holds only
                    check(@"X:\SFTP", @"X:\=" + serverDrive, null), // made by the setup
                    check(@"X:\Data\SFTP", @"X:\=" + drive + @"|X:\Data=" + win11Made + @"|X:\Data\SFTP=" + adminsOnly, false), // the folder above can be renamed
                    check(@"X:\Data\SFTP", @"X:\=" + drive + @"|X:\Data=O:BAD:PAI(A;;0x40;;;BU)(A;OICI;FA;;;BA)|X:\Data\SFTP=" + adminsOnly, false), // what it holds can be deleted
                    check(@"X:\Data\SFTP", @"X:\=" + drive + @"|X:\Data=O:S-1-5-21-1-2-3-1001D:PAI(A;OICI;FA;;;BA)", false),
                    check(@"X:\ProgramData\osm-authtest-1\partners", @"X:\=" + drive + @"|X:\ProgramData=" + programData + @"|X:\ProgramData\osm-authtest-1=" + adminsOnly + @"|X:\ProgramData\osm-authtest-1\partners=" + adminsOnly, null),
                    check(@"X:\", @"X:\=" + drive, false), // a drive root is never hardened
                    // A Windows 10/11 data drive: Authenticated Users have Modify (DELETE included) on its root, which cannot be renamed.
                    check(@"X:\SFTP", @"X:\=O:BAD:PAI(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;0x1301bf;;;AU)(A;OICI;0x1200a9;;;BU)|X:\SFTP=" + adminsOnly, null),
                };
                var f = fails.Where(x => x != null).ToList();
                if (f.Count > 0) throw new Exception(string.Join("\n", f));
                // The real folders: the temporary folder reads without the "not checked" answer an exception gives.
                bool any; var real = PartnerSetup.RootProblem(tmpDir, out any);
                if (real != null && real.Contains("were not checked")) throw new Exception(real);
                return null;
            });
            test("partners: a domain controller is refused (its accounts are domain accounts)", () =>
            {
                if (Partners.HostError(false) != null || Partners.HostError(true) == null || Partners.HostError(true).IndexOf("domain controller", StringComparison.Ordinal) < 0) throw new Exception("HostError");
                if (!LocalAccounts.IsDcProductType("LanmanNT") || LocalAccounts.IsDcProductType("ServerNT") || LocalAccounts.IsDcProductType("WinNT") || LocalAccounts.IsDcProductType(null)) throw new Exception("ProductType");
                return null;
            });
            test("partners: a rule above the partner rules that covers partners is reported", () =>
            {
                var g = new PartnerGroups { KeysDir = @"C:\ProgramData\ssh\partner_keys" };
                var users = BareName(WellKnownSidType.BuiltinUsersSid); var admins = BareName(WellKnownSidType.BuiltinAdministratorsSid);
                Func<SshdConfig> setUp = () => { var c = Config(); PartnerSetup.Apply(c, g, @"Q:\Partners-" + Id()); return c; };
                Func<SshdConfig, string, bool> reported = (c, kind) => PartnerSetup.Check(c, g).Problems.Any(p => p.StartsWith("the " + kind + " rule for group " + users + " comes before", StringComparison.Ordinal));
                var c1 = setUp();
                if (reported(c1, "SFTP") || reported(c1, "login-method")) throw new Exception("reported after a plain setup");
                var sftp = SftpConfig.Read(c1).Rules; sftp.Insert(0, new SftpRule { IsGroup = true, Name = users, Folder = null }); SftpConfig.Apply(c1, true, true, sftp);
                if (!reported(c1, "SFTP")) throw new Exception("an SFTP rule for " + users + " above the partner rules is not reported: " + string.Join("; ", PartnerSetup.Check(c1, g).Problems));
                if (PartnerSetup.Check(c1, g).Missing.Count != 0) throw new Exception("reported as missing, not as a warning");
                var c2 = setUp();
                var auth = AuthConfig.Read(c2).Rules; auth.Insert(0, new AuthRule { IsGroup = true, Name = users, Methods = new AuthMethods { Password = true, PublicKey = true } }); AuthConfig.Apply(c2, null, auth);
                if (!reported(c2, "login-method")) throw new Exception("a login-method rule for " + users + " above the partner rules is not reported: " + string.Join("; ", PartnerSetup.Check(c2, g).Problems));
                var c3 = setUp();
                auth = AuthConfig.Read(c3).Rules; auth.Insert(0, new AuthRule { IsGroup = true, Name = admins, Methods = new AuthMethods { Password = false, PublicKey = true } });
                auth.Add(new AuthRule { IsGroup = true, Name = users, Methods = new AuthMethods { Password = true, PublicKey = true } }); AuthConfig.Apply(c3, null, auth);
                sftp = SftpConfig.Read(c3).Rules; sftp.Add(new SftpRule { IsGroup = true, Name = users, Folder = null }); SftpConfig.Apply(c3, true, true, sftp);
                var extra = PartnerSetup.Check(c3, g).Problems.Where(p => p.IndexOf("comes before", StringComparison.Ordinal) >= 0).ToList();
                if (extra.Count > 0) throw new Exception("false alarm for the wizard's administrators rule or a rule below the partner rules: " + string.Join("; ", extra));
                return null;
            });
            test("partners: the sessions of a partner, and a session list that is not complete", () =>
            {
                string error;
                var none = Partners.SessionsOf("acme", new[] { new SessionInfo { Pid = 0, User = "error: access denied" } }, out error);
                if (none.Count != 0 || error == null || error.IndexOf("could not be listed", StringComparison.Ordinal) < 0) throw new Exception("a failed list: " + error);
                var list = new[]
                {
                    new SessionInfo { Pid = 10, User = Environment.MachineName.ToUpperInvariant() + "\\Acme" }, new SessionInfo { Pid = 11, User = "acme" },
                    new SessionInfo { Pid = 12, User = "OSMT-OTHER-DOMAIN\\acme" }, new SessionInfo { Pid = 13, User = Environment.MachineName + "\\acmex" },
                    new SessionInfo { Pid = 14, User = "NT AUTHORITY\\SYSTEM" },
                };
                var pids = Partners.SessionsOf("ACME", list, out error);
                if (string.Join(",", pids) != "10,11" || error != null) throw new Exception("found " + string.Join(",", pids) + ", " + error);
                pids = Partners.SessionsOf("acme", list.Concat(new[] { new SessionInfo { Pid = 15, User = "?" } }), out error);
                if (string.Join(",", pids) != "10,11" || error == null) throw new Exception("a session of an unknown account is not reported");
                return null;
            });
            test("partners: the setup makes groups and folders before sshd_config, and restarts a first sshd_config too", () =>
            {
                var calls = new List<string>();
                Func<Task<string>> save = () => { calls.Add("save"); return Task.FromResult<string>(null); };
                Func<string, Task<bool>> restart = b => { calls.Add("restart " + (b ?? "null")); return Task.FromResult(true); };
                try { PartnerSetup.Run(true, () => { throw new IOException("no folder"); }, save, restart).GetAwaiter().GetResult(); throw new Exception("a failed step passed"); }
                catch (IOException) { }
                if (calls.Count != 0) throw new Exception("sshd_config was saved although the folders failed: " + string.Join(", ", calls));
                if (!PartnerSetup.Run(true, () => { calls.Add("create"); return Task.FromResult(0); }, save, restart).GetAwaiter().GetResult() || string.Join(", ", calls) != "create, save, restart null")
                    throw new Exception("steps: " + string.Join(", ", calls));
                calls.Clear();
                if (!PartnerSetup.Run(false, () => { calls.Add("create"); return Task.FromResult(0); }, save, restart).GetAwaiter().GetResult() || string.Join(", ", calls) != "create") throw new Exception("unchanged: " + string.Join(", ", calls));
                return null;
            });
            test("partners: an expired partner keeps its date when edited; a new or changed last day cannot be in the past", () =>
            {
                bool ran = false;
                var p = new PartnerAccount { Name = "osmt-expired", Expires = DateTime.Today.AddDays(-3) };
                using (var d = new PartnerDialog(p, @"C:\SFTP", "", x => ran = true))
                {
                    Show(d);
                    d.TypeForTest("Company", "New Co"); d.OkForTest();
                    if (!ran || d.LastError != null) throw new Exception("saving the company of an expired partner was refused: " + d.LastError);
                    if (d.LastDay != DateTime.Today.AddDays(-4)) throw new Exception("the last day became " + d.LastDay);
                }
                ran = false;
                using (var d = new PartnerDialog(p, @"C:\SFTP", "", x => ran = true))
                {
                    Show(d);
                    d.SetLastDayForTest(DateTime.Today.AddDays(-2)); d.OkForTest();
                    if (ran || d.LastError == null || d.LastError.IndexOf("in the past", StringComparison.Ordinal) < 0) throw new Exception("another past day was accepted");
                }
                using (var d = new PartnerDialog(null, @"C:\SFTP", "", x => ran = true))
                {
                    Show(d);
                    d.TypeForTest("Account name", "osmt-dlg" + Id().Substring(0, 6)); d.TickForTest("Can log in until"); d.SetLastDayForTest(DateTime.Today.AddDays(-1)); d.OkForTest();
                    if (ran || d.LastError == null || d.LastError.IndexOf("in the past", StringComparison.Ordinal) < 0) throw new Exception("a new partner got a past day");
                }
                return null;
            });
            test("partners: a partner group is the local group, not whatever a name lookup finds", () =>
            {
                var users = BareName(WellKnownSidType.BuiltinUsersSid);
                if (LocalAccounts.GroupExists("SYSTEM")) throw new Exception("SYSTEM taken for a local group");
                if (!LocalAccounts.GroupExists(users)) throw new Exception(users + " not found");
                var id = Id();
                var st = PartnerSetup.Check(Config(), new PartnerGroups { Full = "SYSTEM", ReadOnly = "osmt-r-" + id, KeyOnly = "osmt-k-" + id, KeysDir = Path.Combine(tmpDir, "pk-" + id) });
                if (!st.MissingGroups.Contains("SYSTEM")) throw new Exception("a well-known name counts as the partner group: " + string.Join(", ", st.MissingGroups));
                return null;
            });
            test("partners: group members that cannot be read are an error on the Partners tab, a missing group is empty", () =>
            {
                foreach (var rc in new[] { 0, 2220, 1376 }) if (LocalAccounts.MembersError("g", rc) != null) throw new Exception("error for " + rc);
                foreach (var rc in new[] { 5, 1789 }) if (LocalAccounts.MembersError("g", rc) == null) throw new Exception("no error for " + rc);
                if (LocalAccounts.GroupMembersStrict("osmt-missing-" + Id()).Count != 0 || LocalAccounts.GroupMembersStrict(Environment.UserName).Count != 0) throw new Exception("members of a group that does not exist");
                return null;
            });
            test("partners: a last day the account cannot store is refused, not wrapped to a day long past", () =>
            {
                var epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
                if (LocalAccounts.ExpiryValue(null) != 0xFFFFFFFF) throw new Exception("no expiry");
                foreach (var day in new[] { DateTime.Today.AddDays(30), LocalAccounts.MaxLastDay })
                {
                    var back = LocalAccounts.LastDay(epoch.AddSeconds(LocalAccounts.ExpiryValue(day)).ToLocalTime());
                    if (back != day) throw new Exception(day.ToString("yyyy-MM-dd") + " came back as " + back);
                }
                foreach (var day in new[] { new DateTime(2106, 2, 8), new DateTime(2150, 1, 1), new DateTime(9998, 12, 31) })
                {
                    try { var v = LocalAccounts.ExpiryValue(day); throw new Exception(day.ToString("yyyy-MM-dd") + " stored as " + epoch.AddSeconds(v).ToString("yyyy-MM-dd")); }
                    catch (ConfigException) { }
                }
                return null;
            });
        }

        private static string Id() { return Guid.NewGuid().ToString("N").Substring(0, 8); }

        /// <summary>Partner groups that do not exist: a step that should not run fails at AddToGroup and is rolled back.</summary>
        private static PartnerGroups Groups(string tmpDir, string id)
        {
            return new PartnerGroups { Full = "osmt-f-" + id, ReadOnly = "osmt-r-" + id, KeyOnly = "osmt-k-" + id, KeysDir = Path.Combine(tmpDir, "pk-" + id) };
        }

        private static DirectorySecurity Sd(string sddl) { var ds = new DirectorySecurity(); ds.SetSecurityDescriptorSddlForm(sddl); return ds; }

        private static string BareName(WellKnownSidType type)
        {
            var n = new SecurityIdentifier(type, null).Translate(typeof(NTAccount)).Value;
            return Accounts.AsciiLower(n.Substring(n.IndexOf('\\') + 1));
        }

        private static SshdConfig Config()
        {
            return new SshdConfig { Lines = new List<string> { "#Port 22", "AuthorizedKeysFile\t.ssh/authorized_keys", "", "# override default of no subsystems", "Subsystem\tsftp\tsftp-server.exe", "", "Match Group administrators", "       AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys" } };
        }

        private static void Junction(string link, string target)
        {
            var r = Proc.Run(Path.Combine(Environment.SystemDirectory, "cmd.exe"), "/c mklink /J \"" + link + "\" \"" + target + "\"");
            if (!r.Ok || !Directory.Exists(link)) throw new Exception("could not make the junction " + link + ": " + r.Output);
        }

        private static void HardLink(string link, string target)
        {
            var r = Proc.Run(Path.Combine(Environment.SystemDirectory, "cmd.exe"), "/c mklink /H \"" + link + "\" \"" + target + "\"");
            if (!r.Ok || !File.Exists(link)) throw new Exception("could not make the hard link " + link + ": " + r.Output);
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern SafeFileHandle CreateFileW(string path, int access, int share, IntPtr sa, int disposition, int flags, IntPtr template);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool DeviceIoControl(SafeFileHandle h, int code, byte[] input, int inputSize, IntPtr output, int outputSize, out int returned, IntPtr overlapped);

        /// <summary>A reparse point of another vendor on a file, whose tag does not name another file (no name-surrogate bit).</summary>
        private static void DataReparsePoint(string file)
        {
            using (var h = CreateFileW(file, 0x40000000 /*GENERIC_WRITE*/ | 0x100 | 0x80, 7, IntPtr.Zero, 3, 0x00200000 | 0x02000000, IntPtr.Zero))
            {
                if (h.IsInvalid) throw new Exception("could not open " + file + ": error " + Marshal.GetLastWin32Error());
                var buf = new byte[24 + 4]; // REPARSE_GUID_DATA_BUFFER: tag, data length, reserved, GUID, data
                BitConverter.GetBytes(0x00000123).CopyTo(buf, 0); BitConverter.GetBytes((ushort)4).CopyTo(buf, 4); Guid.NewGuid().ToByteArray().CopyTo(buf, 8);
                int returned;
                if (!DeviceIoControl(h, 0x000900A4 /*FSCTL_SET_REPARSE_POINT*/, buf, buf.Length, IntPtr.Zero, 0, out returned, IntPtr.Zero)) throw new Exception("could not set a reparse point on " + file + ": error " + Marshal.GetLastWin32Error());
            }
        }

        /// <summary>Removes junctions themselves: Directory.Delete(dir, true) of the .NET Framework stops at the folder that holds one.</summary>
        private static void RemoveLinks(IEnumerable<string> links)
        {
            foreach (var l in links) try { if (Directory.Exists(l)) Directory.Delete(l); } catch { }
        }

        private static void Show(Form d)
        {
            d.StartPosition = FormStartPosition.Manual; d.Location = new Point(-20000, -20000); d.ShowInTaskbar = false; d.Show(); Application.DoEvents();
        }
    }
}

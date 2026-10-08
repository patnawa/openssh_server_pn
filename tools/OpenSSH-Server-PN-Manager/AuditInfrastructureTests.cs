using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace OpenSSHServerPNManager
{
    internal static class AuditInfrastructureTests
    {
        internal static void Run(Action<string, Func<string>> test, string tmpDir)
        {
            test("listeners: resolved addresses override global ports and retain every family", () =>
            {
                var state = ServerState.FromEffectiveOutput(new RunResult { StdOut = "port 22\nport 2222\nlistenaddress 127.0.0.1:2022\nlistenaddress [::]:3022\n" });
                if (!state.Verified || state.FirewallPorts != "2022,3022") throw new Exception(state.FirewallPorts);
                state.ListeningPorts = new[] { 22, 2022 };
                if (state.FirewallPorts != "22,2022,3022") throw new Exception("running and configured listeners were not combined");
                return null;
            });
            test("listeners: incomplete discovery never guesses port 22", () =>
            {
                foreach (var r in new[] { new RunResult { ExitCode = 1 }, new RunResult(), new RunResult { StdOut = "listenaddress [::]\n" }, new RunResult { StdOut = "port 65536\n" } })
                    if (ServerState.FromEffectiveOutput(r).Verified) throw new Exception("invalid discovery was accepted");
                var multi = ServerState.FromEffectiveOutput(new RunResult { StdOut = "port 22\nport 2222\n" });
                if (multi.FirewallPorts != "22,2222") throw new Exception("multiple ports were collapsed");
                return null;
            });
            test("listeners: service executable and runtime configuration overrides must be verified", () =>
            {
                const string executable = @"C:\Program Files\OpenSSH\sshd.exe", config = @"C:\ProgramData\ssh\sshd_config";
                var prefix = Proc.Quote(executable);
                foreach (var args in new[] { "", " -D -e", " -f " + Proc.Quote(config), " -f" + config, " -E C:\\logs\\sshd.log" })
                    if (ServerState.ServiceDefinitionError(prefix + args, executable, config) != null) throw new Exception("Valid service definition rejected: " + args);
                foreach (var args in new[] { " -f C:\\Custom\\sshd_config", " -f relative.conf", " -p 2222", " -o Port=2222", " -6", " -f", " -E" })
                    if (ServerState.ServiceDefinitionError(prefix + args, executable, config) == null) throw new Exception("Unverified runtime override accepted: " + args);
                if (ServerState.ServiceDefinitionError(@"C:\Other\sshd.exe", executable, config) == null || ServerState.ServiceDefinitionError(null, executable, config) == null)
                    throw new Exception("Unknown service executable accepted");
                return null;
            });
            test("configuration: failed atomic replacement preserves original bytes", () =>
            {
                var p = Path.Combine(tmpDir, "atomic-failure"); File.WriteAllText(p, "original");
                try { ConfigurationTransaction.AtomicWrite(p, "replacement", (a, b) => { throw new IOException("simulated unsupported atomic replace"); }); throw new Exception("replacement failure was ignored"); }
                catch (IOException) { }
                if (File.ReadAllText(p) != "original" || Directory.GetFiles(tmpDir, "atomic-failure.new-*").Length != 0) throw new Exception("original truncated or temporary file leaked");
                return null;
            });
            test("recovery: trusted storage checks ownership, protected ACLs and replaceable ancestors", () =>
            {
                var security = new System.Security.AccessControl.FileSecurity();
                var admins = new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid, null);
                var user = new System.Security.Principal.SecurityIdentifier("S-1-5-21-111-222-333-1001");
                security.SetAccessRuleProtection(true, false);
                security.SetOwner(user);
                security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(admins, System.Security.AccessControl.FileSystemRights.FullControl, System.Security.AccessControl.AccessControlType.Allow));
                if (ConfigurationRecovery.TrustedSecurity(security, true)) throw new Exception("Untrusted owner could reclaim the protected DACL");
                security.SetOwner(admins);
                if (!ConfigurationRecovery.TrustedSecurity(security, true)) throw new Exception("Private admin-owned storage rejected");
                security.SetAccessRuleProtection(false, false);
                if (ConfigurationRecovery.TrustedSecurity(security, true)) throw new Exception("Inherited private storage accepted");
                security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(user, System.Security.AccessControl.FileSystemRights.ReadAndExecute, System.Security.AccessControl.AccessControlType.Allow));
                if (!ConfigurationRecovery.TrustedSecurity(security, false)) throw new Exception("Readable but protected ancestor rejected");
                security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(user, System.Security.AccessControl.FileSystemRights.DeleteSubdirectoriesAndFiles, System.Security.AccessControl.AccessControlType.Allow));
                if (ConfigurationRecovery.TrustedSecurity(security, false)) throw new Exception("Untrusted parent can replace protected child");
                return null;
            });
            test("configuration: atomic replacement retains original security descriptor", () =>
            {
                var p = Path.Combine(tmpDir, "atomic-security"); File.WriteAllText(p, "original");
                var sections = System.Security.AccessControl.AccessControlSections.Owner | System.Security.AccessControl.AccessControlSections.Group | System.Security.AccessControl.AccessControlSections.Access;
                var before = File.GetAccessControl(p, sections);
                ConfigurationTransaction.AtomicWrite(p, "replacement");
                var after = File.GetAccessControl(p, sections);
                if (!ConfigurationTransaction.SameFileSecurity(before, after)) throw new Exception("Atomic replacement changed the destination owner or ACL. Before=" + before.GetSecurityDescriptorSddlForm(sections) + "; After=" + after.GetSecurityDescriptorSddlForm(sections));
                bool rejected = false;
                try { ConfigurationTransaction.AtomicBytes(p, Encoding.UTF8.GetBytes("unsafe"), null, temporary => { throw new UnauthorizedAccessException("cannot protect temporary file"); }); }
                catch (IOException) { rejected = true; }
                if (!rejected || File.ReadAllText(p) != "replacement") throw new Exception("Failed temporary-file protection still committed bytes");
                return null;
            });
            test("configuration: atomic replacement preserves nondefault groups and elevated alternate ownership", () =>
            {
                var sections = System.Security.AccessControl.AccessControlSections.Owner | System.Security.AccessControl.AccessControlSections.Group | System.Security.AccessControl.AccessControlSections.Access;
                using (var identity = System.Security.Principal.WindowsIdentity.GetCurrent())
                {
                    var owners = new List<System.Security.Principal.SecurityIdentifier> { identity.User };
                    if (Elevation.IsAdministrator()) owners.Add(new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid, null));
                    foreach (var owner in owners)
                    foreach (bool protect in new[] { false, true })
                    {
                        var p = Path.Combine(tmpDir, "atomic-alternate-" + Guid.NewGuid().ToString("N")); File.WriteAllText(p, "original");
                        var security = File.GetAccessControl(p, sections);
                        security.SetOwner(owner); security.SetGroup(identity.User);
                        security.SetAccessRuleProtection(protect, true); File.SetAccessControl(p, security);
                        var before = File.GetAccessControl(p, sections);
                        ConfigurationTransaction.AtomicWrite(p, "replacement");
                        var after = File.GetAccessControl(p, sections);
                        if (!ConfigurationTransaction.SameFileSecurity(before, after)) throw new Exception("Nondefault file security changed. Before=" + before.GetSecurityDescriptorSddlForm(sections) + "; After=" + after.GetSecurityDescriptorSddlForm(sections));
                    }
                    return Elevation.IsAdministrator() ? "user and Administrators owners, protected and inherited DACLs" : "user owner and nondefault group, protected and inherited DACLs; alternate administrator owner requires elevated CI";
                }
            });
            test("configuration: temporary security failure occurs before any replacement bytes are written", () =>
            {
                var p = Path.Combine(tmpDir, "atomic-protect-before-bytes"); File.WriteAllText(p, "original");
                long observed = -1; bool rejected = false;
                try { ConfigurationTransaction.AtomicBytes(p, Encoding.UTF8.GetBytes("replacement"), null, temporary => { observed = new FileInfo(temporary).Length; throw new UnauthorizedAccessException("security setup failed"); }); }
                catch (IOException) { rejected = true; }
                if (!rejected || observed != 0 || File.ReadAllText(p) != "original") throw new Exception("Replacement bytes existed before temporary security was established: " + observed);
                return null;
            });
            test("configuration: legacy inherited ACEs retain their flags without explicit duplicates", () =>
            {
                var sections = System.Security.AccessControl.AccessControlSections.Owner | System.Security.AccessControl.AccessControlSections.Group | System.Security.AccessControl.AccessControlSections.Access;
                using (var identity = System.Security.Principal.WindowsIdentity.GetCurrent())
                foreach (bool autoInherited in new[] { false, true })
                {
                    var dir = Path.Combine(tmpDir, "legacy-acl-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(dir);
                    string flags = autoInherited ? "AI" : "";
                    SetFixtureDacl(dir, "D:" + (autoInherited ? "PAI" : "") + "(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + identity.User.Value + ")");
                    var p = Path.Combine(dir, "sshd_config"); File.WriteAllText(p, "original");
                    SetFixtureDacl(p, "D:" + flags + "(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;FA;;;" + identity.User.Value + ")");
                    var security = File.GetAccessControl(p, sections);
                    var raw = new System.Security.AccessControl.RawSecurityDescriptor(security.GetSecurityDescriptorBinaryForm(), 0);
                    if (raw.DiscretionaryAcl.Count != 3 || ((raw.ControlFlags & System.Security.AccessControl.ControlFlags.DiscretionaryAclAutoInherited) != 0) != autoInherited ||
                        raw.DiscretionaryAcl.Cast<System.Security.AccessControl.GenericAce>().Any(ace => (ace.AceFlags & System.Security.AccessControl.AceFlags.Inherited) == 0))
                        throw new Exception("The legacy ACL fixture was normalized before the test: " + security.GetSecurityDescriptorSddlForm(sections));
                    string before = security.GetSecurityDescriptorSddlForm(sections);
                    ConfigurationTransaction.AtomicWrite(p, "replacement");
                    string after = File.GetAccessControl(p, sections).GetSecurityDescriptorSddlForm(sections);
                    if (before != after) throw new Exception("Inherited ACEs or control flags changed. Before=" + before + "; After=" + after);
                }
                return null;
            });
            test("configuration: atomic replacement preserves named streams, creation time and attributes", () =>
            {
                var p = Path.Combine(tmpDir, "atomic-metadata"); File.WriteAllText(p, "original contents longer than replacement");
                var metadata = Encoding.UTF8.GetBytes("retained named stream");
                using (var stream = FixtureStream(p + ":pn-metadata", true)) { stream.Write(metadata, 0, metadata.Length); stream.Flush(true); }
                var created = new DateTime(2020, 2, 3, 4, 5, 6, DateTimeKind.Utc); File.SetCreationTimeUtc(p, created);
                var attributes = FileAttributes.Hidden | FileAttributes.Archive | FileAttributes.NotContentIndexed; File.SetAttributes(p, attributes);
                try
                {
                    ConfigurationTransaction.AtomicWrite(p, "new");
                    byte[] actual;
                    using (var stream = FixtureStream(p + ":pn-metadata", false)) using (var memory = new MemoryStream()) { stream.CopyTo(memory); actual = memory.ToArray(); }
                    if (File.ReadAllText(p) != "new" || !actual.SequenceEqual(metadata) || File.GetCreationTimeUtc(p) != created || File.GetAttributes(p) != attributes)
                        throw new Exception("Atomic replacement lost file metadata or left trailing original bytes");
                    File.SetAttributes(p, attributes | FileAttributes.ReadOnly);
                    bool rejected = false;
                    try { ConfigurationTransaction.AtomicWrite(p, "must fail"); } catch (IOException) { rejected = true; }
                    if (!rejected || File.ReadAllText(p) != "new") throw new Exception("Read-only original was replaced");
                }
                finally { File.SetAttributes(p, FileAttributes.Normal); }
                return null;
            });
            test("recovery: another process can restore configuration and firewall after the deadline", () =>
            {
                var f = new Fixture(tmpDir); var host = new Host();
                var first = f.Open(host); first.Arm(f.Backup, new FirewallRule { Name = "test", Enabled = false, Profiles = 3, Ports = "22,2222" }, f.Due);
                if (f.Open(host).Recover(f.Due.AddSeconds(-1))) throw new Exception("restored before deadline");
                if (!f.Open(host).Recover(f.Due.AddSeconds(1))) throw new Exception("not restored by new process instance");
                if (!File.ReadAllBytes(f.Live).SequenceEqual(f.Before) || host.Restarts != 1 || host.Firewall.Ports != "22,2222" || host.Firewall.Enabled) throw new Exception("recovery state mismatch");
                if (f.Open(host).Recover(f.Due.AddHours(1))) throw new Exception("recovery replay was not idempotent");
                return null;
            });
            test("recovery: confirmation is durable and rejects a stale transaction", () =>
            {
                var f = new Fixture(tmpDir); var host = new Host(); var txn = f.Open(host); string id = txn.Arm(f.Backup, null, f.Due);
                try { txn.Confirm("another-id"); throw new Exception("stale confirmation accepted"); } catch (ConfigException) { }
                txn.Confirm(id);
                if (f.Open(host).Recover(f.Due.AddDays(1)) || File.ReadAllText(f.Live) != "new settings") throw new Exception("confirmed settings rolled back");
                return null;
            });
            test("recovery: external edits are not overwritten and restart failures retry", () =>
            {
                var f = new Fixture(tmpDir); var host = new Host { FailRestart = true }; f.Open(host).Arm(f.Backup, null, f.Due);
                File.WriteAllText(f.Live, "external edit");
                try { f.Open(host).Recover(f.Due); throw new Exception("external edit overwritten"); } catch (ConfigChangedException) { }
                if (File.ReadAllText(f.Live) != "external edit") throw new Exception("external edit lost");
                File.WriteAllText(f.Live, "new settings");
                try { f.Open(host).Recover(f.Due); throw new Exception("restart error swallowed"); } catch (IOException) { }
                host.FailRestart = false;
                if (!f.Open(host).Recover(f.Due) || host.Restarts != 2 || !File.ReadAllBytes(f.Live).SequenceEqual(f.Before)) throw new Exception("partially completed recovery did not resume");
                return null;
            });
            test("recovery: missing original config and failed scheduling are explicit", () =>
            {
                var f = new Fixture(tmpDir); var host = new Host { FailSchedule = true }; var txn = f.Open(host);
                try { txn.Arm(null, null, f.Due); throw new Exception("scheduling error ignored"); } catch (IOException) { }
                if (txn.Pending) throw new Exception("failed arming left a live transaction");
                host.FailSchedule = false; txn.Arm(null, null, f.Due); txn.Recover(f.Due);
                if (File.Exists(f.Live)) throw new Exception("original absence was not restored");
                var xml = ConfigurationRecovery.TaskXml("C:\\Program Files\\manager.exe", f.Due);
                if (!xml.Contains("BootTrigger") || !xml.Contains("StartWhenAvailable>true") || !xml.Contains("--recover-configuration")) throw new Exception("recovery cannot survive GUI exit and reboot");
                return null;
            });
            test("recovery: firewall scope survives journal and exact rule reconstruction", () =>
            {
                var rule = new FakeFirewallRule { Name = Firewall.RuleName, Enabled = false, Profiles = 3, LocalPorts = "22,2222", ApplicationName = @"C:\Custom SSH\sshd.exe",
                    RemoteAddresses = "192.0.2.0/24,2001:db8::/32", LocalAddresses = "10.0.0.4", RemotePorts = "1000-65535", ServiceName = "sshd",
                    Interfaces = new object[] { "Ethernet", "Admin VPN" }, InterfaceTypes = "LAN,RemoteAccess", Description = "custom scope", Grouping = "custom group",
                    EdgeTraversal = true, EdgeTraversalOptions = 2, LocalUserOwner = "S-1-5-21-1", LocalUserAuthorizedList = "D:(A;;CC;;;BA)", SecureFlags = 1 };
                var snapshot = Firewall.CaptureRule(rule);
                var f = new Fixture(tmpDir); var host = new Host(); f.Open(host).Arm(f.Backup, snapshot, f.Due); f.Open(host).Recover(f.Due);
                var restored = new FakeFirewallRule(); Firewall.ApplySnapshot(restored, host.Firewall);
                var actual = Firewall.CaptureRule(restored);
                if (actual.Program != snapshot.Program || actual.Ports != snapshot.Ports || actual.Enabled != snapshot.Enabled || actual.Profiles != snapshot.Profiles || actual.Name != snapshot.Name ||
                    actual.Attributes.Count != snapshot.Attributes.Count || snapshot.Attributes.Any(p => !actual.Attributes.ContainsKey(p.Key) || actual.Attributes[p.Key] != p.Value)) throw new Exception("A firewall address, program, service, interface or security scope was lost");
                return null;
            });
            test("recovery: explicit firewall absence and duplicate named rules survive the journal", () =>
            {
                foreach (bool absent in new[] { true, false })
                {
                    var rules = new List<FirewallRule>();
                    if (!absent) { rules.Add(Firewall.CaptureRule(new FakeFirewallRule { Name = Firewall.RuleName })); rules.Add(Firewall.CaptureRule(new FakeFirewallRule { Name = Firewall.RuleName, Direction = 2 })); }
                    var f = new Fixture(tmpDir); var host = new Host();
                    f.Open(host).Arm(f.Backup, new FirewallRule { Name = Firewall.ManagedRuleName, Exists = !absent, RelatedRules = rules }, f.Due); f.Open(host).Recover(f.Due);
                    if (host.Firewall.Exists == absent || host.Firewall.RelatedRules == null || host.Firewall.RelatedRules.Count != rules.Count) throw new Exception("Absence or duplicate rules collapsed");
                    if (!absent && host.Firewall.RelatedRules[1].Attributes["Direction"] != "2") throw new Exception("Outbound same-name rule lost");
                }
                return null;
            });
            test("recovery: firewall restoration preserves rule identity and refuses external scope edits", () =>
            {
                var inbound = new FakeFirewallRule { Name = Firewall.ManagedRuleName, RemoteAddresses = "192.0.2.0/24", LocalPorts = "22" };
                var outbound = new FakeFirewallRule { Name = Firewall.ManagedRuleName, Direction = 2 };
                var original = new FirewallRule { RelatedRules = new List<FirewallRule> { Firewall.CaptureRule(inbound), Firewall.CaptureRule(outbound) } };
                var current = new List<object> { inbound, outbound };
                inbound.LocalPorts = "22,2222"; inbound.Profiles = 1; inbound.Enabled = false;
                Firewall.RestoreRules(current, original, name => { throw new Exception("Existing rules must not be removed"); });
                if (inbound.LocalPorts != "22" || inbound.Profiles != 7 || !inbound.Enabled || outbound.Direction != 2) throw new Exception("Original rule state not restored in place");
                inbound.RemoteAddresses = "203.0.113.0/24";
                try { Firewall.RestoreRules(current, original, name => { throw new Exception("External rule removed"); }); throw new Exception("External scope edit ignored"); } catch (ConfigChangedException) { }
                if (inbound.RemoteAddresses != "203.0.113.0/24") throw new Exception("External scope edit overwritten");
                return null;
            });
            test("recovery: absent original firewall removes only the newly created rule and retries interrupted removal", () =>
            {
                var created = new FakeFirewallRule { Name = Firewall.ManagedRuleName, Description = "Inbound rule for OpenSSH SSH Server (sshd), managed by OpenSSH Server PN Manager", ApplicationName = Ssh.Exe("sshd.exe") };
                var original = new FirewallRule { Exists = false, RelatedRules = new List<FirewallRule>() };
                var current = new List<object> { created };
                try { Firewall.RestoreRules(current, original, name => { throw new IOException("interrupted after rename"); }); throw new Exception("Removal failure swallowed"); } catch (IOException) { }
                Firewall.RestoreRules(current, original, name => { if (name != created.Name || name == Firewall.ManagedRuleName) throw new Exception("Removal used an ambiguous name"); current.Remove(created); });
                if (current.Count != 0) throw new Exception("Interrupted firewall deletion was not retried");
                return null;
            });
            test("configuration: Include snapshots detect content changes and glob membership", () =>
            {
                var dir = Path.Combine(tmpDir, "include-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(dir);
                var child = Path.Combine(dir, "child.conf"); var nested = Path.Combine(dir, "nested.conf");
                File.WriteAllText(child, "Include nested.conf\nPort 22\n"); File.WriteAllText(nested, "PasswordAuthentication yes\n");
                var graph = ConfigurationDependencies.Capture(new[] { "Include child.conf", "Match User someone", "Include future*.conf" }, dir);
                graph.RequireUnchanged();
                File.WriteAllText(nested, "PasswordAuthentication no\n");
                try { graph.RequireUnchanged(); throw new Exception("Nested Include edit ignored"); } catch (ConfigChangedException) { }
                File.WriteAllText(nested, "PasswordAuthentication yes\n"); graph.RequireUnchanged();
                File.WriteAllText(Path.Combine(dir, "future1.conf"), "Port 2222\n");
                try { graph.RequireUnchanged(); throw new Exception("New glob match ignored"); } catch (ConfigChangedException) { }
                return null;
            });
            test("recovery: changed Includes stop rollback without overwriting external work", () =>
            {
                var f = new Fixture(tmpDir); var include = Path.Combine(f.Dir, "included.conf"); File.WriteAllText(include, "Port 22\n");
                var applied = Encoding.UTF8.GetBytes("Include " + SshdArgs.Quote(include) + "\nPort 2222\n");
                File.WriteAllBytes(f.Live, applied);
                var host = new Host(); var txn = f.Open(host);
                txn.Prepare(f.Backup, applied, ConfigurationDependencies.Capture(new[] { "Include " + SshdArgs.Quote(include) }));
                txn.Arm(f.Backup, null, f.Due); File.WriteAllText(include, "Port 3333\n");
                try { f.Open(host).Recover(f.Due); throw new Exception("Changed Include was ignored"); } catch (ConfigChangedException) { }
                if (!File.ReadAllBytes(f.Live).SequenceEqual(applied) || File.ReadAllText(include) != "Port 3333\n" || host.Restarts != 0) throw new Exception("Rollback touched external work");
                try { txn.Confirm(ReadId(f.Dir), f.Due.AddSeconds(-1)); throw new Exception("Changed Include was committed"); } catch (ConfigChangedException) { }
                return null;
            });
            test("recovery: prepared save-only seed does not arm or revert and rejects stale candidate", () =>
            {
                var f = new Fixture(tmpDir); var host = new Host(); var txn = f.Open(host);
                txn.Prepare(f.Backup, Encoding.UTF8.GetBytes("new settings"), ConfigurationDependencies.Capture(new string[0]));
                if (txn.Pending || txn.Recover(f.Due.AddDays(1)) || host.Schedules != 0) throw new Exception("Save-only seed performed recovery");
                File.WriteAllText(f.Live, "external edit after save");
                try { txn.Arm(f.Backup, null, f.Due); throw new Exception("External edit between save and arm was adopted"); } catch (ConfigChangedException) { }
                if (host.Schedules != 0 || File.ReadAllText(f.Live) != "external edit after save") throw new Exception("Stale seed changed state");
                return null;
            });
            test("recovery: scheduling precedes pending and failed reschedule retains the original deadline", () =>
            {
                var f = new Fixture(tmpDir); var host = new Host(); var txn = f.Open(host);
                host.OnSchedule = () => { if (txn.Pending) throw new Exception("Pending published before scheduler succeeded"); };
                var id = txn.Arm(f.Backup, null, f.Due);
                host.OnSchedule = null; host.FailSchedule = true;
                try { txn.SetDeadline(id, f.Due.AddMinutes(10)); throw new Exception("Failed scheduling ignored"); } catch (IOException) { }
                host.FailSchedule = false;
                if (!txn.Recover(f.Due.AddSeconds(1))) throw new Exception("A failed reschedule extended the recovery deadline");
                return null;
            });
            test("recovery: expired confirmation cannot disarm rollback", () =>
            {
                var f = new Fixture(tmpDir); var host = new Host(); var txn = f.Open(host); var id = txn.Arm(f.Backup, null, f.Due);
                try { txn.Confirm(id, f.Due); throw new Exception("Late confirmation accepted"); } catch (ConfigException) { }
                if (!txn.Pending || !txn.Recover(f.Due)) throw new Exception("Late confirmation disabled recovery");
                return null;
            });
            test("recovery: interrupted firewall and restart steps resume without repeating finished work", () =>
            {
                var f = new Fixture(tmpDir); var host = new Host { FailFirewall = true }; var txn = f.Open(host);
                txn.Arm(f.Backup, new FirewallRule { Name = "test", Ports = "22", Profiles = 3 }, f.Due);
                try { txn.Recover(f.Due); throw new Exception("Firewall failure ignored"); } catch (IOException) { }
                if (!File.ReadAllBytes(f.Live).SequenceEqual(f.Before) || host.Restarts != 0) throw new Exception("Recovery advanced past failed firewall step");
                host.FailFirewall = false; host.FailRestart = true;
                try { txn.Recover(f.Due); throw new Exception("Restart failure ignored"); } catch (IOException) { }
                host.FailRestart = false; txn.Recover(f.Due);
                if (host.FirewallAttempts != 2 || host.Restarts != 2) throw new Exception("Completed firewall restoration was repeated");
                return null;
            });
            test("recovery: immutable runner can be reused while executing and corrupt backup fails closed", () =>
            {
                var f = new Fixture(tmpDir); var runner = Path.Combine(f.Dir, "runner.exe"); var bytes = Encoding.UTF8.GetBytes("immutable test runner");
                ConfigurationRecovery.EnsureRunnerFile(runner, bytes);
                using (var held = new FileStream(runner, FileMode.Open, FileAccess.Read, FileShare.Read)) ConfigurationRecovery.EnsureRunnerFile(runner, bytes);
                try { ConfigurationRecovery.EnsureRunnerFile(runner, Encoding.UTF8.GetBytes("different runner")); throw new Exception("Runner replaced unexpectedly"); } catch (ConfigException) { }
                var host = new Host(); var txn = f.Open(host); txn.Arm(f.Backup, null, f.Due); File.WriteAllText(Path.Combine(f.Dir, "previous.config"), "corrupted");
                try { txn.Recover(f.Due); throw new Exception("Corrupt backup accepted"); } catch (ConfigException) { }
                if (host.Restarts != 0 || File.ReadAllText(f.Live) != "new settings") throw new Exception("Corruption caused a mutation");
                return null;
            });
            test("recovery dialog: absolute deadline includes suspended UI and slow checks", () =>
            {
                var now = DateTime.UtcNow; var deadline = now.AddSeconds(20);
                if (KeepSettingsDialog.SecondsLeft(now, deadline) != 20 || KeepSettingsDialog.SecondsLeft(now.AddSeconds(19.5), deadline) != 1 || KeepSettingsDialog.SecondsLeft(now.AddSeconds(25), deadline) != 0)
                    throw new Exception("Countdown depends on number of UI ticks");
                return null;
            });
            test("recovery: asynchronous Keep cannot be overtaken by recovery and callback failure stays armed", () =>
            {
                AsyncUiTest.Wait(async () =>
                {
                    var f = new Fixture(tmpDir); var host = new Host(); var txn = f.Open(host); var id = txn.Arm(f.Backup, null, f.Due);
                    var entered = new System.Threading.Tasks.TaskCompletionSource<bool>();
                    var release = new System.Threading.Tasks.TaskCompletionSource<bool>();
                    var commit = txn.ConfirmAsync(id, async () => { entered.SetResult(true); await release.Task; });
                    await entered.Task;
                    var recovery = System.Threading.Tasks.Task.Run(() => f.Open(host).Recover(f.Due, true));
                    await System.Threading.Tasks.Task.Delay(30);
                    if (recovery.IsCompleted) throw new Exception("Recovery overtook the final firewall update");
                    release.SetResult(true); await commit;
                    if (await recovery || txn.Pending || File.ReadAllText(f.Live) != "new settings") throw new Exception("Confirmed async update was restored");
                    f = new Fixture(tmpDir); txn = f.Open(host); id = txn.Arm(f.Backup, null, f.Due);
                    try { await txn.ConfirmAsync(id, async () => { await System.Threading.Tasks.Task.Delay(1); throw new IOException("final firewall update failed"); }); throw new Exception("Callback failure ignored"); }
                    catch (IOException) { }
                    if (!txn.Pending || !txn.Recover(f.Due)) throw new Exception("Failed finalization disabled recovery");
                });
                return null;
            });
            test("recovery: a killed fixture process is restored by a separate process using the durable journal", () =>
            {
                var f = new Fixture(tmpDir); var worker = Path.Combine(f.Dir, "recovery-fixture.exe");
                const string code = @"using System; using System.IO; using System.Reflection; using System.Threading;
class Fixture { static int Main(string[] args) { try {
 var a=Assembly.LoadFrom(args[0]); var host=Activator.CreateInstance(a.GetType(""OpenSSHServerPNManager.AuditInfrastructureTests+Host""),true);
 var t=a.GetType(""OpenSSHServerPNManager.ConfigurationRecoveryTransaction""); var tx=Activator.CreateInstance(t,new object[]{args[1],Path.Combine(args[1],""sshd_config""),host});
 if(args[2]==""arm"") { t.GetMethod(""Arm"").Invoke(tx,new object[]{Path.Combine(args[1],""sshd_config.bak""),null,DateTime.UtcNow.AddMinutes(5)}); File.WriteAllText(Path.Combine(args[1],""ready""),""ready""); Thread.Sleep(300000); }
 else { var ok=(bool)t.GetMethod(""Recover"").Invoke(tx,new object[]{DateTime.UtcNow.AddDays(1),false}); if(!ok) return 2; }
 return 0; } catch(Exception ex) { Console.Error.WriteLine(ex); return 1; } } }";
                using (var compiler = new Microsoft.CSharp.CSharpCodeProvider())
                {
                    var options = new System.CodeDom.Compiler.CompilerParameters { GenerateExecutable = true, OutputAssembly = worker };
                    var result = compiler.CompileAssemblyFromSource(options, code);
                    if (result.Errors.HasErrors) throw new Exception("Could not compile recovery fixture process");
                }
                var args = Proc.Quote(typeof(ConfigurationRecovery).Assembly.Location) + " " + Proc.Quote(f.Dir) + " ";
                using (var process = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(worker, args + "arm") { UseShellExecute = false, CreateNoWindow = true }))
                {
                    try
                    {
                        var until = DateTime.UtcNow.AddSeconds(5);
                        while (!File.Exists(Path.Combine(f.Dir, "ready")) && DateTime.UtcNow < until && !process.HasExited) System.Threading.Thread.Sleep(10);
                        if (!File.Exists(Path.Combine(f.Dir, "ready"))) throw new Exception("Fixture did not arm its journal");
                    }
                    finally { if (!process.HasExited) process.Kill(); process.WaitForExit(); }
                }
                var recovered = Proc.Run(worker, args + "recover", 15000);
                if (!recovered.Ok || !File.ReadAllBytes(f.Live).SequenceEqual(f.Before)) throw new Exception("Separate recovery process failed: " + recovered.Output);
                return null;
            });
        }

        [System.Runtime.InteropServices.DllImport("advapi32.dll", EntryPoint = "SetFileSecurityW", CharSet = System.Runtime.InteropServices.CharSet.Unicode, SetLastError = true)]
        private static extern bool SetFixtureSecurity(string path, uint information, byte[] descriptor);

        private static void SetFixtureDacl(string path, string sddl)
        {
            if (sddl.StartsWith("D:AI", StringComparison.Ordinal) || sddl.StartsWith("D:PAI", StringComparison.Ordinal))
            {
                if (Directory.Exists(path))
                {
                    var security = new System.Security.AccessControl.DirectorySecurity(); security.SetSecurityDescriptorSddlForm(sddl, System.Security.AccessControl.AccessControlSections.Access);
                    Directory.SetAccessControl(path, security);
                }
                else
                {
                    var security = new System.Security.AccessControl.FileSecurity(); security.SetSecurityDescriptorSddlForm(sddl, System.Security.AccessControl.AccessControlSections.Access);
                    File.SetAccessControl(path, security);
                }
                return;
            }
            var raw = new System.Security.AccessControl.RawSecurityDescriptor(sddl); var bytes = new byte[raw.BinaryLength]; raw.GetBinaryForm(bytes, 0);
            if (!SetFixtureSecurity(path, 4, bytes)) throw new System.ComponentModel.Win32Exception(System.Runtime.InteropServices.Marshal.GetLastWin32Error());
        }

        [System.Runtime.InteropServices.DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = System.Runtime.InteropServices.CharSet.Unicode, SetLastError = true)]
        private static extern Microsoft.Win32.SafeHandles.SafeFileHandle OpenFixtureStream(string path, uint access, uint sharing, IntPtr security, uint disposition, uint attributes, IntPtr template);

        private static FileStream FixtureStream(string path, bool write)
        {
            var handle = OpenFixtureStream(path, write ? 0x40000000u : 0x80000000u, 7, IntPtr.Zero, write ? 2u : 3u, 0x80, IntPtr.Zero);
            if (handle.IsInvalid) { int error = System.Runtime.InteropServices.Marshal.GetLastWin32Error(); handle.Dispose(); throw new System.ComponentModel.Win32Exception(error); }
            try { return new FileStream(handle, write ? FileAccess.Write : FileAccess.Read); } catch { handle.Dispose(); throw; }
        }

        private static string ReadId(string directory)
        { var line = File.ReadAllLines(Path.Combine(directory, "pending.ini")).Single(l => l.StartsWith("id=", StringComparison.Ordinal)); return Encoding.UTF8.GetString(Convert.FromBase64String(line.Substring(3))); }

        private sealed class Fixture
        {
            internal string Dir, Live, Backup;
            internal byte[] Before = new byte[] { 239, 187, 191, 111, 108, 100, 13, 10 };
            internal DateTime Due = DateTime.UtcNow.AddMinutes(5);
            internal Fixture(string root)
            {
                Dir = Path.Combine(root, "recovery-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(Dir);
                Live = Path.Combine(Dir, "sshd_config"); Backup = Live + ".bak"; File.WriteAllBytes(Backup, Before); File.WriteAllText(Live, "new settings");
            }
            internal ConfigurationRecoveryTransaction Open(Host host) { return new ConfigurationRecoveryTransaction(Dir, Live, host); }
        }

        private sealed class Host : IRecoveryHost
        {
            internal int Restarts, Schedules, FirewallAttempts; internal FirewallRule Firewall; internal bool FailRestart, FailSchedule, FailFirewall; internal Action OnSchedule;
            public void Schedule(DateTime dueUtc) { if (OnSchedule != null) OnSchedule(); if (FailSchedule) throw new IOException("scheduler unavailable"); Schedules++; }
            public void Disarm() { }
            public void RestoreFirewall(FirewallRule before) { FirewallAttempts++; if (FailFirewall) throw new IOException("firewall restore interrupted"); Firewall = before; }
            public void Restart() { Restarts++; if (FailRestart) throw new IOException("restart interrupted"); }
        }

        internal sealed class FakeFirewallRule
        {
            public string Name = "test", Description = "", ApplicationName = "", ServiceName = "", LocalPorts = "22", RemotePorts = "*", LocalAddresses = "*", RemoteAddresses = "*", InterfaceTypes = "All", Grouping = "", IcmpTypesAndCodes = "*";
            public string LocalAppPackageId = "", LocalUserOwner = "", LocalUserAuthorizedList = "", RemoteUserAuthorizedList = "", RemoteMachineAuthorizedList = "";
            public int Protocol = 6, Direction = 1, Action = 1, Profiles = 7, EdgeTraversalOptions, SecureFlags;
            public bool Enabled = true, EdgeTraversal;
            public object Interfaces;
        }
    }
}

// OpenSSH Server PN Manager: WindowsSettings

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

namespace OpenSSHServerPNManager
{
    // ------------------------------------------------------------------------------------------
    // Default shell (registry) and firewall (COM, language independent)
    // ------------------------------------------------------------------------------------------
    internal static class DefaultShell
    {
        private static RegistryKey Open(bool writable)
        {
            var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, Environment.Is64BitOperatingSystem ? RegistryView.Registry64 : RegistryView.Default);
            return writable ? baseKey.CreateSubKey(@"SOFTWARE\OpenSSH") : baseKey.OpenSubKey(@"SOFTWARE\OpenSSH");
        }
        public static string Get() { try { using (var k = Open(false)) return k == null ? null : k.GetValue("DefaultShell") as string; } catch { return null; } }
        public static string GetOption() { try { using (var k = Open(false)) return k == null ? null : k.GetValue("DefaultShellCommandOption") as string; } catch { return null; } }
        public static void Set(string shell, string option)
        {
            using (var k = Open(true))
            {
                if (string.IsNullOrWhiteSpace(shell)) { k.DeleteValue("DefaultShell", false); k.DeleteValue("DefaultShellCommandOption", false); return; }
                k.SetValue("DefaultShell", shell.Trim(), RegistryValueKind.String);
                if (string.IsNullOrWhiteSpace(option)) k.DeleteValue("DefaultShellCommandOption", false);
                else k.SetValue("DefaultShellCommandOption", option.Trim(), RegistryValueKind.String);
            }
        }
        public static List<string> Candidates()
        {
            var l = new List<string>();
            var pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            foreach (var p in new[] {
                Path.Combine(Environment.SystemDirectory, "cmd.exe"),
                Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe"),
                Path.Combine(pf, @"PowerShell\7\pwsh.exe"),
                Path.Combine(pf, @"Git\bin\bash.exe"),
                Path.Combine(Environment.SystemDirectory, "bash.exe") })
                if (File.Exists(p)) l.Add(p);
            return l;
        }
    }

    internal sealed class FirewallRule { public string Name; public bool Enabled; public int Profiles; public string Ports; public string Program; public bool Exists = true;
        public Dictionary<string, string> Attributes = new Dictionary<string, string>(StringComparer.Ordinal);
        /// <summary>Non-null for a complete recovery snapshot of both managed names, including outbound/duplicate rules.</summary>
        public List<FirewallRule> RelatedRules;
        public string ProfilesText { get { return ProfileText(Profiles); } }
        internal void Store(IDictionary<string, string> values, string prefix)
        {
            values[prefix + "name"] = Name ?? ""; values[prefix + "exists"] = Exists ? "1" : "0";
            values[prefix + "enabled"] = Enabled ? "1" : "0"; values[prefix + "profiles"] = Profiles.ToString(System.Globalization.CultureInfo.InvariantCulture);
            values[prefix + "ports"] = Ports ?? ""; values[prefix + "program"] = Program ?? "";
            foreach (var pair in Attributes) values[prefix + "attribute." + pair.Key] = pair.Value;
            values[prefix + "related"] = RelatedRules == null ? "-1" : RelatedRules.Count.ToString(System.Globalization.CultureInfo.InvariantCulture);
            if (RelatedRules != null) for (int i = 0; i < RelatedRules.Count; i++) RelatedRules[i].Store(values, prefix + "rule." + i + ".");
        }
        internal static FirewallRule Read(IDictionary<string, string> values, string prefix)
        {
            var rule = new FirewallRule { Name = values[prefix + "name"], Exists = values[prefix + "exists"] == "1", Enabled = values[prefix + "enabled"] == "1",
                Profiles = int.Parse(values[prefix + "profiles"], System.Globalization.CultureInfo.InvariantCulture), Ports = values[prefix + "ports"], Program = values[prefix + "program"] };
            foreach (var pair in values.Where(v => v.Key.StartsWith(prefix + "attribute.", StringComparison.Ordinal))) rule.Attributes[pair.Key.Substring((prefix + "attribute.").Length)] = pair.Value;
            int count = int.Parse(values[prefix + "related"], System.Globalization.CultureInfo.InvariantCulture);
            if (count < -1 || count > 10000) throw new ConfigException("The firewall recovery snapshot is invalid.");
            if (count >= 0) { rule.RelatedRules = new List<FirewallRule>(); for (int i = 0; i < count; i++) rule.RelatedRules.Add(Read(values, prefix + "rule." + i + ".")); }
            return rule;
        }
        public static string ProfileText(int p) { if ((p & 0x7fffffff) == 0x7fffffff || (p & 7) == 7) return "Domain, Private, Public"; var l = new List<string>(); if ((p & 1) != 0) l.Add("Domain"); if ((p & 2) != 0) l.Add("Private"); if ((p & 4) != 0) l.Add("Public"); return l.Count == 0 ? "none" : string.Join(", ", l); } }

    internal static class Firewall
    {
        public const string RuleName = "OpenSSH SSH Server Preview (sshd)";
        public const string ManagedRuleName = "OpenSSH SSH Server (sshd)";
        private const string RecoveryRemovalPrefix = "OpenSSH Server PN Manager recovery ";

        private static dynamic Policy() { return Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2")); }

        /// <summary>
        /// The inbound rule for sshd, or null. Looked up by name (Rules.Item): walking all rules costs one COM call per rule,
        /// which is quick on the window's thread but took about 150 ms per rule on the background refresh thread (more
        /// than a minute for the 1,100 rules of a test machine). All rules are walked only when the rule found by name is
        /// not the inbound one (an outbound rule of the same name).
        /// </summary>
        public static FirewallRule Get() { return Get(RuleName, ManagedRuleName); }

        /// <summary>The first inbound rule with one of these names, or null (the names are tried in order).</summary>
        public static FirewallRule Get(params string[] names)
        {
            try
            {
                dynamic policy = Policy();
                foreach (var name in names)
                {
                    dynamic byName = null;
                    // No rule of that name: through dynamic, the COM error comes as FileNotFoundException (0x80070002), and
                    // must not end the search, or the second name is never tried.
                    try { byName = policy.Rules.Item(name); } catch (Exception ex) when (ex is COMException || ex is FileNotFoundException) { continue; }
                    if ((int)byName.Direction == 1) return FromRule(name, byName);
                    foreach (dynamic r in policy.Rules)
                    {
                        try { if ((string)r.Name == name && (int)r.Direction == 1) return FromRule(name, r); }
                        catch { }
                    }
                }
            }
            catch (Exception ex) { Log.Error("Firewall query failed", ex, false); }
            return null;
        }

        private static FirewallRule FromRule(string name, dynamic r)
        {
            return CaptureRule((object)r);
        }

        internal static FirewallRule CaptureRule(object value)
        {
            dynamic r = value;
            var result = new FirewallRule { Name = (string)r.Name, Enabled = (bool)r.Enabled, Profiles = (int)r.Profiles, Program = (string)r.ApplicationName };
            int protocol = (int)r.Protocol;
            var a = result.Attributes;
            a["Protocol"] = protocol.ToString(System.Globalization.CultureInfo.InvariantCulture);
            a["Direction"] = ((int)r.Direction).ToString(System.Globalization.CultureInfo.InvariantCulture);
            a["Action"] = ((int)r.Action).ToString(System.Globalization.CultureInfo.InvariantCulture);
            a["Description"] = (string)r.Description ?? ""; a["ServiceName"] = (string)r.ServiceName ?? "";
            a["LocalAddresses"] = (string)r.LocalAddresses; a["RemoteAddresses"] = (string)r.RemoteAddresses;
            a["InterfaceTypes"] = (string)r.InterfaceTypes; a["Grouping"] = (string)r.Grouping ?? "";
            a["EdgeTraversal"] = (bool)r.EdgeTraversal ? "1" : "0";
            if (protocol == 6 || protocol == 17) { result.Ports = (string)r.LocalPorts; a["RemotePorts"] = (string)r.RemotePorts; }
            if (protocol == 1 || protocol == 58) a["IcmpTypesAndCodes"] = (string)r.IcmpTypesAndCodes;
            var interfaces = (object)r.Interfaces as System.Collections.IEnumerable;
            a["Interfaces"] = interfaces == null ? "" : string.Join("\n", interfaces.Cast<object>().Select(x => Convert.ToBase64String(Encoding.UTF8.GetBytes(Convert.ToString(x, System.Globalization.CultureInfo.InvariantCulture)))));
            CaptureOptional(a, "EdgeTraversalOptions", () => (object)r.EdgeTraversalOptions);
            CaptureOptional(a, "LocalAppPackageId", () => (object)r.LocalAppPackageId);
            CaptureOptional(a, "LocalUserOwner", () => (object)r.LocalUserOwner);
            CaptureOptional(a, "LocalUserAuthorizedList", () => (object)r.LocalUserAuthorizedList);
            CaptureOptional(a, "RemoteUserAuthorizedList", () => (object)r.RemoteUserAuthorizedList);
            CaptureOptional(a, "RemoteMachineAuthorizedList", () => (object)r.RemoteMachineAuthorizedList);
            CaptureOptional(a, "SecureFlags", () => (object)r.SecureFlags);
            return result;
        }

        private static void CaptureOptional(IDictionary<string, string> values, string name, Func<object> read)
        {
            try { values[name] = Convert.ToString(read(), System.Globalization.CultureInfo.InvariantCulture) ?? ""; }
            catch (Microsoft.CSharp.RuntimeBinder.RuntimeBinderException) { }
            catch (COMException ex) when (ex.ErrorCode == unchecked((int)0x80020003) || ex.ErrorCode == unchecked((int)0x80004001)) { }
        }

        /// <summary>Recovery must distinguish an absent rule from a failed query and preserve all rule scopes.</summary>
        public static FirewallRule CaptureForRecovery()
        {
            dynamic policy = Policy();
            var result = new FirewallRule { Name = ManagedRuleName, Exists = false, RelatedRules = new List<FirewallRule>() };
            foreach (dynamic r in policy.Rules)
                if ((string)r.Name == RuleName || (string)r.Name == ManagedRuleName || ((string)r.Name).StartsWith(RecoveryRemovalPrefix, StringComparison.Ordinal)) result.RelatedRules.Add(CaptureRule((object)r));
            result.Exists = result.RelatedRules.Count > 0;
            return result;
        }

        internal static void ApplySnapshot(object value, FirewallRule snapshot)
        {
            dynamic r = value;
            var a = snapshot.Attributes;
            r.Enabled = false; r.Name = snapshot.Name;
            int protocol = a.ContainsKey("Protocol") ? int.Parse(a["Protocol"], System.Globalization.CultureInfo.InvariantCulture) : 6;
            r.Protocol = protocol;
            r.Direction = a.ContainsKey("Direction") ? int.Parse(a["Direction"], System.Globalization.CultureInfo.InvariantCulture) : 1;
            r.Action = a.ContainsKey("Action") ? int.Parse(a["Action"], System.Globalization.CultureInfo.InvariantCulture) : 1;
            r.ApplicationName = snapshot.Program ?? "";
            if (protocol == 6 || protocol == 17) { r.LocalPorts = snapshot.Ports; if (a.ContainsKey("RemotePorts")) r.RemotePorts = a["RemotePorts"]; }
            if (a.ContainsKey("Description")) r.Description = a["Description"];
            if (a.ContainsKey("ServiceName")) r.ServiceName = a["ServiceName"];
            if (a.ContainsKey("LocalAddresses")) r.LocalAddresses = a["LocalAddresses"];
            if (a.ContainsKey("RemoteAddresses")) r.RemoteAddresses = a["RemoteAddresses"];
            if (a.ContainsKey("IcmpTypesAndCodes")) r.IcmpTypesAndCodes = a["IcmpTypesAndCodes"];
            if (a.ContainsKey("InterfaceTypes")) r.InterfaceTypes = a["InterfaceTypes"];
            if (a.ContainsKey("Interfaces")) r.Interfaces = a["Interfaces"].Length == 0 ? null : a["Interfaces"].Split('\n').Select(s => (object)Encoding.UTF8.GetString(Convert.FromBase64String(s))).ToArray();
            if (a.ContainsKey("Grouping")) r.Grouping = a["Grouping"];
            if (a.ContainsKey("EdgeTraversal")) r.EdgeTraversal = a["EdgeTraversal"] == "1";
            if (a.ContainsKey("EdgeTraversalOptions")) r.EdgeTraversalOptions = int.Parse(a["EdgeTraversalOptions"], System.Globalization.CultureInfo.InvariantCulture);
            if (a.ContainsKey("LocalAppPackageId")) r.LocalAppPackageId = a["LocalAppPackageId"];
            if (a.ContainsKey("LocalUserOwner")) r.LocalUserOwner = a["LocalUserOwner"];
            if (a.ContainsKey("LocalUserAuthorizedList")) r.LocalUserAuthorizedList = a["LocalUserAuthorizedList"];
            if (a.ContainsKey("RemoteUserAuthorizedList")) r.RemoteUserAuthorizedList = a["RemoteUserAuthorizedList"];
            if (a.ContainsKey("RemoteMachineAuthorizedList")) r.RemoteMachineAuthorizedList = a["RemoteMachineAuthorizedList"];
            if (a.ContainsKey("SecureFlags")) r.SecureFlags = int.Parse(a["SecureFlags"], System.Globalization.CultureInfo.InvariantCulture);
            r.Profiles = snapshot.Profiles; r.Enabled = snapshot.Enabled;
        }

        public static void Restore(FirewallRule before)
        {
            if (before == null) throw new ArgumentNullException("before");
            dynamic policy = Policy();
            var current = new List<object>();
            foreach (dynamic rule in policy.Rules)
                if ((string)rule.Name == RuleName || (string)rule.Name == ManagedRuleName || ((string)rule.Name).StartsWith(RecoveryRemovalPrefix, StringComparison.Ordinal)) current.Add((object)rule);
            RestoreRules(current, before, name => policy.Rules.Remove(name));
        }

        internal static void RestoreRules(IList<object> current, FirewallRule before, Action<string> remove)
        {
            var original = before.RelatedRules ?? (before.Exists ? new List<FirewallRule> { before } : new List<FirewallRule>());
            var available = current.Select(rule => new KeyValuePair<object, FirewallRule>(rule, CaptureRule(rule))).ToList();
            var matched = new List<KeyValuePair<object, FirewallRule>>();
            foreach (var snapshot in original)
            {
                var match = available.FirstOrDefault(pair => SameScope(pair.Value, snapshot));
                if (match.Key == null) throw new ConfigChangedException("An SSH firewall rule was removed or its scope changed outside this transaction. Recovery will not replace that external change: " + snapshot.Name);
                matched.Add(new KeyValuePair<object, FirewallRule>(match.Key, snapshot)); available.Remove(match);
            }
            // Apply never deletes an existing rule. Preserve its COM identity, optional properties, and outbound duplicates.
            // INetFwRules.Add does not support recreating packaged-app rules and may overwrite duplicate identifiers.
            foreach (var extra in available)
            {
                string description, protocol, direction, action;
                if ((extra.Value.Name != ManagedRuleName && !extra.Value.Name.StartsWith(RecoveryRemovalPrefix, StringComparison.Ordinal)) || extra.Value.Program != Ssh.Exe("sshd.exe") ||
                    !extra.Value.Attributes.TryGetValue("Description", out description) || description != "Inbound rule for OpenSSH SSH Server (sshd), managed by OpenSSH Server PN Manager" ||
                    !extra.Value.Attributes.TryGetValue("Protocol", out protocol) || protocol != "6" || !extra.Value.Attributes.TryGetValue("Direction", out direction) || direction != "1" ||
                    !extra.Value.Attributes.TryGetValue("Action", out action) || action != "1")
                    throw new ConfigChangedException("An additional SSH firewall rule appeared outside this transaction. Recovery will not delete it.");
            }
            foreach (var pair in matched)
            {
                dynamic rule = pair.Key; var snapshot = pair.Value;
                if (snapshot.Attributes["Protocol"] == "6" || snapshot.Attributes["Protocol"] == "17") rule.LocalPorts = snapshot.Ports;
                rule.Profiles = snapshot.Profiles; rule.Enabled = snapshot.Enabled;
            }
            foreach (var extra in available)
            {
                // Removing by a shared display name could remove an original outbound rule. Give only our new rule a
                // unique name before removal, so the operation cannot target an unrelated duplicate.
                dynamic rule = extra.Key; string unique = RecoveryRemovalPrefix + Guid.NewGuid().ToString("N");
                rule.Name = unique; remove(unique);
            }
        }

        private static bool SameScope(FirewallRule first, FirewallRule second)
        {
            return first.Name == second.Name && first.Program == second.Program && first.Attributes.Count == second.Attributes.Count &&
                first.Attributes.All(pair => second.Attributes.ContainsKey(pair.Key) && second.Attributes[pair.Key] == pair.Value);
        }

        /// <summary>True when a rule's LocalPorts value ("22", "22,2222", "2000-3000", "*") admits the port.</summary>
        public static bool Covers(string ports, int port)
        {
            if (string.IsNullOrWhiteSpace(ports)) return false;
            foreach (var raw in ports.Split(','))
            {
                var t = raw.Trim();
                if (t == "*" || t.Equals("Any", StringComparison.OrdinalIgnoreCase)) return true;
                int a, b; int dash = t.IndexOf('-');
                if (dash > 0 && int.TryParse(t.Substring(0, dash), out a) && int.TryParse(t.Substring(dash + 1), out b)) { if (port >= a && port <= b) return true; }
                else if (int.TryParse(t, out a) && a == port) return true;
            }
            return false;
        }

        /// <summary>True when LocalPorts holds exactly one port number (the form the Firewall tab edits directly).</summary>
        public static bool IsSinglePort(string ports) { int p; return int.TryParse((ports ?? "").Trim(), out p) && p >= 1 && p <= 65535; }

        public static void Apply(bool enabled, int profiles, int port) { Apply(enabled, profiles, port.ToString()); }

        /// <summary>Creates or updates the inbound sshd rule; ports is a LocalPorts value such as "22" or "22,2222".</summary>
        public static void Apply(bool enabled, int profiles, string ports)
        {
            dynamic policy = Policy();
            dynamic rule = null;
            foreach (dynamic r in policy.Rules)
            {
                try { if (((string)r.Name == RuleName || (string)r.Name == ManagedRuleName) && (int)r.Direction == 1) { rule = r; break; } } catch { }
            }
            if (rule == null)
            {
                rule = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule"));
                rule.Name = ManagedRuleName;
                rule.Description = "Inbound rule for OpenSSH SSH Server (sshd), managed by OpenSSH Server PN Manager";
                rule.Protocol = 6; // TCP
                rule.Direction = 1; // in
                rule.Action = 1; // allow
                rule.ApplicationName = Ssh.Exe("sshd.exe");
                rule.LocalPorts = ports;
                rule.Profiles = profiles == 0 ? 0x7fffffff : profiles;
                rule.Enabled = enabled;
                policy.Rules.Add(rule);
                return;
            }
            rule.LocalPorts = ports;
            rule.Profiles = profiles == 0 ? 0x7fffffff : profiles;
            rule.Enabled = enabled;
        }

        public static void Remove()
        {
            dynamic policy = Policy();
            foreach (var name in new[] { RuleName, ManagedRuleName }) { try { policy.Rules.Remove(name); } catch { } }
        }

        /// <summary>The inbound block rule this program keeps for addresses blocked from SSH (block rules win over allow rules).</summary>
        public const string BlockRuleName = "OpenSSH Server PN Manager: blocked addresses";
        /// <summary>The block rule's name under the earlier name of the manager, OpenSSH Server Manager (1.6.0 and older): still read and kept up to date, so no blocked address is lost by an update.</summary>
        public const string LegacyBlockRuleName = "OpenSSH Server Manager: blocked addresses";

        /// <summary>The block rules in the policy, under the current name first, then the earlier one: (name, rule) pairs.</summary>
        private static List<KeyValuePair<string, dynamic>> BlockRules(object policyObject)
        {
            dynamic policy = policyObject;
            var l = new List<KeyValuePair<string, dynamic>>();
            foreach (var n in new[] { BlockRuleName, LegacyBlockRuleName })
            {
                // No such rule: through dynamic, the COM error comes as FileNotFoundException (0x80070002).
                try { dynamic r = policy.Rules.Item(n); l.Add(new KeyValuePair<string, dynamic>(n, r)); } catch (Exception ex) when (ex is COMException || ex is FileNotFoundException) { }
            }
            return l;
        }

        /// <summary>The name of the block rule that exists (the earlier name while only that one exists), or the current name.</summary>
        public static string BlockRuleNameInUse()
        {
            try { var l = BlockRules((object)Policy()); return l.Count > 0 ? l[0].Key : BlockRuleName; } catch (COMException) { return BlockRuleName; }
        }

        /// <summary>
        /// The addresses in the block rule (empty when there is none). When both names exist (1.6.0 was started again after
        /// 2.0.0), the addresses of both.
        /// </summary>
        public static List<string> BlockedAddresses()
        {
            try
            {
                var all = new List<string>();
                foreach (var kv in BlockRules((object)Policy()))
                {
                    var v = (string)kv.Value.RemoteAddresses;
                    if (string.IsNullOrEmpty(v) || v == "*") continue;
                    all.AddRange(v.Split(',').Select(a => NormaliseAddress(a.Trim())).Where(a => a.Length > 0));
                }
                return all.Distinct().ToList();
            }
            catch (COMException) { return new List<string>(); }
        }

        /// <summary>"1.2.3.4/255.255.255.255" (how Windows stores a single address) as "1.2.3.4"; ranges and subnets stay as they are.</summary>
        public static string NormaliseAddress(string a)
        {
            if (a.EndsWith("/255.255.255.255")) return a.Substring(0, a.Length - 16);
            if (a.EndsWith("/128") && a.Contains(":")) return a.Substring(0, a.Length - 4);
            return a;
        }

        /// <summary>
        /// Writes the block rule: TCP to the given local ports from these addresses is blocked on every profile. An empty
        /// list removes the rule. When rules of both names exist, the first is written and the other removed afterwards.
        /// </summary>
        public static void SetBlockedAddresses(IList<string> addresses, string ports)
        {
            dynamic policy = Policy();
            var rules = BlockRules((object)policy);
            if (addresses == null || addresses.Count == 0) { foreach (var kv in rules) policy.Rules.Remove(kv.Key); return; }
            if (rules.Count > 0)
            {
                // Changed in place: removing and adding again would leave a moment with nothing blocked, and every address
                // unblocked if the new rule could not be added.
                dynamic existing = rules[0].Value;
                existing.RemoteAddresses = string.Join(",", addresses);
                existing.LocalPorts = ports;
                existing.Enabled = true;
                for (int i = 1; i < rules.Count; i++) policy.Rules.Remove(rules[i].Key);
                return;
            }
            dynamic rule = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule"));
            rule.Name = BlockRuleName;
            rule.Description = "Addresses blocked from SSH by OpenSSH Server PN Manager (Logs tab, Failed logins by address).";
            rule.Protocol = 6; rule.Direction = 1; rule.Action = 0; // TCP, inbound, block
            rule.LocalPorts = ports;
            rule.RemoteAddresses = string.Join(",", addresses);
            rule.Profiles = 0x7fffffff;
            rule.Enabled = true;
            policy.Rules.Add(rule);
        }

        /// <summary>Expiry only removes requested addresses; each existing rule retains its port scope and enabled state.</summary>
        public static void RemoveBlockedAddresses(IEnumerable<string> addresses)
        {
            var remove = new HashSet<string>(addresses.Select(NormaliseAddress), StringComparer.OrdinalIgnoreCase);
            dynamic policy = Policy();
            foreach (var entry in BlockRules((object)policy))
            {
                string remote = (string)entry.Value.RemoteAddresses;
                if (string.IsNullOrEmpty(remote) || remote == "*") continue;
                var previous = remote.Split(',');
                var remaining = previous.Where(a => !remove.Contains(NormaliseAddress(a.Trim()))).ToArray();
                if (remaining.Length == previous.Length) continue;
                if (remaining.Length == 0) policy.Rules.Remove(entry.Key);
                else entry.Value.RemoteAddresses = string.Join(",", remaining);
            }
        }

        /// <summary>Why an address should not be blocked (this computer, loopback, an address it cannot parse), or null.</summary>
        public static string NotBlockable(string address)
        {
            IPAddress ip;
            if (!IPAddress.TryParse(address, out ip)) return address + " is not an IP address";
            if (IPAddress.IsLoopback(ip)) return address + " is this computer (loopback)";
            try
            {
                foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
                    foreach (var ua in ni.GetIPProperties().UnicastAddresses)
                        if (ua.Address.Equals(ip)) return address + " is an address of this computer";
            }
            catch { }
            return null;
        }
    }

    // ------------------------------------------------------------------------------------------
    // Event log
    // ------------------------------------------------------------------------------------------
    internal sealed class LogEvent { public DateTime Time; public int Id; public string Level; public string Message; }

    internal static class EventLogs
    {
        public const string LogName = "OpenSSH/Operational";

        public static List<LogEvent> Read(int max, string filter) { return Read(max, filter, null, CancellationToken.None); }

        /// <summary>The newest events first, at most max, whose message contains filter; only those of the last period when given.</summary>
        public static List<LogEvent> Read(int max, string filter, TimeSpan? period, CancellationToken cancel)
        {
            var l = new List<LogEvent>();
            try
            {
                var xpath = period.HasValue ? "*[System[TimeCreated[timediff(@SystemTime) <= " + (long)period.Value.TotalMilliseconds + "]]]" : "*";
                var q = new EventLogQuery(LogName, PathType.LogName, xpath) { ReverseDirection = true };
                using (var reader = new EventLogReader(q))
                {
                    EventRecord rec;
                    while (l.Count < max && !cancel.IsCancellationRequested && (rec = reader.ReadEvent()) != null)
                    {
                        using (rec)
                        {
                            string msg;
                            try { msg = rec.FormatDescription(); } catch { msg = null; }
                            if (string.IsNullOrEmpty(msg)) { try { msg = string.Join(" ", rec.Properties.Select(p => Convert.ToString(p.Value))); } catch { msg = "(no message)"; } }
                            msg = msg.Replace("\r", " ").Replace("\n", " ").Trim();
                            if (!string.IsNullOrEmpty(filter) && msg.IndexOf(filter, StringComparison.OrdinalIgnoreCase) < 0) continue;
                            string level; try { level = rec.LevelDisplayName; } catch { level = rec.Level.ToString(); }
                            l.Add(new LogEvent { Time = rec.TimeCreated ?? DateTime.MinValue, Id = rec.Id, Level = level, Message = msg });
                        }
                    }
                }
            }
            catch (EventLogNotFoundException) { l.Add(new LogEvent { Time = DateTime.Now, Id = 0, Level = "Info", Message = "The " + LogName + " event log does not exist on this system. Install the server feature or enable file logging (SyslogFacility LOCAL0)." }); }
            catch (Exception ex) { l.Add(new LogEvent { Time = DateTime.Now, Id = 0, Level = "Error", Message = "Cannot read event log: " + ex.Message }); }
            return l;
        }

        private static readonly Regex FailurePattern = new Regex(
            // The address is taken from the END of the message: a user name may contain spaces, so "ssh -l 'x from 10.1.2.3
            // port 22' server" makes sshd log "Invalid user x from 10.1.2.3 port 22 from <real address> port <n>". The user
            // groups are greedy and the address must be followed only by the port, "ssh2" and "[preauth]".
            @"(?:^|: )(?:(?:Failed \S+ for (?:invalid user )?(?<user>.*)|Invalid user (?<user>.*)|maximum authentication attempts exceeded for (?:invalid user )?(?<user>.*)) from|(?:Connection closed by|Disconnected from) (?:authenticating|invalid) user (?<user>.*)|Timeout before authentication for) (?<addr>[0-9A-Fa-f.:]+) port \d+(?: ssh2)?(?: \[preauth\])?\s*$",
            RegexOptions.IgnoreCase);

        /// <summary>
        /// The client address (and the account name tried, if any) of an sshd message about a failed or abandoned login
        /// ("Failed password for x from 10.0.0.5 port 50123 ssh2", "Invalid user x from ..."), or null for other messages.
        /// </summary>
        public static string FailedLoginAddress(string message, out string user)
        {
            user = null;
            var m = FailurePattern.Match((message ?? "").Replace("sshd: ", "").Trim());
            if (!m.Success) return null;
            IPAddress ip;
            if (!IPAddress.TryParse(m.Groups["addr"].Value, out ip)) return null;
            user = m.Groups["user"].Success ? m.Groups["user"].Value : null;
            return (ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip).ToString();
        }

        /// <summary>Failed logins grouped by client address, the most first.</summary>
        public sealed class FailedSource { public string Address; public int Count; public DateTime First, Last; public SortedSet<string> Users = new SortedSet<string>(StringComparer.OrdinalIgnoreCase); }

        public static List<FailedSource> FailedByAddress(IEnumerable<LogEvent> events)
        {
            var d = new Dictionary<string, FailedSource>();
            foreach (var e in events)
            {
                string user; var a = FailedLoginAddress(e.Message, out user);
                if (a == null) continue;
                FailedSource s;
                if (!d.TryGetValue(a, out s)) d[a] = s = new FailedSource { Address = a, First = e.Time, Last = e.Time };
                s.Count++;
                if (e.Time < s.First) s.First = e.Time;
                if (e.Time > s.Last) s.Last = e.Time;
                if (!string.IsNullOrEmpty(user)) s.Users.Add(user);
            }
            return d.Values.OrderByDescending(x => x.Count).ThenByDescending(x => x.Last).ToList();
        }

        public static string FileLogPath()
        {
            try
            {
                if (!Directory.Exists(Ssh.LogDir)) return null;
                return Directory.GetFiles(Ssh.LogDir, "sshd*.log").OrderByDescending(f => File.GetLastWriteTime(f)).FirstOrDefault();
            }
            catch { return null; }
        }

        public static string TailFile(string path, int lines)
        {
            try
            {
                const int window = 512 * 1024; // sshd.log can grow to hundreds of MB; read only the end
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                {
                    bool partial = fs.Length > window;
                    if (partial) fs.Seek(-window, SeekOrigin.End);
                    using (var sr = new StreamReader(fs, Encoding.UTF8))
                    {
                        var all = sr.ReadToEnd().Split('\n');
                        if (partial && all.Length > 1) all = all.Skip(1).ToArray(); // first line is cut
                        return string.Join("\n", all.Skip(Math.Max(0, all.Length - lines)));
                    }
                }
            }
            catch (Exception ex) { return "Cannot read " + path + ": " + ex.Message; }
        }
    }
}

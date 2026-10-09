using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace OpenSSHServerPNManager
{
    /// <summary>Regressions for the server window, wizard and hardening (October 2026 follow-up review).</summary>
    internal static class FollowUpGuiTests
    {
        private const BindingFlags Members = BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic;
        private static object Get(object o, string name) { return o.GetType().GetField(name, Members).GetValue(o); }
        private static void Set(object o, string name, object value) { o.GetType().GetField(name, Members).SetValue(o, value); }
        private static object Call(object o, string name, params object[] args) { return o.GetType().GetMethod(name, Members).Invoke(o, args); }
        private static void Wait(object o, string name, params object[] args) { AsyncUiTest.Wait(() => (Task)Call(o, name, args)); }

        private static IEnumerable<Control> Descendants(Control root)
        {
            foreach (Control c in root.Controls) { yield return c; foreach (var d in Descendants(c)) yield return d; }
        }

        /// <summary>The server window with a handle but not shown (no service, firewall or registry writes), on configDir's sshd_config when given.</summary>
        private static void WithWindow(string configDir, Action<MainForm> body)
        {
            bool old = Program.Unattended; var oldDir = Ssh.ConfigDirOverride;
            Program.Unattended = true;
            try
            {
                if (configDir != null) Ssh.ConfigDirOverride = configDir;
                AsyncUiTest.EnsureContext();
                using (var f = new MainForm())
                {
                    var handle = f.Handle;
                    Set(f, "_cfg", configDir != null && File.Exists(Ssh.ConfigPath) ? SshdConfig.Load() : new SshdConfig());
                    try { body(f); }
                    finally { f.Close(); }
                }
            }
            finally { Ssh.ConfigDirOverride = oldDir; Program.Unattended = old; }
        }

        private static void PressKey(MainForm f, System.Windows.Forms.Keys key)
        {
            var handled = (bool)typeof(MainForm).GetMethod("ProcessCmdKey", Members).Invoke(f, new object[] { new Message(), key });
            f.WaitForIdleForTest();
            if (!handled) throw new Exception(key + " was not handled");
        }

        private static string NewDir(string tmpDir, string name)
        {
            var dir = Path.Combine(tmpDir, name + "-" + Guid.NewGuid().ToString("N").Substring(0, 8));
            Directory.CreateDirectory(dir);
            return dir;
        }

        /// <summary>Runs one of the setup wizard's own steps as its buttons and Load do (WorkAsync).</summary>
        private static void WizardWork(SetupWizard w, Func<Task> work) { AsyncUiTest.Wait(() => (Task)Call(w, "WorkAsync", work)); }

        internal static void Run(Action<string, Func<string>> test, string tmpDir)
        {
            test("authorized keys: only keys sshd can log in with count for key-only login", () =>
            {
                var dir = NewDir(tmpDir, "usable-keys");
                const string blob = "AAAAC3NzaC1lZDI1NTE5AAAAIGVkMjU1MTlzZWxmdGVzdGtleTAwMDAwMDAwMDAwMDAwMDA";
                string a = Path.Combine(dir, "a"), b = Path.Combine(dir, "b");
                File.WriteAllLines(a, new[]
                {
                    "# a comment",
                    "ssh-ed25519 " + blob + " plain",
                    "from=\"10.0.0.0/8\",no-pty ssh-ed25519 " + blob + " with options",
                    "cert-authority,principals=\"alice,bob\" ssh-ed25519 " + blob + " a CA, which needs a certificate",
                    "ssh-dss AAAAB3NzaC1kc3MAAACBAPfixturefixturefixturefixture old DSA",
                    "ssh-ed25519 " + blob + "x unreadable",
                });
                File.WriteAllLines(b, new[] { "principals=\"x,cert-authority\" ssh-ed25519 " + blob + " a principal named like the option" });
                Func<string, string> fingerprint = line => line.EndsWith("unreadable") ? "invalid key" : "SHA256:fixture";
                int n = Keys.UsableCount(new[] { a, b, Path.Combine(dir, "missing") }, fingerprint);
                if (n != 3) throw new Exception(n + " usable keys counted; expected 3 (plain, with options, the principal)");
                // ssh-keygen judges the material: made-up and truncated lines look like keys but do not count.
                var bad = Path.Combine(dir, "bad");
                File.WriteAllLines(bad, new[] { "ssh-rsa AAAAnotreallyakey= made up", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGVkMjU1MTlz truncated" });
                if (Keys.Read(bad).Count(k => k.Type != "?") != 2) throw new Exception("the fixture lines are not key-shaped");
                if (Keys.UsableCount(new[] { bad }) != 0) throw new Exception("lines ssh-keygen rejects were counted as usable keys");
                return null;
            });
            test("authorized keys: usable keys are counted as sshd reads the file and as its policy allows", () =>
            {
                var dir = NewDir(tmpDir, "usable-policy");
                const string blob = "AAAAC3NzaC1lZDI1NTE5AAAAIGVkMjU1MTlzZWxmdGVzdGtleTAwMDAwMDAwMDAwMDAwMDA";
                Func<string, string> fingerprint = line => "SHA256:fixture";
                Func<string, byte[], int> count = (name, bytes) => { var p = Path.Combine(dir, name); File.WriteAllBytes(p, bytes); return Keys.UsableCount(new[] { p }, fingerprint); };
                var utf8 = new UTF8Encoding(false);
                // Windows PowerShell's "echo key > file" writes UTF-16: sshd reads no key from it.
                if (count("utf16", Encoding.Unicode.GetPreamble().Concat(Encoding.Unicode.GetBytes("ssh-ed25519 " + blob + " x\r\n")).ToArray()) != 0) throw new Exception("a UTF-16 file was counted");
                if (count("utf8bom", new byte[] { 0xEF, 0xBB, 0xBF }.Concat(utf8.GetBytes("ssh-ed25519 " + blob + " x\n")).ToArray()) != 1) throw new Exception("a UTF-8 BOM hid the key");
                // Ctrl-Z ends the file in sshd's text-mode read ("copy a.pub+b.pub").
                if (count("ctrlz", utf8.GetBytes("ssh-ed25519 " + blob + " a\n\u001a\nssh-ed25519 " + blob + " after\n")) != 1) throw new Exception("a key after Ctrl-Z was counted");
                if (count("option", utf8.GetBytes("no-agent-fowarding ssh-ed25519 " + blob + " typo\n")) != 0) throw new Exception("a line with an option sshd refuses was counted");
                if (count("cert", utf8.GetBytes("ssh-ed25519-cert-v01@openssh.com " + blob + " certificate\n")) != 0) throw new Exception("a certificate line was counted");
                // RSA below RequiredRSASize, and types PubkeyAcceptedAlgorithms leaves out.
                var modulus = new byte[129]; modulus[1] = 0x80;
                var rsa1024 = Convert.ToBase64String(new SshWriter().String("ssh-rsa").String(new byte[] { 1, 0, 1 }).String(modulus).ToArray());
                if (Keys.RsaBits(rsa1024) != 1024) throw new Exception("RSA size read as " + Keys.RsaBits(rsa1024));
                var rsaFile = Path.Combine(dir, "rsa"); File.WriteAllText(rsaFile, "ssh-rsa " + rsa1024 + " old\n");
                if (Keys.UsableCount(new[] { rsaFile }, fingerprint, Keys.KeyPolicy.From(null)) != 1) throw new Exception("a 1024-bit key was refused at the default size");
                if (Keys.UsableCount(new[] { rsaFile }, fingerprint, Keys.KeyPolicy.From(null, 2048)) != 0) throw new Exception("a 1024-bit key counted with RequiredRSASize 2048");
                var mldsa = Path.Combine(dir, "mldsa"); File.WriteAllText(mldsa, "ssh-mldsa44-ed25519@openssh.com " + blob + " experimental\n");
                if (Keys.UsableCount(new[] { mldsa }, fingerprint) != 0) throw new Exception("ML-DSA counted although the default list leaves it out");
                var policy = Keys.KeyPolicy.From(new Dictionary<string, string> { { "pubkeyacceptedalgorithms", "ssh-mldsa44-ed25519@openssh.com,ssh-ed25519" } });
                if (Keys.UsableCount(new[] { mldsa }, fingerprint, policy) != 1 || Keys.UsableCount(new[] { rsaFile }, fingerprint, policy) != 0) throw new Exception("PubkeyAcceptedAlgorithms was not followed");
                // With the real ssh-keygen, a valid key does count (so the refusals above are not an ssh-keygen that is missing).
                if (File.Exists(Ssh.Exe("ssh-keygen.exe")))
                {
                    var real = Convert.ToBase64String(new SshWriter().String("ssh-ed25519").String(Enumerable.Range(1, 32).Select(i => (byte)i).ToArray()).ToArray());
                    var good = Path.Combine(dir, "good"); File.WriteAllText(good, "ssh-ed25519 " + real + " real\n");
                    if (Keys.UsableCount(new[] { good }) != 1) throw new Exception("ssh-keygen did not accept a valid Ed25519 key");
                }
                return null;
            });
            test("setup wizard: a wrong .pub file keeps the key-only choices of the keys already authorized", () =>
            {
                AsyncUiTest.EnsureContext();
                using (var w = new SetupWizard(22, null, null, () => 1, () => { throw new ConfigException("The file does not contain an OpenSSH public key."); }, o => null))
                {
                    var handle = w.Handle;
                    WizardWork(w, () => (Task)Call(w, "UpdateKeys")); // as Load does
                    var admins = (RadioButton)Get(w, "_adminKeys"); admins.Checked = true;
                    var add = Descendants(w).OfType<Button>().Single(x => x.Text.StartsWith("Add my public key"));
                    typeof(Button).GetMethod("OnClick", Members).Invoke(add, new object[] { EventArgs.Empty });
                    var until = DateTime.UtcNow.AddSeconds(30);
                    while ((bool)Get(w, "_working") && DateTime.UtcNow < until) { Application.DoEvents(); System.Threading.Thread.Sleep(1); }
                    var state = ((Label)Get(w, "_keysState")).Text;
                    if (!admins.Enabled || !admins.Checked || !((RadioButton)Get(w, "_allKeys")).Enabled || state.Contains("could not be verified"))
                        throw new Exception("after a failed add: key-only enabled " + admins.Enabled + ", still chosen " + admins.Checked + "; " + state);
                }
                using (var w = new SetupWizard(22, null, null, () => { throw new InvalidOperationException("sshd -T failed"); }, () => { }, o => null))
                {
                    var handle = w.Handle;
                    WizardWork(w, () => (Task)Call(w, "UpdateKeys"));
                    if (!((RadioButton)Get(w, "_keep")).Checked || ((RadioButton)Get(w, "_adminKeys")).Enabled || ((RadioButton)Get(w, "_allKeys")).Enabled ||
                        !((Label)Get(w, "_keysState")).Text.Contains("could not be verified"))
                        throw new Exception("key-only login is offered although the keys could not be counted");
                }
                return null;
            });
            test("setup wizard: the firewall plan adds the ports sshd uses and never takes one away", () =>
            {
                // sshd_config says Port 2200, but its ListenAddress with a port decides (as an Include with Port 2222 would).
                var cfg = new SshdConfig { Lines = new List<string> { "Port 2200", "ListenAddress 0.0.0.0:2222" } };
                var state = ServerState.FromEffectiveOutput(new RunResult { StdOut = "port 2200\nlistenaddress 0.0.0.0:2222\n" });
                if (!state.Verified || string.Join(",", state.Ports) != "2222" || cfg.EffectivePort != 2200) throw new Exception("fixture: " + string.Join(",", state.Ports));
                // The wizard shows 2200; left as it is, nothing is added (the rule used to be narrowed to 2200 alone).
                if (WizardPlan.FirewallAdds("2222", cfg.EffectivePort, false, state.Ports).Count != 0) throw new Exception("the unchanged port was added");
                var adds = WizardPlan.FirewallAdds("2222", 2300, true, state.Ports);
                if (string.Join(",", adds) != "2300") throw new Exception("a changed port: " + string.Join(",", adds));
                adds = WizardPlan.FirewallAdds("22", 22, false, state.Ports);
                if (string.Join(",", adds) != "2222") throw new Exception("sshd's port missing from the rule: " + string.Join(",", adds));
                adds = WizardPlan.FirewallAdds("2222", 2200, false, null);
                if (string.Join(",", adds) != "2200") throw new Exception("without verified ports: " + string.Join(",", adds));
                if (WizardPlan.FirewallAdds(null, 22, false, new[] { 22, 2222 }).Count != 2) throw new Exception("a new rule does not get every port sshd uses");
                var l = new WizardPlan { Port = 22, Profiles = 3 }.Describe(22, 3, true, true, new List<int> { 2222 });
                if (l.Count != 1 || !l[0].Contains("2222")) throw new Exception("the summary hides the firewall change: " + string.Join(" / ", l));
                if (new WizardPlan { Port = 22, Profiles = 3 }.Describe(22, 3, true, true, new List<int>()).Count != 0) throw new Exception("no change described as a change");
                return null;
            });
            test("setup wizard: the summary names the ports the firewall rule ends with once the settings are kept", () =>
            {
                Func<int[], ServerStateSnapshot> sshd = ports => new ServerStateSnapshot { Verified = true, ConfiguredPorts = ports, ListeningPorts = ports };
                Func<List<string>, string> fwLine = l => l.Single(x => x.StartsWith("The firewall rule"));
                var to2222 = new WizardPlan { Port = 2222, Profiles = 3 };
                // A rule with one port, or a new one, ends with the port sshd then uses: the old one is allowed only until then.
                foreach (var l in new[] { to2222.Summary(22, 3, true, true, "22", sshd(new[] { 22 }), true), to2222.Summary(22, 3, false, false, null, sshd(new[] { 22 }), true) })
                    if (!fwLine(l).EndsWith("allows port 2222 (and port 22 until you keep the new settings).") || fwLine(l).Contains("also")) throw new Exception("narrowed rule: " + fwLine(l));
                // Nothing is taken away from a rule with several ports, without verified ports or without a restart.
                foreach (var l in new[] { to2222.Summary(22, 3, true, true, "22,2200", sshd(new[] { 22 }), true), to2222.Summary(22, 3, true, true, "22", null, true),
                                          to2222.Summary(22, 3, true, true, "22", new ServerStateSnapshot(), true), new WizardPlan { Port = 2222, Profiles = 3 }.Summary(2222, 3, true, true, "22", sshd(new[] { 2222 }), false) })
                    if (!fwLine(l).EndsWith("also allows port 2222.")) throw new Exception("not narrowed: " + fwLine(l));
                // sshd listens where its ListenAddress says: the port changed here is allowed only until the settings are kept.
                var line = fwLine(to2222.Summary(22, 3, true, true, "22", sshd(new[] { 2200 }), true));
                if (!line.EndsWith("allows port 2200 (and port 22, 2222 until you keep the new settings).")) throw new Exception("ListenAddress: " + line);
                line = fwLine(new WizardPlan { Port = 22, Profiles = 3 }.Summary(22, 3, false, false, null, sshd(new[] { 22 }), true));
                if (!line.EndsWith("network profile(s) and allows port 22.")) throw new Exception("new rule on the same port: " + line);
                // The summary page asks the main window whether sshd_config changes (only then is sshd restarted and the rule narrowed).
                using (var w = new SetupWizard(2222, new FirewallRule { Enabled = true, Profiles = 3, Ports = "22" }, null, () => 0, () => { }, o => null))
                {
                    w.UseServerState(sshd(new[] { 2222 }));
                    foreach (var changes in new[] { true, false })
                    {
                        w.ChangesConfig = p => changes;
                        w.ShowPageForTest(4);
                        var summary = ((Label)Get(w, "_summary")).Text;
                        if (summary.Contains("(and port 22 until you keep the new settings)") != changes) throw new Exception("sshd_config changes " + changes + ": " + summary);
                    }
                }
                return null;
            });
            test("setup wizard: the summary follows sshd -T for the new sshd_config when a ListenAddress or an Include decides the port", () =>
            {
                Func<int[], ServerStateSnapshot> sshd = ports => new ServerStateSnapshot { Verified = true, ConfiguredPorts = ports, ListeningPorts = ports };
                Func<List<string>, string> fwLine = l => l.Single(x => x.StartsWith("The firewall rule"));
                var to2300 = new WizardPlan { Port = 2300, Profiles = 3 };
                // "ListenAddress 0.0.0.0:2222" and no Port line: the port shown (2222) stays, the Port line written is ignored.
                var line = fwLine(to2300.Summary(2222, 3, true, true, "2222", sshd(new[] { 2222 }), true, () => new[] { 2222 }));
                if (!line.EndsWith("allows port 2222 (and port 2300 until you keep the new settings).")) throw new Exception("ListenAddress with a port: " + line);
                // An Include sets Port 2222 and the main file has none: the Port line written adds 2300 to it.
                line = fwLine(to2300.Summary(22, 3, true, true, "2222", sshd(new[] { 2222 }), true, () => new[] { 2222, 2300 }));
                if (!line.EndsWith("allows port 2222, 2300.")) throw new Exception("Include with a Port: " + line);
                // Unknown (sshd -T failed): the earlier estimate, never an exception.
                line = fwLine(new WizardPlan { Port = 2222, Profiles = 3 }.Summary(22, 3, true, true, "22", sshd(new[] { 22 }), true, () => null));
                if (!line.EndsWith("allows port 2222 (and port 22 until you keep the new settings).")) throw new Exception("without a prediction: " + line);
                // When the Port line alone decides nothing, the main window says why.
                Func<string[], string> caveat = lines => MainForm.WizardPortCaveat(new SshdConfig { Lines = lines.ToList() });
                if (caveat(new[] { "ListenAddress 0.0.0.0:2222" }) == null || !caveat(new[] { "ListenAddress 0.0.0.0:2222" }).Contains("2222")) throw new Exception("ListenAddress with a port not named");
                if (caveat(new[] { "Include sshd_config.d/*.conf" }) == null) throw new Exception("an Include without a Port line not named");
                foreach (var plain in new[] { new[] { "Port 22", "Include sshd_config.d/*.conf" }, new[] { "ListenAddress ::" }, new[] { "Port 2222" } })
                    if (caveat(plain) != null) throw new Exception("a caveat for " + string.Join(" / ", plain));
                using (var w = new SetupWizard(2222, new FirewallRule { Enabled = true, Profiles = 3, Ports = "2222" }, null, () => 0, () => { }, o => null))
                {
                    // sshd -T agrees with the port shown, yet a ListenAddress decides it: the note still says so.
                    w.UseServerState(sshd(new[] { 2222 }), caveat(new[] { "ListenAddress 0.0.0.0:2222" }));
                    var note = ((Label)Get(w, "_portNote")).Text;
                    if (!note.Contains("ListenAddress") || note.Contains("sshd -T")) throw new Exception("note: " + note);
                }
                return null;
            });
            test("setup wizard: the port page says when sshd -T uses other ports than the Port line shown", () =>
            {
                using (var w = new SetupWizard(22, new FirewallRule { Enabled = true, Profiles = 3, Ports = "2222" }, null, () => 0, () => { }, o => null))
                {
                    w.UseServerState(new ServerStateSnapshot { Verified = true, ConfiguredPorts = new[] { 2222 }, ListeningPorts = new[] { 2222 } });
                    var note = ((Label)Get(w, "_portNote")).Text;
                    if (!note.Contains("2222") || !note.Contains("sshd -T")) throw new Exception("note: " + note);
                    Descendants(w).OfType<CheckBox>().Single(c => c.Text.StartsWith("Apply the recommended")).Checked = false;
                    w.ShowPageForTest(4);
                    var summary = ((Label)Get(w, "_summary")).Text;
                    if (!summary.StartsWith("Nothing to change")) throw new Exception("summary: " + summary);
                }
                using (var w = new SetupWizard(22, new FirewallRule { Enabled = true, Profiles = 3, Ports = "22" }, null, () => 0, () => { }, o => null))
                {
                    w.UseServerState(new ServerStateSnapshot { Verified = true, ConfiguredPorts = new[] { 22 }, ListeningPorts = new[] { 22 } });
                    if (((Label)Get(w, "_portNote")).Text.Length != 0) throw new Exception("a note although sshd uses the port shown");
                }
                return null;
            });
            test("hardening: Fix selected handles every selection, then opens the tab of the first fixed elsewhere", () =>
            {
                WithWindow(null, f =>
                {
                    var checks = (ListView)Get(f, "_lvChecks"); var h = checks.Handle;
                    foreach (var name in new[] { "Login restriction", "Firewall rule" })
                        checks.Items.Add(new ListViewItem(new[] { name, "WARN", "" }) { Tag = new CheckResult { Name = name, Status = "WARN", Detail = "" } });
                    foreach (ListViewItem item in checks.Items) item.Selected = true;
                    Wait(f, "FixSelectedChecks");
                    var tab = ((TabControl)Get(f, "_tabs")).SelectedTab; var status = ((ToolStripStatusLabel)Get(f, "_statusText")).Text;
                    if (tab != Get(f, "_pgSettings") || !status.Contains("AllowGroups") || !status.Contains("Firewall")) throw new Exception("tab " + tab.Text + ", status: " + status);
                });
                return null;
            });
            test("hardening: a fix that leaves sshd_config as it is (the value is in an Include) is not saved", () =>
            {
                var c = new SshdConfig { Lines = new List<string> { "Include C:/ProgramData/ssh/sshd_config.d/*.conf", "Port 22" } };
                var none = MainForm.IneffectiveFixes(c, new[] { "Key exchange", "Host key algorithms", "Ciphers", "Per-source penalties", "MaxAuthTries" });
                if (string.Join("|", none) != "Key exchange|Host key algorithms|Ciphers") throw new Exception("without effect: " + string.Join("|", none));
                if (c.Lines.Count != 2) throw new Exception("the check changed the configuration");
                c.Lines.Add("Ciphers aes128-cbc,aes256-ctr");
                if (MainForm.IneffectiveFixes(c, new[] { "Ciphers" }).Count != 0) throw new Exception("a Ciphers line in sshd_config is fixed there");
                return null;
            });
            test("settings: a choice written in another case is no unsaved change, and a later file replaces it", () =>
            {
                var dir = NewDir(tmpDir, "settings-case");
                File.WriteAllText(Path.Combine(dir, "sshd_config"), "Port 22\nLogLevel verbose\nPermitTTY No\nSyslogFacility local0\n");
                WithWindow(dir, f =>
                {
                    Wait(f, "LoadSettings", false);
                    if (f.SettingsEditedForTest() || f.FieldTextForTest("LogLevel") != "VERBOSE" || f.FieldTextForTest("PermitTTY") != "no")
                        throw new Exception("fresh window: edited " + f.SettingsEditedForTest() + ", LogLevel " + f.FieldTextForTest("LogLevel"));
                    // What another tab's save does: the file changed, and changes on the Settings tab are kept.
                    File.WriteAllText(Ssh.ConfigPath, "Port 22\nLogLevel INFO\nPermitTTY No\n");
                    Set(f, "_cfg", SshdConfig.Load());
                    Wait(f, "LoadSettings", true);
                    if (f.FieldTextForTest("LogLevel") != "INFO" || f.SettingsEditedForTest()) throw new Exception("after the file changed: LogLevel " + f.FieldTextForTest("LogLevel"));
                });
                return null;
            });
            test("preferences and alerts: a stored value beyond a field's range shows at its limit", () =>
            {
                var old = Prefs.FailedLoginThreshold;
                Prefs.FailedLoginThreshold = 50000;
                try { using (new MainForm()) { } }
                finally { Prefs.FailedLoginThreshold = old; }
                var dir = NewDir(tmpDir, "alerts-range");
                Directory.CreateDirectory(Path.Combine(dir, "manager"));
                File.WriteAllLines(Path.Combine(dir, "manager", "alerts.ini"), new[] { "block.threshold=5000", "block.minutes=5000", "alert.burst=200000", "block.allow=198.51.100.7" });
                WithWindow(dir, f =>
                {
                    Wait(f, "LoadAlerts");
                    foreach (var name in new[] { "_alThreshold", "_alWindow", "_alBurst" })
                    {
                        var n = (NumericUpDown)Get(f, name);
                        if (n.Value != n.Maximum) throw new Exception(name + " shows " + n.Value);
                    }
                    if (((TextBox)Get(f, "_alAllow")).Text != "198.51.100.7" || f.UnsavedTabsForTest().Contains("the Alerts tab")) throw new Exception("the tab was not loaded completely");
                });
                return null;
            });
            test("notification area: the Sessions tab's refresh keeps the icon's sshd state current", () =>
            {
                WithWindow(null, f =>
                {
                    using (var tray = new NotifyIcon { Text = "sshd: Running, 1 connection(s)" })
                    {
                        Set(f, "_tray", tray); Set(f, "_lastSshdStatus", "Running"); Set(f, "_expectedStateChange", DateTime.UtcNow);
                        try
                        {
                            var data = Activator.CreateInstance(typeof(MainForm).GetNestedType("SessionsData", BindingFlags.NonPublic), true);
                            Set(data, "List", new List<SessionInfo>()); Set(data, "Connections", new List<string[]>()); Set(data, "Sshd", new ServiceState { Status = "Stopped" });
                            Call(f, "ShowSessions", data);
                            if (!tray.Text.StartsWith("sshd: Stopped") || (string)Get(f, "_lastSshdStatus") != "Stopped") throw new Exception("icon: " + tray.Text);
                        }
                        finally { Set(f, "_tray", null); }
                    }
                });
                return null;
            });
            test("firewall and alerts: F5, and a reload after another change, keep the changes not applied yet", () =>
            {
                WithWindow(null, f =>
                {
                    ((TabControl)Get(f, "_tabs")).SelectedTab = (TabPage)Get(f, "_pgFirewall");
                    Wait(f, "LoadFirewall"); // a read-only query
                    var port = (NumericUpDown)Get(f, "_fwPort");
                    var edited = port.Value == 2222 ? 2223 : 2222;
                    port.Value = edited;
                    PressKey(f, System.Windows.Forms.Keys.F5);
                    if (port.Value != edited || !f.UnsavedTabsForTest().Contains("the Firewall tab")) throw new Exception("F5 discarded the edited port");
                    // What a port save, the wizard or a recovery do after they changed the rule.
                    Wait(f, "LoadFirewall");
                    if (port.Value != edited || !f.UnsavedTabsForTest().Contains("the Firewall tab")) throw new Exception("a reload discarded the edited port");
                });
                WithWindow(NewDir(tmpDir, "alerts-f5"), f =>
                {
                    Wait(f, "LoadAlerts");
                    ((TabControl)Get(f, "_tabs")).SelectedTab = (TabPage)Get(f, "_pgAlerts");
                    f.WaitForIdleForTest();
                    var host = (TextBox)Get(f, "_alHost"); host.Text = "unsaved.example.invalid";
                    PressKey(f, System.Windows.Forms.Keys.F5);
                    if (host.Text != "unsaved.example.invalid" || !f.UnsavedTabsForTest().Contains("the Alerts tab")) throw new Exception("F5 discarded the alert edits");
                });
                return null;
            });
            test("firewall: Apply warns about every port sshd uses that the rule would no longer allow", () =>
            {
                Func<string[], List<int>> ports = lines => MainForm.ExpectedPorts(new SshdConfig { Lines = lines.ToList() });
                var two = ports(new[] { "Port 22", "Port 2222" });
                Func<IEnumerable<int>, string, string> uncovered = (sshd, rule) => string.Join(",", MainForm.FirewallUncovered(sshd, rule));
                if (uncovered(two, "22") != "2222" || uncovered(two, "2222") != "22" || uncovered(two, "22,2222") != "" || uncovered(two, "2000-3000") != "22")
                    throw new Exception("two ports: " + uncovered(two, "22") + " / " + uncovered(two, "2222") + " / " + uncovered(two, "2000-3000"));
                var listen = ports(new[] { "Port 22", "ListenAddress 10.0.0.1:2200" });
                if (uncovered(listen, "22") != "2200" || listen[0] != 2200) throw new Exception("ListenAddress with a port: " + uncovered(listen, "22"));
                return null;
            });
            test("keyboard: Ctrl+1 to Ctrl+9 open the pages in the order the navigation shows them", () =>
            {
                WithWindow(null, f =>
                {
                    Set(f, "_suspendTabLoadsForTest", true);
                    var tree = (TreeView)Get(f, "_navigation");
                    var leaves = tree.Nodes.Cast<TreeNode>().SelectMany(g => g.Nodes.Cast<TreeNode>()).ToList();
                    foreach (var digit in new[] { 4, 5, 9 })
                    {
                        PressKey(f, System.Windows.Forms.Keys.Control | (System.Windows.Forms.Keys.D1 + digit - 1));
                        var shown = ((TabControl)Get(f, "_tabs")).SelectedTab;
                        if (shown != leaves[digit - 1].Tag) throw new Exception("Ctrl+" + digit + " opened " + shown.Text + ", the list shows " + leaves[digit - 1].Text);
                    }
                });
                return null;
            });
            test("dashboard: host keys shown in another order are the same keys (no rebuild, the selection stays)", () =>
            {
                var rows = new List<string[]> { new[] { "ssh_host_ecdsa_key", "ECDSA", "256", "SHA256:a" }, new[] { "ssh_host_ed25519_key", "ED25519", "256", "SHA256:b" } };
                var sorted = rows.AsEnumerable().Reverse().ToList();
                if (!MainForm.SameRows(rows, sorted)) throw new Exception("a sorted list counts as changed keys");
                if (MainForm.SameRows(rows, new List<string[]> { rows[0], new[] { "ssh_host_ed25519_key", "ED25519", "256", "SHA256:c" } })) throw new Exception("a changed fingerprint was missed");
                if (MainForm.SameRows(rows, rows.Take(1).ToList())) throw new Exception("a removed key was missed");
                return null;
            });
        }
    }
}

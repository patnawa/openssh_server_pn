// OpenSSH Server Manager for Windows: setup wizard

using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Windows.Forms;

namespace OpenSSHServerManager
{
    /// <summary>How accounts log in after the wizard.</summary>
    internal enum WizardLogin { Keep, AdministratorsKeyOnly, EveryoneKeyOnly }

    /// <summary>What the setup wizard was asked to do; MainForm applies it with the usual preview, backup and restart check.</summary>
    internal sealed class WizardPlan
    {
        public int Port; public int Profiles; public bool FirewallEnabled = true;
        public WizardLogin Login = WizardLogin.Keep;
        public bool Recommended;
        /// <summary>AllowGroups as typed ("administrators "openssh users""), or null to leave it.</summary>
        public string AllowGroups;

        /// <summary>The changes in words, for the summary page and the preview.</summary>
        public List<string> Describe(int currentPort, int currentProfiles, bool firewallExists)
        {
            var l = new List<string>();
            if (Port != currentPort) l.Add("sshd listens on port " + Port + " instead of " + currentPort + ".");
            if (!firewallExists || Profiles != currentProfiles || Port != currentPort) l.Add("The firewall rule allows port " + Port + " on the " + FirewallRule.ProfileText(Profiles) + " network profile(s).");
            if (Login == WizardLogin.AdministratorsKeyOnly) l.Add("Administrators log in with a public key only; other accounts as before.");
            if (Login == WizardLogin.EveryoneKeyOnly) l.Add("Every account logs in with a public key only (no Windows password over SSH).");
            if (Recommended) l.Add("Recommended settings: ClientAliveInterval 300, MaxAuthTries 4, LoginGraceTime 60, RequiredRSASize 2048, LogLevel VERBOSE, keyboard-interactive off.");
            if (AllowGroups != null) l.Add(AllowGroups.Length == 0 ? "Every account may log in (AllowGroups removed)." : "Only members of " + AllowGroups + " may log in (AllowGroups).");
            return l;
        }
    }

    /// <summary>
    /// First steps after installing: port and networks, a key for you, how accounts log in, recommended settings, who may
    /// log in. Nothing is written until Apply on the last page; the main window then saves with a preview, keeps a backup,
    /// restarts sshd and asks to keep the result.
    /// </summary>
    internal sealed class SetupWizard : ThemedForm
    {
        private readonly Panel[] _pages;
        private int _page;
        private readonly Button _back, _next, _cancel;
        private readonly Label _title, _step;
        private readonly NumericUpDown _port;
        private readonly CheckBox _dom, _priv, _pub, _recommended, _restrict;
        private readonly RadioButton _keep, _adminKeys, _allKeys;
        private readonly TextBox _groups;
        private readonly Label _keysState, _summary;
        private readonly Func<int> _myKeyCount;
        private readonly Action _addKey;
        private readonly int _currentPort, _currentProfiles; private readonly bool _fwExists;
        public WizardPlan Plan;

        public SetupWizard(int currentPort, FirewallRule fw, string allowGroups, Func<int> myKeyCount, Action addKey)
        {
            _myKeyCount = myKeyCount; _addKey = addKey; _currentPort = currentPort; _fwExists = fw != null;
            _currentProfiles = fw == null ? DefaultProfiles() : ((fw.Profiles & 0x7fffffff) == 0x7fffffff ? 7 : fw.Profiles & 7);
            Text = "Set up the SSH server"; StartPosition = FormStartPosition.CenterParent; FormBorderStyle = FormBorderStyle.FixedDialog; if (Ui.AppIcon != null) Icon = Ui.AppIcon;
            MinimizeBox = MaximizeBox = false; ShowInTaskbar = false; ClientSize = new Size(Ui.Px(720), Ui.Px(470)); Font = new Font("Segoe UI", Ui.Pt(9.5f));

            _title = new Label { Dock = DockStyle.Top, Height = Ui.Px(40), Font = new Font("Segoe UI", Ui.Pt(13f), FontStyle.Bold), Padding = new Padding(Ui.Px(12), Ui.Px(10), 0, 0) };
            _step = new Label { Dock = DockStyle.Top, Height = Ui.Px(24), ForeColor = Theme.Muted, Padding = new Padding(Ui.Px(14), 0, 0, 0) };
            var bar = new FlowLayoutPanel { Dock = DockStyle.Bottom, FlowDirection = FlowDirection.RightToLeft, Height = Ui.Px(50), Padding = new Padding(Ui.Px(8)) };
            _cancel = new Button { Text = "Cancel", DialogResult = DialogResult.Cancel, Width = Ui.Px(100), Height = Ui.Px(32) };
            _next = new Button { Text = "&Next >", Width = Ui.Px(110), Height = Ui.Px(32) };
            _back = new Button { Text = "< &Back", Width = Ui.Px(100), Height = Ui.Px(32) };
            bar.Controls.Add(_cancel); bar.Controls.Add(_next); bar.Controls.Add(_back);
            CancelButton = _cancel;

            // 1. Port and networks
            var p1 = Page("Port and networks", "sshd listens on this TCP port, and the Windows Firewall rule lets other computers reach it on these kinds of networks.");
            var portRow = new FlowLayoutPanel { AutoSize = true, Margin = new Padding(0, 6, 0, 6) };
            portRow.Controls.Add(new Label { Text = "Port:", AutoSize = true, Margin = new Padding(3, 7, 6, 3) });
            _port = new NumericUpDown { Minimum = 1, Maximum = 65535, Value = Math.Max(1, Math.Min(65535, currentPort)), Width = Ui.Px(90), AccessibleName = "Port" };
            portRow.Controls.Add(_port);
            portRow.Controls.Add(new Label { Text = "22 is the standard; another port only reduces the noise of scanners, it is not a protection.", AutoSize = true, ForeColor = Theme.Muted, Margin = new Padding(10, 7, 3, 3) });
            Add(p1, portRow);
            _dom = new CheckBox { Text = "Domain networks (the domain of a domain member)", AutoSize = true, Checked = (_currentProfiles & 1) != 0 };
            _priv = new CheckBox { Text = "Private networks (home, office)", AutoSize = true, Checked = (_currentProfiles & 2) != 0 };
            _pub = new CheckBox { Text = "Public networks (cafés, hotels, other untrusted networks)", AutoSize = true, Checked = (_currentProfiles & 4) != 0 };
            Add(p1, _dom); Add(p1, _priv); Add(p1, _pub);
            Add(p1, Note("A laptop should not accept SSH on public networks. A server on the internet uses the network profile of its connection, often Public."));

            // 2. Your key
            var p2 = Page("A key for you", "A public key logs you in without a password that could be guessed or phished. The private key stays on the computer you connect from.");
            _keysState = new Label { AutoSize = true, MaximumSize = new Size(Ui.Px(680), 0), Font = new Font("Segoe UI", Ui.Pt(9.5f), FontStyle.Bold), Margin = new Padding(3, 8, 3, 8) };
            Add(p2, _keysState);
            var addKeyButton = new Button { Text = "Add my public key (.pub file)...", AutoSize = true, MinimumSize = new Size(0, Ui.Px(32)) };
            addKeyButton.Click += (s, e) => { try { _addKey(); } catch (Exception ex) { MessageBox.Show(this, ex.Message, Program.AppName, MessageBoxButtons.OK, MessageBoxIcon.Warning); } UpdateKeys(); };
            Add(p2, addKeyButton);
            Add(p2, Note("No key yet? Create one on the computer you connect from (ssh-keygen -t ed25519) and add its .pub file here, or finish this wizard and use the Key generator tab. The next page offers key-only login only once a key is authorized for you."));

            // 3. Login methods
            var p3 = Page("How accounts log in", "Windows authentication means the Windows account name and password. With a key only, a stolen or guessed password is not enough.");
            _keep = new RadioButton { Text = "Keep the login methods as they are", AutoSize = true, Checked = true };
            _adminKeys = new RadioButton { Text = "Administrators with a public key only; other accounts as they are (recommended)", AutoSize = true };
            _allKeys = new RadioButton { Text = "Every account with a public key only", AutoSize = true };
            Add(p3, _keep); Add(p3, _adminKeys); Add(p3, _allKeys);
            Add(p3, Note("Detailed rules per user and group are on the Authentication tab."));

            // 4. Recommended settings and who may log in
            var p4 = Page("Protection", "Settings that make brute-force attacks and forgotten sessions less of a problem.");
            _recommended = new CheckBox { Text = "Apply the recommended settings (idle timeout, 4 tries per connection, 60 s to log in, RSA keys of 2048 bits and more, detailed log)", AutoSize = true, Checked = true, MaximumSize = new Size(Ui.Px(680), 0) };
            Add(p4, _recommended);
            _restrict = new CheckBox { Text = "Only members of these groups may log in over SSH (AllowGroups):", AutoSize = true, Checked = !string.IsNullOrEmpty(allowGroups), Margin = new Padding(3, 14, 3, 3) };
            Add(p4, _restrict);
            _groups = new TextBox { Width = Ui.Px(420), Text = string.IsNullOrEmpty(allowGroups) ? "administrators \"openssh users\"" : allowGroups, AccessibleName = "Groups that may log in", Margin = new Padding(24, 3, 3, 3) };
            Add(p4, _groups);
            Add(p4, Note("Separate the groups with spaces; put \"double quotes\" around a name with spaces. The group \"OpenSSH Users\" is created by the Windows OpenSSH feature on some systems; any local or domain group works. Saving warns you if your own account would be refused."));
            _restrict.CheckedChanged += (s, e) => _groups.Enabled = _restrict.Checked; _groups.Enabled = _restrict.Checked;

            // 5. Summary
            var p5 = Page("Summary", "Apply shows the changes to sshd_config first, keeps a backup, restarts sshd and then asks you to keep the result: if you do not answer, the previous settings come back.");
            _summary = new Label { AutoSize = true, MaximumSize = new Size(Ui.Px(680), 0), Margin = new Padding(3, 8, 3, 3) };
            Add(p5, _summary);

            _pages = new[] { p1, p2, p3, p4, p5 };
            foreach (var p in _pages) { p.Visible = false; Controls.Add(p); }
            Controls.Add(_step); Controls.Add(_title); Controls.Add(bar);
            _back.Click += (s, e) => ShowPage(_page - 1);
            _next.Click += (s, e) => { if (_page == _pages.Length - 1) Finish(); else ShowPage(_page + 1); };
            Load += (s, e) => { UpdateKeys(); ShowPage(0); };
        }

        /// <summary>Windows Server: every profile; Windows 10 and 11: Domain and Private (as the installer does).</summary>
        private static int DefaultProfiles()
        {
            try { using (var k = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\ProductOptions")) return (k != null && (k.GetValue("ProductType") as string ?? "WinNT") != "WinNT") ? 7 : 3; }
            catch { return 3; }
        }

        private Panel Page(string title, string intro)
        {
            var p = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown, WrapContents = false, Padding = new Padding(Ui.Px(14), Ui.Px(4), Ui.Px(14), 0), AutoScroll = true, Tag = title };
            p.Controls.Add(new Label { Text = intro, AutoSize = true, MaximumSize = new Size(Ui.Px(680), 0), Margin = new Padding(3, 3, 3, 10) });
            return p;
        }

        private static void Add(Panel p, Control c) { p.Controls.Add(c); }
        private static Label Note(string text) { return new Label { Text = text, AutoSize = true, ForeColor = Theme.Muted, MaximumSize = new Size(Ui.Px(680), 0), Margin = new Padding(3, 10, 3, 3) }; }

        private void UpdateKeys()
        {
            int n = _myKeyCount();
            _keysState.Text = n > 0 ? n + " key(s) are authorized for " + KeyGen.LoginName() + " (you). You can log in with a key." : "No key is authorized for " + KeyGen.LoginName() + " (you) yet.";
            _keysState.ForeColor = n > 0 ? Theme.Good : Theme.Warn;
            _adminKeys.Enabled = _allKeys.Enabled = n > 0;
            if (n == 0) _keep.Checked = true;
        }

        private void ShowPage(int i)
        {
            _page = Math.Max(0, Math.Min(_pages.Length - 1, i));
            for (int k = 0; k < _pages.Length; k++) _pages[k].Visible = k == _page;
            _title.Text = (string)_pages[_page].Tag;
            _step.Text = "Step " + (_page + 1) + " of " + _pages.Length;
            _back.Enabled = _page > 0;
            _next.Text = _page == _pages.Length - 1 ? "&Apply" : "&Next >";
            if (_page == _pages.Length - 1)
            {
                var plan = BuildPlan();
                var l = plan.Describe(_currentPort, _currentProfiles, _fwExists);
                _summary.Text = l.Count == 0 ? "Nothing to change: everything stays as it is." : string.Join("\n\n", l.Select(x => "• " + x));
            }
            AcceptButton = _next;
        }

        /// <summary>--screenshot: shows one page.</summary>
        internal void ShowPageForTest(int i) { ShowPage(i); }

        private WizardPlan BuildPlan()
        {
            int profiles = (_dom.Checked ? 1 : 0) | (_priv.Checked ? 2 : 0) | (_pub.Checked ? 4 : 0);
            return new WizardPlan
            {
                Port = (int)_port.Value, Profiles = profiles, FirewallEnabled = profiles != 0,
                Login = _allKeys.Checked ? WizardLogin.EveryoneKeyOnly : _adminKeys.Checked ? WizardLogin.AdministratorsKeyOnly : WizardLogin.Keep,
                Recommended = _recommended.Checked,
                AllowGroups = _restrict.Checked ? _groups.Text.Trim() : null,
            };
        }

        private void Finish()
        {
            var plan = BuildPlan();
            if (plan.Profiles == 0 && MessageBox.Show(this, "No network profile is ticked: the firewall rule is switched off and other computers cannot connect. Go on?", Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;
            if (plan.AllowGroups != null && plan.AllowGroups.Length > 0) { string err; if (SshdArgs.ParseTyped(plan.AllowGroups, out err) == null) { MessageBox.Show(this, "Groups: " + err + ".", Program.AppName, MessageBoxButtons.OK, MessageBoxIcon.Warning); return; } }
            Plan = plan;
            DialogResult = DialogResult.OK;
        }
    }
}

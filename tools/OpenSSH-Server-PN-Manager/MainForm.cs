// OpenSSH Server PN Manager: MainForm

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
using System.Threading.Tasks;
using System.Windows.Forms;
using Microsoft.Win32;

namespace OpenSSHServerPNManager
{
    /// <summary>
    /// Sizes for this screen. The manifest declares system DPI awareness, so Windows does not stretch the window: fonts
    /// in points grow with the DPI by themselves, and every size in pixels must grow with them. Sizes in the code are for
    /// 96 DPI (100%). --ui-scale and the window tests set another scale to check layouts without changing the display.
    /// </summary>
    internal static class Ui
    {
        public static readonly float SystemScale = ReadSystemScale();
        public static float Scale = SystemScale;
        private static float ReadSystemScale() { try { using (var g = Graphics.FromHwnd(IntPtr.Zero)) return g.DpiX / 96f; } catch { return 1f; } }
        public static int Px(int n) { return (int)Math.Round(n * Scale); }
        /// <summary>A font size in points: Windows scales points to the system DPI already; only a test scale adds to it.</summary>
        public static float Pt(float pt) { return pt * Scale / SystemScale; }
        /// <summary>A size for people: "812 bytes", "3.4 MB", "1.2 GB" (1 MB = 1024 × 1024 bytes).</summary>
        public static string Bytes(long n)
        {
            if (n < 1024) return n + " bytes";
            string[] units = { "KB", "MB", "GB", "TB" }; double v = n; int u = -1;
            while (v >= 1024 && u < units.Length - 1) { v /= 1024; u++; }
            return v.ToString(v < 10 ? "0.0" : "0", System.Globalization.CultureInfo.InvariantCulture) + " " + units[u];
        }

        private static Icon _appIcon; private static bool _appIconRead;
        /// <summary>The program icon with all its sizes (app.ico, embedded by build.ps1), or null in a build without it.</summary>
        public static Icon AppIcon
        {
            get
            {
                if (_appIconRead) return _appIcon;
                _appIconRead = true;
                try { using (var s = typeof(Ui).Assembly.GetManifestResourceStream("OpenSSHServerPNManager.app.ico")) if (s != null) _appIcon = new Icon(s); }
                catch (Exception ex) { Log.Error("Program icon", ex, false); }
                return _appIcon;
            }
        }
    }

    // ------------------------------------------------------------------------------------------
    // Main window
    // ------------------------------------------------------------------------------------------
    internal sealed partial class MainForm : ThemedForm
    {
        private readonly ThemedTabControl _tabs = new ThemedTabControl();
        private readonly StatusStrip _status = new StatusStrip();
        private readonly ToolStripStatusLabel _statusText = new ToolStripStatusLabel("Ready");
        private readonly ToolStripProgressBar _busy = new ToolStripProgressBar { Style = ProgressBarStyle.Marquee, Visible = false, Width = Ui.Px(90) };
        private readonly ToolTip _tips = new ToolTip { AutoPopDelay = 20000, InitialDelay = 400, ReshowDelay = 200 };
        private readonly System.Windows.Forms.Timer _timer = new System.Windows.Forms.Timer { Interval = 5000 };

        // dashboard
        private Label _lblSshd, _lblAgent, _lblVersion, _lblListen, _lblSessions, _lblSftp, _lblFirewall, _lblConfig;
        private Button _btnStart, _btnStop, _btnRestart;
        private ListView _lvHostKeys;
        // settings
        private readonly Dictionary<string, Control> _fields = new Dictionary<string, Control>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, Label> _hints = new Dictionary<string, Label>(StringComparer.OrdinalIgnoreCase);
        /// <summary>The text each settings field showed after loading; a field is written only when it differs.</summary>
        private readonly Dictionary<string, string> _shown = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        /// <summary>The effective-value hint of each field, shown when the field has no error.</summary>
        private readonly Dictionary<string, string> _hintText = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        private readonly ErrorProvider _errors = new ErrorProvider { BlinkStyle = ErrorBlinkStyle.NeverBlink };
        private string _pwshShown, _shellShown, _shellOptionShown, _rawShown = "";
        private Action<string, string> _writeDefaultShell = DefaultShell.Set;
        private bool _loadingSettings;
        private TabPage _pgSettings, _pgAuth, _pgSftp, _pgRaw;
        private Label _setPending, _rawPending, _setIncludeNote;
        private CheckBox _chkPwshSubsystem; private TextBox _txtPwshPath;
        private ComboBox _cmbShell; private TextBox _txtShellOption;
        private TextBox _rawEditor;
        private SshdConfig _cfg;
        // keys
        private ListView _lvAdminKeys, _lvUserKeys; private ComboBox _cmbUsers;
        // firewall
        private CheckBox _fwEnabled, _fwDomain, _fwPrivate, _fwPublic; private NumericUpDown _fwPort; private Label _fwState; private string _fwLoadedPorts;
        // logs
        private ListView _lvEvents; private TextBox _txtFilter, _txtFileLog; private NumericUpDown _numEvents;
        // hardening
        private ListView _lvChecks;
        // authentication
        private CheckBox _auPassword, _auKey, _auKerberos;
        private RadioButton _auEither, _auBoth, _auCustom;
        private Label _auSummary, _auRulesNote, _auResult, _auPending;
        private ListView _lvRules;
        private Button[] _auRuleButtons;
        private TextBox _auAccount;
        private AuthState _auState = new AuthState();          // as read from sshd_config
        private List<AuthRule> _auRules = new List<AuthRule>(); // being edited
        private bool _auLoading;
        // sftp
        private CheckBox _sfEnabled, _sfLog;
        private Label _sfServer, _sfRulesNote, _sfResult, _sfPending;
        private ListView _lvSftp;
        private Button[] _sfRuleButtons;
        private TextBox _sfAccount;
        private SftpState _sfFile = new SftpState();            // as read from sshd_config
        private List<SftpRule> _sfRules = new List<SftpRule>(); // being edited
        private bool _sfLoading;

        // State colours of the current palette (Theme): light, dark or high contrast.
        private static Color Green { get { return Theme.Good; } }
        private static Color Red { get { return Theme.Bad; } }
        private static Color Orange { get { return Theme.Warn; } }

        private readonly bool _clientOnly;

        public MainForm() : this(false) { }

        public MainForm(bool clientOnly)
        {
            _clientOnly = clientOnly;
            Text = Program.AppName + " " + Program.AppVersion + (clientOnly ? " — Client workspace" : " — Server administration");
            Font = new Font("Segoe UI", Ui.Pt(9.5f));
            AutoScaleMode = AutoScaleMode.Font;
            StartPosition = FormStartPosition.CenterScreen;
            MinimumSize = new Size(Ui.Px(1080), Ui.Px(640));
            Size = new Size(Ui.Px(1220), Ui.Px(760));
            if (Ui.AppIcon != null) Icon = Ui.AppIcon;
            else { try { Icon = Icon.ExtractAssociatedIcon(Ssh.Exe("sshd.exe")); } catch { } }

            _tabs.Dock = DockStyle.Fill;
            if (clientOnly)
            {
                _tabs.TabPages.Add(_pgClient = BuildClient());
                _tabs.TabPages.Add(_pgAbout = BuildAbout());
            }
            else
            {
            _tabs.TabPages.Add(_pgDashboard = BuildDashboard());
            _tabs.TabPages.Add(_pgSessions = BuildSessions());
            _tabs.TabPages.Add(_pgSettings = BuildSettings());
            _tabs.TabPages.Add(_pgAuth = BuildAuthentication());
            _tabs.TabPages.Add(_pgSftp = BuildSftp());
            _tabs.TabPages.Add(_pgPartners = BuildPartners());
            _tabs.TabPages.Add(_pgRaw = BuildRawEditor());
            _tabs.TabPages.Add(_pgKeys = BuildKeys());
            _tabs.TabPages.Add(_pgKeyGen = BuildKeyGen());
            _tabs.TabPages.Add(_pgClient = BuildClient());
            _tabs.TabPages.Add(_pgFirewall = BuildFirewall());
            _tabs.TabPages.Add(_pgLogs = BuildLogs());
            _tabs.TabPages.Add(_pgAlerts = BuildAlerts());
            _tabs.TabPages.Add(_pgHardening = BuildHardening());
            _tabs.TabPages.Add(_pgAbout = BuildAbout());
            }
            _tabs.SelectedIndexChanged += async (s, e) => await SafeAsync(async () => await OnTabSelected());
            _tabs.AccessibleName = "Sections";

            _cancelButton.Click += (s, e) => { var c = _cancel; if (c != null) { c.Cancel(); Status("Cancelling..."); } };
            _status.Items.Add(_statusText); _status.Items.Add(_busy); _status.Items.Add(_cancelButton);
            Controls.Add(BuildNavigation()); Controls.Add(_status);
            if (clientOnly)
            {
                var administration = new ToolStripButton("Manage this server…");
                administration.Click += (s, e) => Elevation.Relaunch("--server");
                _status.Items.Add(administration);
            }
            KeyPreview = true;

            _timer.Tick += (s, e) =>
            {
                // In the background: service, network, firewall and process queries can take seconds, and the
                // window must stay responsive meanwhile. The notification area icon needs the service state even
                // while another tab (or no window) is shown.
                if (_tabs.SelectedTab == _pgSessions) RefreshInBackground(CollectSessions, ShowSessions);
                else if (_tabs.SelectedTab == _pgDashboard || _tray != null) RefreshInBackground(CollectDashboard, ShowDashboard);
            };
            Shown += async (s, e) =>
            {
                if (_clientOnly) { await SafeAsync(LoadClient); return; }
                await SafeAsync(LoadEverything); _timer.Start(); await SafeAsync(CheckPendingRecovery); await SafeAsync(OfferWizard, false);
            };
            FormClosing += (s, e) =>
            {
                if (_busyDepth > 0 && e.CloseReason == CloseReason.UserClosing) { e.Cancel = true; Status("Wait until the running operation has finished"); return; }
                if (!_clientOnly && !Program.Unattended && e.CloseReason == CloseReason.UserClosing)
                {
                    var unsaved = UnsavedTabs();
                    if (unsaved.Count > 0 && MessageBox.Show(this, "Changes on " + string.Join(" and ", unsaved) + " are not saved.\n\nClose anyway and lose them?", Program.AppName,
                            MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes) { e.Cancel = true; return; }
                }
                _timer.Stop();
                StopWatchers();
            };
            if (!_clientOnly) InitTray();
            // "Like Windows" follows a change of the Windows colours (dark mode, high contrast) while the window is open.
            SystemEvents.UserPreferenceChanged += OnUserPreferenceChanged;
            FormClosed += (s, e) => SystemEvents.UserPreferenceChanged -= OnUserPreferenceChanged;
        }

        private void OnUserPreferenceChanged(object sender, UserPreferenceChangedEventArgs e)
        {
            if (Program.Unattended) return;
            var want = Theme.For(Prefs.Theme);
            if (want.Dark == Theme.Current.Dark && want.HighContrast == Theme.Current.HighContrast) return;
            // Not in the middle of an operation: switching colours recreates the tab control's window. EndBusy applies it then.
            try { BeginInvoke((Action)(() => { if (_busyDepth > 0) _themePending = true; else Safe(ApplyTheme, false); })); } catch (InvalidOperationException) { }
        }

        private bool _themePending;

        private TabPage _pgDashboard, _pgSessions, _pgKeys, _pgKeyGen, _pgClient, _pgFirewall, _pgLogs, _pgHardening, _pgAbout;

        /// <summary>Keyboard shortcuts: Ctrl+S saves the tab shown, F5 refreshes it, Ctrl+F finds in the sshd_config text, Ctrl+1 to Ctrl+9 open tabs.</summary>
        protected override bool ProcessCmdKey(ref Message msg, System.Windows.Forms.Keys keyData)
        {
            if (_busyDepth == 0)
            {
                var tab = _tabs.SelectedTab;
                switch (keyData)
                {
                    case System.Windows.Forms.Keys.Control | System.Windows.Forms.Keys.S:
                        if (tab == _pgSettings) RunUi(async () => await SaveSettings(false));
                        else if (tab == _pgRaw) RunUi(async () => await SaveRaw());
                        else if (tab == _pgAuth) RunUi(ApplyAuth);
                        else if (tab == _pgSftp) RunUi(ApplySftp);
                        else if (tab == _pgFirewall) RunUi(ApplyFirewall);
                        else if (tab == _pgAlerts) RunUi(SaveAlerts);
                        else return base.ProcessCmdKey(ref msg, keyData);
                        return true;
                    case System.Windows.Forms.Keys.F5:
                        if (tab == _pgDashboard) RunUi(RefreshDashboard);
                        else if (tab == _pgSessions) RunUi(RefreshSessions);
                        else if (tab == _pgLogs) RunUi(LoadLogs);
                        else if (tab == _pgHardening) RunUi(RunChecks);
                        else if (tab == _pgKeys) RunUi(LoadKeys);
                        else if (tab == _pgFirewall) { if (ReloadDiscards(FirewallEdited(), "firewall")) RunUi(() => LoadFirewallRule(true)); }
                        else if (tab == _pgPartners) RunUi(LoadPartners);
                        else if (tab == _pgClient) RunUi(LoadClient);
                        else if (tab == _pgAlerts) { if (ReloadDiscards(AlertsEdited(), "alert")) RunUi(LoadAlerts); }
                        else return base.ProcessCmdKey(ref msg, keyData);
                        return true;
                    case System.Windows.Forms.Keys.Control | System.Windows.Forms.Keys.F:
                        if (tab == _pgRaw) { ShowFind(); return true; }
                        break;
                    case System.Windows.Forms.Keys.F3:
                    case System.Windows.Forms.Keys.Shift | System.Windows.Forms.Keys.F3:
                        if (tab == _pgRaw) { FindNext((keyData & System.Windows.Forms.Keys.Shift) == 0); return true; }
                        break;
                }
                var digit = keyData & ~System.Windows.Forms.Keys.Control;
                if ((keyData & System.Windows.Forms.Keys.Control) != 0 && (keyData & (System.Windows.Forms.Keys.Alt | System.Windows.Forms.Keys.Shift)) == 0 && digit >= System.Windows.Forms.Keys.D1 && digit <= System.Windows.Forms.Keys.D9)
                {
                    // In the order of the navigation list, the only order shown (the tab headers are hidden).
                    int i = digit - System.Windows.Forms.Keys.D1;
                    if (i < _compactNavigation.Items.Count) { _tabs.SelectedTab = ((NavigationChoice)_compactNavigation.Items[i]).Page; SyncNavigation(); _tabs.SelectedTab.SelectNextControl(null, true, true, true, false); return true; }
                }
            }
            return base.ProcessCmdKey(ref msg, keyData);
        }

        /// <summary>F5 on a tab with changes not saved: true to reload and lose them (asked, default No; never in the unattended modes).</summary>
        private bool ReloadDiscards(bool edited, string what)
        {
            if (!edited) return true;
            if (Program.Unattended) { Status("Not reloaded: the " + what + " changes are not saved"); return false; }
            return MessageBox.Show(this, "Discard the " + what + " changes not saved yet and reload?", Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Question, MessageBoxDefaultButton.Button2) == DialogResult.Yes;
        }

        // ---------------- test hooks (used by --screenshot) ----------------
        public int TabCount { get { return _tabs.TabPages.Count; } }
        public string TabName(int i) { return _tabs.TabPages[i].Text; }
        public void SelectTabForTest(int i) { _tabs.SelectedIndex = i; AsyncUiTest.Wait(() => SafeAsync(async () => await OnTabSelected(), false)); }
        /// <summary>--screenshot: two example rules on the Authentication tab, in the window only (nothing is saved).</summary>
        public void ShowAuthExampleForTest()
        {
            if (_auState.RulesProblem != null) return;
            _auRules = new List<AuthRule>
            {
                new AuthRule { IsGroup = true, Name = "administrators", Methods = new AuthMethods { Password = false, PublicKey = true } },
                new AuthRule { Name = "backup", Methods = new AuthMethods { Password = true, PublicKey = true, RequireBoth = true } },
            };
            FillRules(); UpdateAuthUi();
        }
        /// <summary>--screenshot: SFTP with transfer logging and two example SFTP-only accounts, in the window only (nothing is saved).</summary>
        /// <summary>--screenshot: drops the example rules of the Authentication tab, as its Undo changes does.</summary>
        public void UndoAuthForTest() { LoadAuth(); }
        /// <summary>--screenshot: the Partners tab, set up, with example partners (in the window only; nothing is read or written).</summary>
        public void ShowPartnersExampleForTest()
        {
            _ptSetupState = new PartnerSetupState { Root = @"D:\SFTP" };
            var today = DateTime.Today;
            _partners = new List<PartnerAccount>
            {
                new PartnerAccount { Name = "acme", FullName = "Somchai K.", Company = "ACME Logistics Co., Ltd.", LastLogon = today.AddHours(9.5), KeyCount = 1 },
                new PartnerAccount { Name = "globex-audit", FullName = "Jane Doe", Company = "Globex Audit", ReadOnly = true, Expires = today.AddDays(46), LastLogon = today.AddDays(-3).AddHours(14) },
                new PartnerAccount { Name = "initech", FullName = "Peter G.", Company = "Initech", KeyOnly = true, KeyCount = 2, LastLogon = today.AddDays(-1).AddHours(8) },
                new PartnerAccount { Name = "umbrella", FullName = "", Company = "Umbrella Trading", Disabled = true, LastLogon = today.AddDays(-40) },
            };
            _ptMonth = new Dictionary<string, TransferTotals>(StringComparer.OrdinalIgnoreCase)
            {
                { "acme", new TransferTotals { User = "acme", Uploads = 42, Downloads = 17 } },
                { "globex-audit", new TransferTotals { User = "globex-audit", Downloads = 9 } },
                { "initech", new TransferTotals { User = "initech", Uploads = 128, Downloads = 3 } },
            };
            _ptLoaded = true;
            FillPartners("acme");
        }
        /// <summary>--screenshot: the Alerts tab filled in with example settings (nothing is saved).</summary>
        public void ShowAlertsExampleForTest()
        {
            _alOn.Checked = true; _alHost.Text = "smtp.example.com"; _alPort.Value = 587; _alTls.Checked = true;
            _alUser.Text = "sftp-alerts@example.com"; _alPassword.Text = "example"; _alFrom.Text = "sftp-alerts@example.com"; _alAdmins.Text = "it-team@example.com";
            _alHook.Text = "https://example.invalid/webhook"; _alTeams.Checked = true; _alAllow.Text = "203.0.113.0/24, 198.51.100.7";
            _alState.Text = "On: the tasks " + Agent.WatchTask + " and " + Agent.DailyTask + " run the manager as SYSTEM. Last entry of the agent log: " +
                            DateTime.Today.AddHours(9.5).ToString("yyyy-MM-dd HH:mm:ss", System.Globalization.CultureInfo.InvariantCulture) + "  blocked 192.0.2.23 until " +
                            DateTime.Today.AddHours(10.5).ToString("yyyy-MM-dd HH:mm", System.Globalization.CultureInfo.InvariantCulture) + " after 12 failed logins (strike 1)";
            _alState.ForeColor = Theme.Muted;
        }
        /// <summary>--screenshot: the Key generator tab showing an example key, as after Load key (the SFTP example is dropped first).</summary>
        public void ShowKeyExampleForTest(KeyFileInfo key) { LoadSftp(); ShowKey(key, "Loaded " + key.FileName + ".", true, Theme.Text); }
        public void ShowSftpExampleForTest()
        {
            if (_sfFile.RulesProblem != null) return;
            _sfEnabled.Checked = true; _sfLog.Checked = true;
            _sfRules = new List<SftpRule>
            {
                new SftpRule { Name = "partner", Folder = "C:\\SFTP\\%u" },
                new SftpRule { IsGroup = true, Name = "sftp readers", Folder = "D:\\Published", ReadOnly = true },
            };
            FillSftpRules(); UpdateSftpUi();
        }

        // ---------------- test hooks (used by --selftest, with Ssh.ConfigDirOverride) ----------------
        public void SetSettingForTest(string key, string value)
        {
            var c = _fields[key];
            if (c is ComboBox) { var cb = (ComboBox)c; cb.SelectedIndex = Math.Max(0, cb.Items.IndexOf(value)); } else ((TextBox)c).Text = value;
        }
        /// <summary>Save on the Settings tab; the error message, or null when it saved.</summary>
        public string SaveSettingsForTest() { try { AsyncUiTest.Wait(() => SaveSettings(false)); return null; } catch (ConfigException ex) { return ex.Message; } }
        public void ReloadFromFileForTest() { AsyncUiTest.Wait(() => ReloadFromFile()); }
        public void TickPasswordForTest(bool on) { _auPassword.Checked = on; }
        public string FieldTextForTest(string key) { return FieldValue(FieldDefs.First(f => f.Key == key)); }
        public string FieldErrorForTest(string key) { return _errors.GetError(_fields[key]); }
        public bool SettingsEditedForTest() { return SettingsEdited(); }
        public bool RawEditedForTest() { return RawEdited(); }
        public string RawTextForTest() { return _rawEditor.Text; }
        public void SetRawTextForTest(string text) { _rawEditor.Text = text; }
        public string RawNoteForTest() { return _rawPending.Text; }
        public List<string> UnsavedTabsForTest() { return UnsavedTabs(); }
        public bool HasAboutIconForTest() { return _tabs.TabPages.Cast<TabPage>().Any(p => p.Text == "About" && Descendants(p).OfType<PictureBox>().Any(b => b.Image != null && b.AccessibleName == "Program icon")); }
        /// <summary>What every other tab does after it saved sshd_config: the window adopts the file.</summary>
        public void OtherTabSavedForTest() { AsyncUiTest.Wait(() => ReloadFromFile(false, false)); }
        /// <summary>Text boxes, lists and the like without a name for screen readers.</summary>
        public List<string> UnnamedInputsForTest()
        {
            return _tabs.TabPages.Cast<TabPage>().SelectMany(p => Descendants(p).Where(c => (c is TextBoxBase || c is ComboBox || c is NumericUpDown || c is ListView) && !(c.Parent is UpDownBase) && string.IsNullOrEmpty(c.AccessibleName))
                .Select(c => p.Text + ": " + c.GetType().Name)).ToList();
        }
        /// <summary>Time on the window's thread: a refresh done there, and starting one in the background (which is then awaited).</summary>
        public TimeSpan[] BackgroundRefreshForTest()
        {
            var sw = Stopwatch.StartNew(); AsyncUiTest.Wait(() => RefreshDashboard()); var direct = sw.Elapsed;
            // A standalone DoEvents pump can uninstall its WindowsForms synchronization context.
            // Production timer ticks have Application.Run's context; restore it for this direct test call.
            AsyncUiTest.EnsureContext();
            _lblVersion.Text = "...";
            sw.Restart();
            if (!RefreshInBackground(CollectDashboard, ShowDashboard)) throw new Exception("a background refresh was already running");
            var start = sw.Elapsed;
            if (RefreshInBackground(CollectDashboard, ShowDashboard)) throw new Exception("a second refresh started while one was running");
            while (_refreshRunning && sw.ElapsedMilliseconds < 30000) { Application.DoEvents(); Thread.Sleep(10); }
            if (_refreshRunning) throw new Exception("the background refresh did not finish within 30 s");
            if (_lblVersion.Text == "...") throw new Exception("the background refresh did not show its result");
            return new[] { direct, start };
        }
        public bool AuthEditedForTest() { return AuthEdited(); }
        public bool SftpEditedForTest() { return SftpEdited(); }
        /// <summary>sshd_config as Apply on the SFTP tab would write it.</summary>
        public SshdConfig SftpCandidateForTest() { return SftpCandidate(); }
        /// <summary>A value of the configuration every tab works on (what the next save of any tab starts from).</summary>
        public string WorkingValueForTest(string key) { return _cfg.Get(key); }
        /// <summary>sshd_config as Apply on the Authentication tab would write it.</summary>
        public SshdConfig AuthCandidateForTest() { return AuthCandidate(); }
        /// <summary>Switches the colours as the Appearance preference does, and reports those of a list, a button, a text box and the window.</summary>
        public Color[] ThemeForTest(string pref, out bool ownerDrawnList, out FlatStyle buttonStyle)
        {
            Prefs.Theme = pref; ApplyTheme();
            var all = _tabs.TabPages.Cast<TabPage>().SelectMany(p => Descendants(p)).ToList();
            var lv = all.OfType<ListView>().First(); var b = all.OfType<Button>().First(); var tb = all.OfType<TextBox>().First(t => !t.ReadOnly && !t.Multiline);
            ownerDrawnList = lv.OwnerDraw; buttonStyle = b.FlatStyle;
            return new[] { lv.BackColor, tb.BackColor, BackColor, _tabs.TabPages[0].BackColor };
        }
        public List<string> TabNamesForTest() { return _tabs.TabPages.Cast<TabPage>().Select(p => p.Text).ToList(); }

        /// <summary>
        /// Text that does not fit, on every tab: a button narrower than its text, a control wider than its table column
        /// (it runs into the next one), or a control that runs past the right edge of its row.
        /// </summary>
        private bool _suspendTabLoadsForTest;
        public List<string> ClippedTextForTest()
        {
            if (!Program.Unattended) throw new InvalidOperationException("Layout traversal is only available to the unattended test harness.");
            WaitForIdleForTest();
            var selected = _tabs.SelectedTab; bool suspended = _suspendTabLoadsForTest;
            _suspendTabLoadsForTest = true;
            try
            {
            var found = new List<string>();
            for (int i = 0; i < _tabs.TabPages.Count; i++)
            {
                _tabs.SelectedIndex = i; WaitForIdleForTest(); Application.DoEvents();
                var page = _tabs.TabPages[i];
                foreach (var c in Descendants(page))
                {
                    if (!c.Visible || c.Width == 0) continue;
                    var text = (c.Text ?? "").Replace("\n", " ");
                    var where = page.Text + ": " + c.GetType().Name + " \"" + (text.Length > 40 ? text.Substring(0, 40) + "..." : text) + "\"";
                    if (c.Font.SizeInPoints < Font.SizeInPoints * 0.95f && text.Length > 0) found.Add(where + " has a " + c.Font.SizeInPoints.ToString("0.#") + " pt font, the window " + Font.SizeInPoints.ToString("0.#") + " pt");
                    var b = c as Button;
                    if (b != null && TextRenderer.MeasureText(b.Text, b.Font).Width + Ui.Px(10) > b.Width) found.Add(where + " is " + b.Width + " px wide for its text");
                    var t = c.Parent as TableLayoutPanel;
                    if (t != null && c.Dock == DockStyle.None)
                    {
                        var widths = t.GetColumnWidths(); int col = t.GetColumn(c), span = Math.Max(1, t.GetColumnSpan(c)), avail = 0;
                        for (int k = Math.Max(0, col); k < Math.Min(widths.Length, col + span); k++) avail += widths[k];
                        if (col >= 0 && c.Width + c.Margin.Horizontal > avail + 1) found.Add(where + " needs " + (c.Width + c.Margin.Horizontal) + " px, its column has " + avail);
                    }
                    var fl = c.Parent as FlowLayoutPanel;
                    if (fl != null && c.Right + c.Margin.Right > fl.ClientSize.Width + 1 && fl.Parent != null && fl.Width >= fl.Parent.ClientSize.Width - fl.Margin.Horizontal - 1)
                        found.Add(where + " ends at " + (c.Right + c.Margin.Right) + " px, its row is " + fl.ClientSize.Width);
                }
            }
            return found;
            }
            finally { _tabs.SelectedTab = selected; _suspendTabLoadsForTest = suspended; }
        }

        private static IEnumerable<Control> Descendants(Control root)
        {
            foreach (Control c in root.Controls) { yield return c; foreach (var d in Descendants(c)) yield return d; }
        }

        // ---------------- helpers ----------------
        private void Status(string s) { _statusText.Text = DateTime.Now.ToString("HH:mm:ss") + "  " + s; }

        private static Button Btn(string text, EventHandler onClick, int width = 130)
        {
            // Never narrower than the text: at 150% and more, text grows with the font.
            int need; using (var f = new Font("Segoe UI", Ui.Pt(9.5f))) need = TextRenderer.MeasureText(text, f).Width + Ui.Px(20);
            var b = new Button { Text = text, AutoSize = false, Width = Math.Max(Ui.Px(width), need), Height = Ui.Px(32), Margin = new Padding(4) };
            b.Click += onClick; return b;
        }
        private static Label Lbl(string text, bool bold = false) { var l = new Label { Text = text, AutoSize = true, Margin = new Padding(4, 8, 4, 4) }; if (bold) l.Font = BoldFont();  return l; }
        /// <summary>The window's font in bold. A new control has the system default font until it is placed in the window, so a font derived from it would be smaller than the window's.</summary>
        private static Font BoldFont() { return new Font("Segoe UI", Ui.Pt(9.5f), FontStyle.Bold); }
        private static FlowLayoutPanel Flow() { return new FlowLayoutPanel { AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, WrapContents = true, Dock = DockStyle.Top, Padding = new Padding(4) }; }

        /// <summary>
        /// Keeps the rows of a top-down panel within its width, whatever the screen and the scale: long labels and check
        /// boxes wrap, and a row of controls goes on on the next line. The width left for a vertical scroll bar is kept
        /// free, so the layout does not change when one appears.
        /// </summary>
        private static void FitRows(FlowLayoutPanel root)
        {
            var own = new Dictionary<Control, int>(); // a text's own width limit, kept where it is the smaller one
            Action<Control, int> limit = (c, width) =>
            {
                int o; if (!own.TryGetValue(c, out o)) own[c] = o = c.MaximumSize.Width;
                c.MaximumSize = new Size(o > 0 ? Math.Min(o, width) : width, 0);
            };
            Action fit = () =>
            {
                int w = root.Width - SystemInformation.VerticalScrollBarWidth - root.Padding.Horizontal - Ui.Px(4);
                if (w < Ui.Px(240)) return;
                root.SuspendLayout();
                foreach (Control c in root.Controls)
                {
                    int cw = w - c.Margin.Horizontal;
                    var row = c as FlowLayoutPanel;
                    if (row != null)
                    {
                        row.WrapContents = true; row.AutoSizeMode = AutoSizeMode.GrowAndShrink; row.MaximumSize = new Size(cw, 0);
                        foreach (Control inner in row.Controls)
                            if (inner is Label || inner is CheckBox) limit(inner, Math.Max(Ui.Px(120), cw - row.Padding.Horizontal - inner.Margin.Horizontal));
                    }
                    else if (c is Label || c is CheckBox) limit(c, cw);
                }
                root.ResumeLayout(true);
            };
            root.SizeChanged += (s, e) => fit();
            fit();
        }
        private static ListView Lv(params string[] cols)
        {
            var lv = new ListView { View = View.Details, FullRowSelect = true, GridLines = true, Dock = DockStyle.Fill, HideSelection = false, MultiSelect = false };
            foreach (var c in cols) { var parts = c.Split('|'); lv.Columns.Add(parts[0], Ui.Px(parts.Length > 1 ? int.Parse(parts[1]) : 150)); }
            lv.ColumnClick += (s, e) => ListSorter.Toggle((ListView)s, e.Column);
            return lv;
        }

        private async Task LoadEverything()
        {
            await BusyAsync("Loading...", async () =>
            {
                _cfg = await BgAsync("Reading the configuration and Includes...", () => SshdConfig.Load());
                await RefreshDashboard();
                await LoadSettings();
                LoadAuth();
                LoadSftp();
                LoadRaw();
                await LoadKeys();
                await LoadFirewall();
            });
            Status("Ready. Configuration: " + Ssh.ConfigPath);
        }

        private async Task OnTabSelected()
        {
            if (Program.Unattended && _suspendTabLoadsForTest) return;
            // By page, not by caption: captions change ("Settings *") and could be translated.
            var tab = _tabs.SelectedTab;
            if (tab == null) return;
            if (tab == _pgDashboard) await RefreshDashboard();
            else if (tab == _pgSessions) await RefreshSessions();
            else if (tab == _pgLogs) { if (_lvEvents.Items.Count == 0) await LoadLogs(); }
            else if (tab == _pgHardening) { if (_lvChecks.Items.Count == 0) await RunChecks(); }
            else if (tab == _pgClient) { if (!_clientLoaded) await LoadClient(); }
            else if (tab == _pgPartners) { if (!_ptLoaded) await LoadPartners(); }
            else if (tab == _pgAlerts) { if (!_alLoaded) await LoadAlerts(); }
            else if (tab == _pgAbout) { if (!_aboutLoaded) await LoadAboutVersions(); }
        }

        // ---------------- Dashboard ----------------
        private TabPage BuildDashboard()
        {
            var page = new TabPage("Dashboard");
            var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 3, Padding = new Padding(8) };
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize)); root.RowStyles.Add(new RowStyle(SizeType.AutoSize)); root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

            var grid = new TableLayoutPanel { AutoSize = true, ColumnCount = 2, Dock = DockStyle.Top };
            grid.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, Ui.Px(170))); grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            Func<string, Label> row = (caption) =>
            {
                grid.Controls.Add(Lbl(caption, true));
                var v = new Label { AutoSize = true, Margin = new Padding(4, 8, 4, 4), Text = "..." }; grid.Controls.Add(v); return v;
            };
            _lblSshd = row("SSH server (sshd)"); _lblSshd.Font = new Font(Font.FontFamily, Ui.Pt(11f), FontStyle.Bold);
            _lblAgent = row("Authentication agent"); _lblVersion = row("Version"); _lblListen = row("Listening on");
            _lblSessions = row("Active sessions"); _lblSftp = row("SFTP"); _lblFirewall = row("Firewall rule"); _lblConfig = row("Configuration");
            root.Controls.Add(grid, 0, 0);

            var actions = Flow();
            _btnStart = Btn("Start", async (s, e) => await ServiceAction("start"));
            _btnStop = Btn("Stop", async (s, e) => await ServiceAction("stop"));
            _btnRestart = Btn("Restart", async (s, e) => await ServiceAction("restart"));
            actions.Controls.Add(_btnStart); actions.Controls.Add(_btnStop); actions.Controls.Add(_btnRestart);
            actions.Controls.Add(Btn("Test configuration", async (s, e) => await SafeAsync(TestLiveConfig), 150));
            actions.Controls.Add(Btn("Refresh", async (s, e) => await SafeAsync(RefreshDashboard), 100));
            actions.Controls.Add(Btn("Open config folder", (s, e) => Proc.OpenExternal("explorer.exe", "\"" + Ssh.ConfigDir + "\""), 150));
            actions.Controls.Add(Btn("Event Viewer", (s, e) => Proc.OpenExternal("eventvwr.exe", "/c:\"" + EventLogs.LogName + "\""), 120));
            actions.Controls.Add(Btn("Add my public key", async (s, e) => await SafeAsync(QuickAddMyKey), 150));
            actions.Controls.Add(Btn("Generate missing host keys", async (s, e) => await SafeAsync(GenerateHostKeys), 200));
            actions.Controls.Add(Btn("Connect (ssh localhost)", (s, e) => Proc.OpenUnelevated(Ssh.Exe("ssh.exe"), "-p " + (_cfg == null ? 22 : _cfg.EffectivePort) + " localhost", true), 170));
            actions.Controls.Add(Btn("Setup wizard...", async (s, e) => await SafeAsync(RunWizard), 130));
            _tips.SetToolTip(_btnRestart, "Stops and starts sshd, which then reads sshd_config again. Connected sessions stay connected: each runs in its own sshd-session.exe process.");
            _tips.SetToolTip(actions.Controls[3], "Runs sshd -t against the live sshd_config and reports syntax errors.");
            root.Controls.Add(actions, 0, 1);

            var keysBox = new GroupBox { Text = "Host keys (server identity fingerprints)", Dock = DockStyle.Fill, Padding = new Padding(6) };
            _lvHostKeys = Lv("File|220", "Type|140", "Bits|60", "SHA256 fingerprint|520"); _lvHostKeys.AccessibleName = "Host keys"; // Type fits MLDSA44-ED25519
            keysBox.Controls.Add(_lvHostKeys);
            root.Controls.Add(keysBox, 0, 2);
            page.Controls.Add(root);
            return page;
        }

        /// <summary>What the dashboard shows. Collected without touching any control, so it can run on a background thread.</summary>
        private sealed class DashboardData
        {
            public ServiceState Sshd, Agent; public string Version; public int Port; public List<string> Listeners, Sessions;
            public FirewallRule Firewall; public bool ConfigExists, RestartPending; public List<HostKey> HostKeys;
            public SftpState Sftp; public int SftpSessions; public ServerStateSnapshot State;
        }

        private DashboardData CollectDashboard(SshdConfig cfg)
        {
            var d = new DashboardData { Sshd = Services.Status("sshd"), Agent = Services.Status("ssh-agent"), Version = Ssh.ServerVersion(), Port = cfg.EffectivePort };
            d.State = ServerState.Read();
            d.Listeners = d.State.ListeningPorts.SelectMany(Net.Listeners).Distinct().ToList();
            d.Sessions = d.State.Ports.SelectMany(Net.Sessions).Distinct().ToList();
            d.Firewall = Firewall.Get();
            d.ConfigExists = File.Exists(Ssh.ConfigPath); d.RestartPending = Services.ChangedSinceStart(d.Sshd, Ssh.ConfigPath);
            d.HostKeys = HostKeys.List();
            d.Sftp = SftpConfig.Read(cfg); d.SftpSessions = Sessions.SftpSessionCount();
            return d;
        }

        private async Task RefreshDashboard()
        {
            if (_cfg == null) _cfg = await BgAsync("Reading the configuration and Includes...", () => SshdConfig.Load());
            var cfg = _cfg;
            ShowDashboard(await BgAsync("Refreshing the dashboard...", () => CollectDashboard(cfg)));
        }

        private void ShowDashboard(DashboardData d)
        {
            var sshd = d.Sshd; var agent = d.Agent;
            _lblSshd.Text = sshd.Status + (sshd.Pid > 0 ? "  (PID " + sshd.Pid + ")" : "") + "   start: " + sshd.StartMode;
            _lblSshd.ForeColor = sshd.Status == "Running" ? Green : Red;
            _lblAgent.Text = agent.Status + "   start: " + agent.StartMode; _lblAgent.ForeColor = agent.Status == "Running" ? Green : Orange;
            _lblVersion.Text = d.Version;
            _lblListen.Text = d.State.Verified ? "Running: " + (d.Listeners.Count > 0 ? string.Join("   ", d.Listeners) : "not listening") + "   Configured ports: " + string.Join(", ", d.State.ConfiguredPorts)
                : "Inspection unavailable: " + d.State.Error;
            _lblListen.ForeColor = d.State.Verified && d.Listeners.Count > 0 ? Green : Orange;
            _lblSessions.Text = d.Sessions.Count + (d.Sessions.Count > 0 ? "   from " + string.Join(", ", d.Sessions.Take(6)) + (d.Sessions.Count > 6 ? " ..." : "") : "");
            var sf = d.Sftp;
            _lblSftp.Text = !sf.Enabled ? "off (no Subsystem sftp)" : "on" + (sf.LogTransfers ? ", transfers logged" : ", transfers not logged") + "   SFTP-only accounts: " + (sf.RulesProblem != null ? "section edited by hand" : sf.Rules.Count.ToString()) + "   SFTP sessions now: " + d.SftpSessions;
            _lblSftp.ForeColor = sf.Enabled ? Green : Theme.Muted;
            var fw = d.Firewall;
            _lblFirewall.Text = fw == null ? "missing" : (fw.Enabled ? "enabled" : "DISABLED") + "   profiles: " + fw.ProfilesText + "   port: " + fw.Ports;
            _lblFirewall.ForeColor = fw != null && fw.Enabled ? Green : Red;
            _lblConfig.Text = Ssh.ConfigPath + (!d.ConfigExists ? "  (not created yet; sshd copies sshd_config_default on first start)"
                            : d.RestartPending ? "   saved after sshd started: restart sshd to apply the changes" : "");
            _lblConfig.ForeColor = d.RestartPending ? Orange : ForeColor;
            _btnStart.Enabled = sshd.Exists && sshd.Status != "Running"; _btnStop.Enabled = sshd.Status == "Running"; _btnRestart.Enabled = sshd.Status == "Running";
            TrayState(sshd, d.Sessions.Count);
            // Rebuilt only when the keys changed, so a selected row stays selected.
            var rows = d.HostKeys.Select(k => new[] { k.File, k.Type, k.Bits ?? "", k.Fingerprint ?? "" }).ToList();
            var shown = _lvHostKeys.Items.Cast<ListViewItem>().Select(i => i.SubItems.Cast<ListViewItem.ListViewSubItem>().Select(s => s.Text).ToArray()).ToList();
            if (!SameRows(rows, shown))
            {
                var selected = new HashSet<string>(_lvHostKeys.SelectedItems.Cast<ListViewItem>().Select(i => i.Text));
                _lvHostKeys.BeginUpdate(); _lvHostKeys.Items.Clear();
                foreach (var r in rows) _lvHostKeys.Items.Add(new ListViewItem(r) { Selected = selected.Contains(r[0]) });
                _lvHostKeys.EndUpdate();
            }
        }

        /// <summary>The same rows in any order: a list sorted by a column shows them in another order than they are read.</summary>
        internal static bool SameRows(IList<string[]> a, IList<string[]> b)
        {
            Func<IList<string[]>, List<string>> keys = rows => rows.Select(r => string.Join("\u0001", r)).OrderBy(k => k, StringComparer.Ordinal).ToList();
            return a.Count == b.Count && keys(a).SequenceEqual(keys(b));
        }

        private bool _refreshRunning; private DateTime _refreshStarted; private long _refreshGeneration;
        /// <summary>
        /// Collects on a background thread (STA, for the COM objects of the firewall API) and shows the result on the
        /// window's thread. At most one runs at a time; a timer tick while one runs is skipped. One that has not finished
        /// after a minute is given up, so that a hung query does not stop the refresh for good. Returns false when one
        /// was already running.
        /// </summary>
        private bool RefreshInBackground<T>(Func<SshdConfig, T> collect, Action<T> show)
        {
            if (_refreshRunning && DateTime.UtcNow - _refreshStarted > TimeSpan.FromMinutes(1)) { Log.Info("Background refresh gave up after a minute"); _refreshRunning = false; }
            if (_refreshRunning || _cfg == null || IsDisposed || Disposing || !IsHandleCreated || _busyDepth > 0) return false;
            _refreshRunning = true; _refreshStarted = DateTime.UtcNow;
            var generation = ++_refreshGeneration;
            var cfg = _cfg;
            TrackOperation(CompleteRefreshAsync(cfg, collect, show, generation));
            return true;
        }

        private async Task CompleteRefreshAsync<T>(SshdConfig config, Func<SshdConfig, T> collect, Action<T> show, long generation)
        {
            try
            {
                var data = await StaOperation.Run(() => collect(config));
                if (IsDisposed || Disposing || generation != _refreshGeneration) return;
                _refreshRunning = false;
                if (_busyDepth == 0) Safe(() => show(data), false);
            }
            catch (Exception error)
            {
                if (generation == _refreshGeneration) _refreshRunning = false;
                Log.Error("Refresh", error, false);
            }
        }

        private async Task ServiceAction(string action)
        {
            await SafeAsync(async () =>
            {
                if (action == "stop" && MessageBox.Show(this, "Stop the SSH server? New connections are refused until it starts again.\n\nConnected sessions stay connected; end them on the Sessions tab if needed.", Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Question, MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;
                if (action == "restart" && !Program.Unattended) { await RestartApplyingSaved(true); return; }
                _expectedStateChange = DateTime.UtcNow;
                await BgAsync((action == "stop" ? "Stopping" : action == "start" ? "Starting" : "Restarting") + " sshd...", () =>
                {
                    switch (action)
                    {
                        case "start": Services.Start("sshd"); break;
                        case "stop": Services.Stop("sshd"); break;
                        case "restart": Services.Restart("sshd"); break;
                    }
                    Thread.Sleep(800);
                });
                _expectedStateChange = DateTime.UtcNow;
                await RefreshDashboard();
                Status("sshd " + action + " completed");
            });
        }

        /// <summary>
        /// Restart from the Dashboard or the tray (ask), or Save and restart with nothing to save. When sshd does not run the
        /// saved file yet (a save-only change, or an edit after sshd started), it goes through RestartWithRollback like a
        /// save does, so settings that lock you out come back by themselves, and the firewall is offered the ports of that
        /// file. Otherwise a plain restart changes nothing. When recovery cannot be armed, a plain restart is offered.
        /// </summary>
        private async Task RestartApplyingSaved(bool ask)
        {
            var rollback = await BgAsync("Checking what sshd runs...", () => ConfigurationRecovery.RestartRollbackFor(Ssh.ConfigPath));
            const string sessions = "\n\nConnected sessions stay connected: each runs in its own sshd-session.exe process.";
            if (rollback == null)
            {
                if (ask && MessageBox.Show(this, "Restart the SSH server? sshd reads sshd_config again; new connections are refused for a moment." + sessions, Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
                await PlainRestart();
                return;
            }
            if (ask && MessageBox.Show(this, "Restart the SSH server? sshd_config was saved after sshd started, so sshd starts with settings it has not run yet.\n\nAfter the restart you are asked to keep them. Without an answer, or with Restore, " +
                    (rollback.FromRecord ? "the settings sshd runs now come back." : "the newest backup (" + Path.GetFileName(rollback.Backup) + ") comes back: the manager has no record of the exact settings sshd runs now.") + sessions,
                    Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
            // A port saved earlier without a restart takes effect now.
            var firewallBack = await OpenFirewallForPort(false);
            try
            {
                await RestartWithRollback(rollback.Backup, firewallBack == null ? null : firewallBack.Undo,
                    firewallBack == null ? null : firewallBack.Apply, firewallBack == null ? null : firewallBack.Keep, !rollback.FromRecord);
            }
            catch (RecoveryNotArmedException ex)
            {
                // Nothing was changed. Before automatic rollback this button restarted sshd as it is, and it still can.
                if (MessageBox.Show(this, "Automatic rollback is unavailable: " + ex.Reason + "\n\nRestart sshd without it? sshd starts with the saved settings, and nothing brings back the previous ones if they lock you out.",
                        Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes)
                { Status("sshd was not restarted: automatic rollback is unavailable"); return; }
                if (firewallBack != null) await firewallBack.Apply();
                await PlainRestart();
            }
        }

        private async Task PlainRestart()
        {
            _expectedStateChange = DateTime.UtcNow;
            await BgAsync("Restarting sshd...", () => { Services.Restart("sshd"); Thread.Sleep(800); });
            _expectedStateChange = DateTime.UtcNow;
            await RefreshDashboard();
            Status("sshd restart completed");
        }

        private async Task TestLiveConfig()
        {
            var r = await BgAsync("Running sshd -t...", () => Ssh.TestConfig(null));
            MessageBox.Show(this, r.Ok ? "sshd -t reports no problems with\n" + Ssh.ConfigPath : "sshd -t reported:\n\n" + r.Output, Program.AppName, MessageBoxButtons.OK, r.Ok ? MessageBoxIcon.Information : MessageBoxIcon.Warning);
        }

        private async Task GenerateHostKeys()
        {
            var o = await BgAsync("Generating host keys...", () => HostKeys.GenerateMissing());
            await RefreshDashboard(); Status("ssh-keygen -A: " + (o.Length == 0 ? "done" : o));
        }

        private async Task QuickAddMyKey()
        {
            using (var dlg = new OpenFileDialog { Title = "Choose your public key (*.pub)", Filter = "Public keys (*.pub)|*.pub|All files|*.*", InitialDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".ssh") })
            {
                if (dlg.ShowDialog(this) != DialogResult.OK) return;
                var path = dlg.FileName; bool already = false;
                var target = await BgAsync("Allowing the key to log in...", () =>
                {
                    var line = File.ReadAllText(path).Trim();
                    if (!Keys.LooksLikePublicKey(line) || line.IndexOf("PRIVATE KEY", StringComparison.OrdinalIgnoreCase) >= 0) throw new ConfigException("The file does not contain an OpenSSH public key. Choose the .pub file, never the private key.");
                    return KeyGen.AuthorizeForCurrentUser(line, out already);
                });
                await LoadKeys();
                if (already) { Status("Key already present in " + target); return; }
                MessageBox.Show(this, "Key added to\n" + target + "\n\nThis is the file sshd reads for " + KeyGen.LoginName() + ". Members of the Administrators group use administrators_authorized_keys; other users their own .ssh\\authorized_keys.", Program.AppName, MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        }

        // ---------------- Sessions ----------------
        private ListView _lvSessions; private Label _lblSessionSummary;

        private TabPage BuildSessions()
        {
            var page = new TabPage("Sessions");
            var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 3 };
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize)); root.RowStyles.Add(new RowStyle(SizeType.AutoSize)); root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            _lblSessionSummary = new Label { AutoSize = true, Margin = new Padding(8, 10, 4, 4), Font = new Font(Font, FontStyle.Bold) };
            root.Controls.Add(_lblSessionSummary, 0, 0);
            var bar = Flow();
            bar.Controls.Add(Btn("Refresh", async (s, e) => await SafeAsync(RefreshSessions), 100));
            bar.Controls.Add(Btn("Disconnect selected", async (s, e) => await SafeAsync(async () => await DisconnectSessions(false)), 160));
            bar.Controls.Add(Btn("Disconnect all", async (s, e) => await SafeAsync(async () => await DisconnectSessions(true)), 130));
            bar.Controls.Add(new Label { AutoSize = true, Margin = new Padding(12, 10, 4, 4), ForeColor = Theme.Muted, MaximumSize = new Size(Ui.Px(560), 0), Text = "Each connection runs as an sshd-session.exe process: one owned by SYSTEM before login, then one owned by the user. Activity: SFTP, scp, or the shell or command the session runs. Refreshes every 5 seconds." });
            root.Controls.Add(bar, 0, 1);
            var split = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal };
            bool splitInit = false;
            split.SizeChanged += (s, e) => { if (splitInit || split.Height < Ui.Px(300)) return; splitInit = true; try { split.SplitterDistance = split.Height * 62 / 100; } catch { } };
            var sessBox = new GroupBox { Text = "Session processes (sshd-session.exe)", Dock = DockStyle.Fill, Padding = new Padding(6) };
            _lvSessions = Lv("PID|80", "User|240", "Started|160", "Duration|100", "Role|200", "Activity|170"); _lvSessions.AccessibleName = "Session processes";
            _lvSessions.MultiSelect = true; // "Disconnect selected" ends every selected session
            _lvSessions.KeyDown += async (s, e) => { if (e.KeyCode == System.Windows.Forms.Keys.Delete) { e.Handled = true; await SafeAsync(async () => await DisconnectSessions(false)); } };
            sessBox.Controls.Add(_lvSessions); split.Panel1.Controls.Add(sessBox);
            var connBox = new GroupBox { Text = "Established TCP connections on the server port (peer address, owning process)", Dock = DockStyle.Fill, Padding = new Padding(6) };
            _lvConnections = Lv("Peer|260", "Owning process|260"); _lvConnections.AccessibleName = "Established connections";
            connBox.Controls.Add(_lvConnections); split.Panel2.Controls.Add(connBox);
            root.Controls.Add(split, 0, 2);
            page.Controls.Add(root);
            return page;
        }

        private ListView _lvConnections;

        /// <summary>Sshd and Peers: for the notification area icon, which the timer keeps up to date while this tab is shown.</summary>
        private sealed class SessionsData { public int Port; public List<SessionInfo> List; public List<string[]> Connections; public string Error; public ServiceState Sshd; public int Peers; }

        private SessionsData CollectSessions(SshdConfig cfg)
        {
            var state = ServerState.Read(); int port = state.Ports.FirstOrDefault();
            return new SessionsData { Port = port, List = Sessions.List(port), Connections = state.Verified ? Sessions.Connections(state.Ports) : new List<string[]>(), Error = state.Verified ? null : state.Error,
                                      Sshd = Services.Status("sshd"), Peers = state.Ports.SelectMany(Net.Sessions).Distinct().Count() };
        }

        private async Task RefreshSessions()
        {
            if (_cfg == null) _cfg = await BgAsync("Reading the configuration and Includes...", () => SshdConfig.Load());
            var cfg = _cfg;
            ShowSessions(await BgAsync("Reading sessions...", () => CollectSessions(cfg)));
        }

        private void ShowSessions(SessionsData data)
        {
            var list = data.List;
            // Rows are found again by PID (0: a row without a process, never an anchor): the selection, the row at the top of
            // the list and the focused row stay where they were.
            var selected = new HashSet<int>(_lvSessions.SelectedItems.Cast<ListViewItem>().Select(i => (int)i.Tag));
            int topPid = _lvSessions.TopItem == null ? 0 : (int)_lvSessions.TopItem.Tag, focusedPid = _lvSessions.FocusedItem == null ? 0 : (int)_lvSessions.FocusedItem.Tag;
            _lvSessions.BeginUpdate(); _lvSessions.Items.Clear();
            foreach (var s in list)
            {
                bool system = s.User.IndexOf("SYSTEM", StringComparison.OrdinalIgnoreCase) >= 0;
                var ts = s.Start == DateTime.MinValue ? TimeSpan.Zero : DateTime.Now - s.Start;
                if (ts < TimeSpan.Zero) ts = TimeSpan.Zero;
                var dur = s.Start == DateTime.MinValue ? "" : ((int)ts.TotalHours).ToString("00") + ":" + ts.Minutes.ToString("00") + ":" + ts.Seconds.ToString("00");
                var it = new ListViewItem(new[] { s.Pid == 0 ? "" : s.Pid.ToString(), s.User, s.Start == DateTime.MinValue ? "" : s.Start.ToString("yyyy-MM-dd HH:mm:ss"), dur, s.Pid == 0 ? "" : (system ? "privileged monitor (pre-login or supervisor)" : "user session"), s.Activity }) { Tag = s.Pid };
                if (system) it.ForeColor = Theme.Faint;
                if (s.Pid != 0 && selected.Contains(s.Pid)) it.Selected = true;
                _lvSessions.Items.Add(it);
            }
            _lvSessions.EndUpdate();
            var top = _lvSessions.Items.Cast<ListViewItem>().FirstOrDefault(i => topPid != 0 && (int)i.Tag == topPid);
            if (top != null) _lvSessions.TopItem = top;
            var focused = _lvSessions.Items.Cast<ListViewItem>().FirstOrDefault(i => focusedPid != 0 && (int)i.Tag == focusedPid);
            if (focused != null) focused.Focused = true;
            var conns = data.Connections;
            _lvConnections.BeginUpdate(); _lvConnections.Items.Clear();
            foreach (var c in conns) _lvConnections.Items.Add(new ListViewItem(c));
            _lvConnections.EndUpdate();
            int users = list.Count(x => x.Pid != 0 && x.User.IndexOf("SYSTEM", StringComparison.OrdinalIgnoreCase) < 0), sftp = list.Count(x => x.Activity == "SFTP");
            _lblSessionSummary.Text = users + " user session(s)" + (sftp > 0 ? " (" + sftp + " SFTP)" : "") + ", " + list.Count(x => x.Pid != 0) + " sshd-session process(es), " +
                (data.Error == null ? conns.Count + " established connection(s) across the server endpoints" : "connection inspection unavailable: " + data.Error);
            _lblSessionSummary.ForeColor = data.Error == null ? Theme.Text : Orange;
            if (data.Sshd != null) TrayState(data.Sshd, data.Peers);
        }

        private async Task DisconnectSessions(bool all)
        {
            var targets = all ? _lvSessions.Items.Cast<ListViewItem>().ToList() : _lvSessions.SelectedItems.Cast<ListViewItem>().ToList();
            targets = targets.Where(i => (int)i.Tag != 0).ToList();
            if (targets.Count == 0) { Status("Select a session first"); return; }
            var who = string.Join("\n", targets.Select(i => "PID " + i.SubItems[0].Text + "  " + i.SubItems[1].Text + "  " + i.SubItems[4].Text));
            if (MessageBox.Show(this, "Disconnect " + targets.Count + " session(s)?\n\n" + who, Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;
            var pids = targets.Select(t => (int)t.Tag).ToList();
            int ok = await BgAsync("Disconnecting...", () => pids.Count(pid => { try { Sessions.Disconnect(pid); return true; } catch (Exception ex) { Log.Error("Disconnect PID " + pid, ex, false); return false; } }));
            await Task.Delay(500); await RefreshSessions();
            Status(ok + " of " + targets.Count + " session(s) disconnected");
        }

        // ---------------- Settings ----------------
        /// <summary>List: a list of names typed with spaces between them, written with the quoting sshd needs (SshdArgs).</summary>
        private sealed class Field { public string Key; public string Label; public string[] Choices; public string Tip; public bool Numeric; public bool Wide; public bool List; }

        private static readonly Field[] FieldDefs = new[]
        {
            new Field { Key = "Port", Label = "Port", Numeric = true, Tip = "TCP port sshd listens on. Default 22. Remember to update the firewall rule." },
            new Field { Key = "ListenAddress", Label = "Listen address", Tip = "Bind to one address only, e.g. 192.168.1.10 or 192.168.1.10:2222. Empty = all addresses." },
            // Login methods (PasswordAuthentication, PubkeyAuthentication, GSSAPIAuthentication, AuthenticationMethods,
            // KbdInteractiveAuthentication) are edited on the Authentication tab, together with the rules per user and group.
            new Field { Key = "PermitEmptyPasswords", Label = "Permit empty passwords", Choices = new[] { "", "yes", "no" }, Tip = "Never enable on a networked server." },
            new Field { Key = "AllowUsers", Label = "Allow users", Wide = true, List = true, Tip = "Space-separated user patterns allowed to log in (user, DOMAIN\\user, user@host). Put \"double quotes\" around a name with spaces. Empty = no restriction." },
            new Field { Key = "AllowGroups", Label = "Allow groups", Wide = true, List = true, Tip = "Space-separated Windows groups allowed to log in, e.g. administrators \"openssh users\" (use lowercase; put double quotes around a name with spaces)." },
            new Field { Key = "DenyUsers", Label = "Deny users", Wide = true, List = true, Tip = "Users that are refused even if allowed elsewhere. Put \"double quotes\" around a name with spaces." },
            new Field { Key = "DenyGroups", Label = "Deny groups", Wide = true, List = true, Tip = "Groups that are refused. Put \"double quotes\" around a name with spaces." },
            new Field { Key = "MaxAuthTries", Label = "Max auth tries", Numeric = true, Tip = "Authentication attempts per connection before disconnect. Default 6." },
            new Field { Key = "LoginGraceTime", Label = "Login grace time (s)", Numeric = true, Tip = "Seconds a client has to authenticate. Default 120." },
            new Field { Key = "ClientAliveInterval", Label = "Client alive interval (s)", Numeric = true, Tip = "Seconds of inactivity before sshd probes the client. 0 = never. 300 recommended." },
            new Field { Key = "ClientAliveCountMax", Label = "Client alive count max", Numeric = true, Tip = "Unanswered probes before the session is closed. Default 3." },
            new Field { Key = "MaxSessions", Label = "Max sessions per connection", Numeric = true, Tip = "Multiplexed sessions per network connection. Default 10." },
            new Field { Key = "MaxStartups", Label = "Max startups (throttle)", Tip = "start:rate:full, e.g. 10:30:100 - random early drop of unauthenticated connections. Protects against floods." },
            new Field { Key = "PerSourcePenalties", Label = "Per-source penalties", Wide = true, Tip = "Automatic temporary blocking of abusive addresses, e.g. authfail:5 noauth:1 crash:90 max:600. 'no' disables." },
            new Field { Key = "PerSourcePenaltyExemptList", Label = "Penalty exempt list", Wide = true, Tip = "Addresses or CIDR ranges never penalised, e.g. 10.0.0.0/8,192.168.1.0/24." },
            new Field { Key = "AllowTcpForwarding", Label = "TCP forwarding", Choices = new[] { "", "yes", "no", "local", "remote" }, Tip = "Port forwarding (-L / -R / -D). Set no for file-transfer-only servers." },
            new Field { Key = "GatewayPorts", Label = "Gateway ports", Choices = new[] { "", "no", "yes", "clientspecified" }, Tip = "Whether remote-forwarded ports bind to all interfaces." },
            new Field { Key = "AllowAgentForwarding", Label = "Agent forwarding", Choices = new[] { "", "yes", "no" }, Tip = "Forward the client's ssh-agent into the session." },
            new Field { Key = "PermitTTY", Label = "Permit TTY", Choices = new[] { "", "yes", "no" }, Tip = "Interactive terminals. Set no for SFTP-only servers." },
            new Field { Key = "Banner", Label = "Banner file", Wide = true, Tip = "Path to a text file shown before login (legal notice)." },
            new Field { Key = "LogLevel", Label = "Log level", Choices = new[] { "", "QUIET", "FATAL", "ERROR", "INFO", "VERBOSE", "DEBUG", "DEBUG1", "DEBUG2", "DEBUG3" }, Tip = "VERBOSE records the key fingerprint used for each login." },
            new Field { Key = "SyslogFacility", Label = "Log destination", Choices = new[] { "", "AUTH", "LOCAL0", "LOCAL1", "LOCAL2", "LOCAL3", "LOCAL4", "LOCAL5", "LOCAL6", "LOCAL7" }, Tip = "AUTH = Windows event log (OpenSSH/Operational). LOCAL0-7 = text file in %ProgramData%\\ssh\\logs." },
            new Field { Key = "AuthorizedKeysFile", Label = "Authorized keys file", Wide = true, Tip = "Path pattern relative to the user's home. Default .ssh/authorized_keys" },
            new Field { Key = "TrustedUserCAKeys", Label = "Trusted user CA keys", Wide = true, Tip = "File with CA public keys; users with certificates signed by them may log in." },
            new Field { Key = "Ciphers", Label = "Ciphers", Wide = true, Tip = "Comma-separated cipher list. Leave empty for the secure defaults." },
            new Field { Key = "MACs", Label = "MACs", Wide = true, Tip = "Comma-separated MAC list. Leave empty for the secure defaults." },
            new Field { Key = "KexAlgorithms", Label = "Key exchange", Wide = true, Tip = "Comma-separated KEX list. Defaults include post-quantum mlkem768x25519-sha256." },
            new Field { Key = "HostKeyAlgorithms", Label = "Host key algorithms", Wide = true, Tip = "Host key signature algorithms offered to clients." },
            new Field { Key = "RequiredRSASize", Label = "Minimum RSA key size", Numeric = true, Tip = "Smallest RSA key accepted. Default 1024; 2048 recommended." },
        };

        private TabPage BuildSettings()
        {
            var page = new TabPage("Settings");
            var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2 };
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 100)); root.RowStyles.Add(new RowStyle(SizeType.AutoSize));

            var scroll = new Panel { Dock = DockStyle.Fill, AutoScroll = true, Padding = new Padding(8) };
            var grid = new TableLayoutPanel { AutoSize = true, ColumnCount = 3, Dock = DockStyle.Top, Padding = new Padding(4) };
            grid.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, Ui.Px(210))); grid.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, Ui.Px(420))); grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));

            grid.Controls.Add(Lbl("Server settings (empty = sshd default; the grey text shows the effective value)", true)); grid.SetColumnSpan(grid.Controls[grid.Controls.Count - 1], 3);
            var authHint = new Label { AutoSize = true, ForeColor = Theme.Muted, Margin = new Padding(4, 0, 4, 6), Text = "Login methods (Windows authentication, public key, Kerberos; rules per user and group) are set on the Authentication tab." };
            grid.Controls.Add(authHint); grid.SetColumnSpan(authHint, 3);
            _setIncludeNote = new Label { AutoSize = true, ForeColor = Orange, MaximumSize = new Size(Ui.Px(960), 0), Margin = new Padding(4, 0, 4, 6), Visible = false };
            grid.Controls.Add(_setIncludeNote); grid.SetColumnSpan(_setIncludeNote, 3);
            foreach (var f in FieldDefs)
            {
                var lbl = Lbl(f.Label); grid.Controls.Add(lbl);
                Control c;
                if (f.Choices != null) { var cb = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = Ui.Px(160) }; cb.Items.AddRange(f.Choices.Select(x => (object)(x == "" ? "(default)" : x)).ToArray()); c = cb; }
                else { c = new TextBox { Width = Ui.Px(f.Wide ? 410 : 200) }; }
                c.Margin = new Padding(4); grid.Controls.Add(c);
                var hint = new Label { AutoSize = true, ForeColor = Theme.Faint, Margin = new Padding(4, 8, 4, 4) }; grid.Controls.Add(hint);
                _fields[f.Key] = c; _hints[f.Key] = hint;
                _tips.SetToolTip(c, f.Tip); _tips.SetToolTip(lbl, f.Tip);
                c.AccessibleName = f.Label; c.AccessibleDescription = f.Tip;
                var field = f;
                EventHandler changed = (s, e) => { if (!_loadingSettings) { ShowFieldError(field); UpdatePending(); } };
                if (c is ComboBox) ((ComboBox)c).SelectedIndexChanged += changed; else c.TextChanged += changed;
            }

            grid.Controls.Add(Lbl("Subsystems and shell", true)); grid.SetColumnSpan(grid.Controls[grid.Controls.Count - 1], 3);
            grid.Controls.Add(Lbl("PowerShell remoting"));
            _chkPwshSubsystem = new CheckBox { Text = "Enable 'powershell' subsystem", AutoSize = true, Margin = new Padding(4, 8, 4, 4) };
            grid.Controls.Add(_chkPwshSubsystem);
            _txtPwshPath = new TextBox { Width = Ui.Px(380), Margin = new Padding(4), Text = @"C:/progra~1/PowerShell/7/pwsh.exe -sshs -NoLogo" };
            grid.Controls.Add(_txtPwshPath);
            _tips.SetToolTip(_chkPwshSubsystem, "Adds 'Subsystem powershell <command>' so Enter-PSSession -HostName works. Requires PowerShell 7.");
            grid.Controls.Add(Lbl("Default shell"));
            _cmbShell = new ComboBox { DropDownStyle = ComboBoxStyle.DropDown, Width = Ui.Px(410), Margin = new Padding(4) };
            grid.Controls.Add(_cmbShell);
            var shellHint = new Label { AutoSize = true, ForeColor = Theme.Faint, Margin = new Padding(4, 8, 4, 4), Text = "registry HKLM\\SOFTWARE\\OpenSSH\\DefaultShell; empty = cmd.exe" }; grid.Controls.Add(shellHint);
            grid.Controls.Add(Lbl("Shell command option"));
            _txtShellOption = new TextBox { Width = Ui.Px(200), Margin = new Padding(4) }; grid.Controls.Add(_txtShellOption);
            var optHint = new Label { AutoSize = true, ForeColor = Theme.Faint, Margin = new Padding(4, 8, 4, 4), Text = "e.g. /c for cmd-like shells, -c for bash; empty = automatic" }; grid.Controls.Add(optHint);
            _tips.SetToolTip(_cmbShell, "Shell started for interactive sessions and remote commands. Applies immediately to new sessions; no restart needed.");
            _txtPwshPath.AccessibleName = "PowerShell subsystem command"; _cmbShell.AccessibleName = "Default shell"; _txtShellOption.AccessibleName = "Shell command option";
            EventHandler other = (s, e) => { if (!_loadingSettings) UpdatePending(); };
            _chkPwshSubsystem.CheckedChanged += other; _txtPwshPath.TextChanged += other; _cmbShell.TextChanged += other; _txtShellOption.TextChanged += other;

            scroll.Controls.Add(grid);
            root.Controls.Add(scroll, 0, 0);

            var bar = Flow();
            bar.Controls.Add(Btn("Save", async (s, e) => await SafeAsync(async () => await SaveSettings(false)), 110));
            bar.Controls.Add(Btn("Save and restart sshd", async (s, e) => await SafeAsync(async () => await SaveSettings(true)), 180));
            bar.Controls.Add(Btn("Reload from file", async (s, e) => await SafeAsync(async () => await ReloadFromFile(true, false)), 140));
            bar.Controls.Add(Btn("Backups...", async (s, e) => await SafeAsync(RestoreBackup), 110));
            bar.Controls.Add(Btn("Reset to shipped defaults", async (s, e) => await SafeAsync(ResetToDefault), 190));
            _tips.SetToolTip(bar.Controls[0], "Ctrl+S");
            _tips.SetToolTip(bar.Controls[3], "Compare the backups kept at every save with the current file, and restore one.");
            _setPending = new Label { AutoSize = true, Margin = new Padding(12, 10, 4, 4), ForeColor = Orange };
            bar.Controls.Add(_setPending);
            var note = new Label { AutoSize = true, Margin = new Padding(12, 10, 4, 4), ForeColor = Theme.Muted, Text = "Every save shows the changes, is validated with sshd -t first, and keeps a timestamped backup next to sshd_config." };
            bar.Controls.Add(note);
            root.Controls.Add(bar, 0, 1);
            page.Controls.Add(root);
            return page;
        }

        /// <summary>Shows sshd_config on the Settings tab. keepEdits: fields changed and not saved keep what was typed.</summary>
        private async Task LoadSettings(bool keepEdits = false)
        {
            Dictionary<string, string> eff;
            try { eff = await BgAsync("Reading the effective settings (sshd -T)...", () => Ssh.EffectiveSettings()); } catch (OperationCanceledException) { throw; } catch { eff = new Dictionary<string, string>(); }
            _effective = eff;
            _loadingSettings = true;
            try { LoadSettingsFields(eff, keepEdits); }
            finally { _loadingSettings = false; }
            foreach (var f in FieldDefs) ShowFieldError(f);
            var inc = _cfg.Includes();
            _setIncludeNote.Visible = inc.Count > 0;
            _setIncludeNote.Text = inc.Count == 0 ? "" : "sshd_config includes other files (Include " + string.Join("; ", inc) + "). sshd takes the first value it reads, so a value in an included file can win over a field here; the grey \"effective\" text shows what sshd really uses. New settings are written before the first Include.";
            UpdatePending();
        }

        /// <summary>The values sshd -T reported when the Settings tab was last loaded (lower-case keywords).</summary>
        private Dictionary<string, string> _effective = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        /// <summary>
        /// The text a field shows for the file: the first line's value; for the Allow and Deny lists, every line together, as
        /// sshd adds them up (saving then writes them as one line).
        /// </summary>
        private string FileValue(Field f)
        {
            var v = _cfg.Get(f.Key) ?? "";
            if (!f.List) return v;
            string err; var args = _cfg.GetCombinedArgs(f.Key, out err);
            return (args == null ? null : SshdArgs.FormatTyped(args)) ?? v;
        }

        private void LoadSettingsFields(Dictionary<string, string> eff, bool keepEdits)
        {
            foreach (var f in FieldDefs)
            {
                bool keep = keepEdits && FieldEdited(f);
                var v = FileValue(f);
                // sshd reads these values without regard to case: "verbose" is shown, and unchanged, as the choice VERBOSE.
                int choice = f.Choices == null ? -1 : Array.FindIndex(f.Choices, x => x.Length > 0 && x.Equals(v, StringComparison.OrdinalIgnoreCase));
                _shown[f.Key] = choice > 0 ? f.Choices[choice] : v;
                var c = _fields[f.Key];
                if (keep) { SetHint(f, eff); continue; }
                if (c is ComboBox)
                {
                    var cb = (ComboBox)c;
                    while (cb.Items.Count > f.Choices.Length) cb.Items.RemoveAt(cb.Items.Count - 1); // a value outside the list added by an earlier load
                    int idx = Array.FindIndex(f.Choices, x => x.Equals(v, StringComparison.OrdinalIgnoreCase));
                    cb.SelectedIndex = idx < 0 ? 0 : idx;
                    if (idx < 0 && v.Length > 0) { cb.Items.Add(v); cb.SelectedIndex = cb.Items.Count - 1; }
                }
                else ((TextBox)c).Text = v;
                SetHint(f, eff);
            }
            bool keepPwsh = keepEdits && PwshWanted() != _pwshShown, keepShell = keepEdits && (_cmbShell.Text.Trim() != _shellShown || _txtShellOption.Text.Trim() != _shellOptionShown);
            _pwshShown = _cfg.GetSubsystem("powershell");
            if (!keepPwsh) { _chkPwshSubsystem.Checked = _pwshShown != null; if (_pwshShown != null) _txtPwshPath.Text = _pwshShown; }
            _shellShown = (DefaultShell.Get() ?? "").Trim(); _shellOptionShown = (DefaultShell.GetOption() ?? "").Trim();
            if (!keepShell)
            {
                _cmbShell.Items.Clear(); _cmbShell.Items.Add(""); foreach (var c in DefaultShell.Candidates()) _cmbShell.Items.Add(c);
                _cmbShell.Text = _shellShown; _txtShellOption.Text = _shellOptionShown;
            }
        }

        private void SetHint(Field f, Dictionary<string, string> eff)
        {
            string ev; var hint = eff.TryGetValue(f.Key, out ev) ? "effective: " + (ev.Length > 70 ? ev.Substring(0, 70) + "..." : ev) : "";
            int occurrences = _cfg.GetAll(f.Key).Count;
            if (occurrences > 1)
                hint += (hint.Length > 0 ? "   " : "") + (f.List ? "(" + occurrences + " lines in the file, shown together as sshd adds them up; saving writes one line)"
                                                              : "(" + occurrences + " lines in the file; this field edits the first, the others stay as they are: see the text tab)");
            _hintText[f.Key] = hint;
        }

        private string FieldValue(Field f)
        {
            var c = _fields[f.Key];
            return c is ComboBox ? (((ComboBox)c).SelectedIndex <= 0 ? "" : ((ComboBox)c).SelectedItem.ToString()) : ((TextBox)c).Text.Trim();
        }

        private bool FieldEdited(Field f) { string shown; return _shown.TryGetValue(f.Key, out shown) && FieldValue(f) != shown; }
        private string PwshWanted() { return _chkPwshSubsystem.Checked ? _txtPwshPath.Text.Trim() : null; }

        /// <summary>Why a typed value cannot be saved, or null. Checked as the user types and again on Save.</summary>
        private static string FieldError(Field f, string v)
        {
            if (v.Length == 0) return null;
            int n;
            if (f.Numeric && !int.TryParse(v, out n)) return f.Label + " must be a whole number, or empty for the sshd default.";
            string err;
            if (f.List && SshdArgs.ParseTyped(v, out err) == null) return f.Label + ": " + err + ".";
            return null;
        }

        /// <summary>A field with an error gets the error icon and the error in red in place of its hint (read by screen readers too).</summary>
        private void ShowFieldError(Field f)
        {
            var c = _fields[f.Key]; var err = FieldError(f, FieldValue(f));
            _errors.SetError(c, err ?? "");
            string hint; _hintText.TryGetValue(f.Key, out hint);
            _hints[f.Key].Text = err ?? hint ?? "";
            _hints[f.Key].ForeColor = err != null ? Red : Theme.Faint;
            c.AccessibleDescription = err ?? FieldDefs.First(x => x.Key == f.Key).Tip;
        }

        private bool SettingsEdited()
        {
            return FieldDefs.Any(FieldEdited) || PwshWanted() != _pwshShown || _cmbShell.Text.Trim() != (_shellShown ?? "") || _txtShellOption.Text.Trim() != (_shellOptionShown ?? "");
        }

        private bool RawEdited() { return _rawEditor.Text != _rawShown; }

        private List<string> UnsavedTabs()
        {
            var l = new List<string>();
            if (SettingsEdited()) l.Add("the Settings tab");
            if (AuthEdited()) l.Add("the Authentication tab");
            if (SftpEdited()) l.Add("the SFTP tab");
            if (RawEdited()) l.Add("the sshd_config (text) tab");
            if (AlertsEdited()) l.Add("the Alerts tab");
            if (FirewallEdited()) l.Add("the Firewall tab");
            return l;
        }

        /// <summary>Marks tabs with changes not saved: "*" after the tab name and a note next to the Save buttons.</summary>
        private void UpdatePending()
        {
            if (_pgSettings == null || _pgSftp == null || _setPending == null || _rawPending == null) return; // still building
            bool s = SettingsEdited(), r = RawEdited();
            MarkTab(_pgSettings, "Settings", s); MarkTab(_pgAuth, "Authentication", AuthEdited()); MarkTab(_pgSftp, "SFTP", SftpEdited()); MarkTab(_pgRaw, "sshd_config (text)", r);
            if (_pgAlerts != null) MarkTab(_pgAlerts, "Alerts", AlertsEdited());
            if (_alPending != null) { _alPending.Text = AlertsEdited() ? "Unsaved alert settings" : "All alert settings saved"; _alPending.ForeColor = AlertsEdited() ? Orange : Theme.Muted; }
            if (_pgFirewall != null) MarkTab(_pgFirewall, "Firewall", FirewallEdited());
            _setPending.Text = s ? "Changes not saved yet" : "";
            if (!r) _rawPending.Text = "";
            else if (_rawPending.Text.Length == 0) _rawPending.Text = "Changes not saved yet";
        }

        private void MarkTab(TabPage page, string name, bool edited)
        {
            var text = edited ? name + " *" : name; if (page.Text != text) page.Text = text;
            TreeNode node; if (_navigationNodes.TryGetValue(page, out node)) node.Text = text;
        }

        private async Task SaveSettings(bool restart)
        {
            var shell = _cmbShell.Text.Trim();
            var shellOption = _txtShellOption.Text.Trim();
            bool optionChanged = shellOption != (DefaultShell.GetOption() ?? "").Trim();
            // Validate only a changed shell: an existing registry value must not block saving unrelated settings.
            bool shellChanged = !string.Equals(shell, (DefaultShell.Get() ?? "").Trim(), StringComparison.OrdinalIgnoreCase);
            if (shellChanged && shell.Length > 0 && !File.Exists(shell)) throw new ConfigException("Default shell not found:\n" + shell + "\n\nEnter the full path of an existing program, or leave the field empty for cmd.exe.");
            var cand = _cfg.Copy();
            var changed = new List<Field>();
            foreach (var f in FieldDefs)
            {
                var v = FieldValue(f);
                // Only fields the user changed are checked and written: an untouched field must not normalise the line or
                // comment out further occurrences of a repeatable directive, and a value sshd accepts in the file (with
                // a comment after it, say) must not block saving another field.
                string shown; if (!_shown.TryGetValue(f.Key, out shown)) shown = FileValue(f);
                if (v == shown) continue;
                var error = FieldError(f, v); if (error != null) throw new ConfigException(error);
                changed.Add(f);
                if (f.List)
                {
                    // The field shows every line of the list; one line with all of them replaces them (sshd adds them up).
                    string err; cand.Set(f.Key, SshdArgs.Join(SshdArgs.ParseTyped(v, out err)));
                }
                else if (SshdConfig.RepeatableKeywords.Contains(f.Key, StringComparer.OrdinalIgnoreCase)) cand.SetFirst(f.Key, v); // the other Port and ListenAddress lines stay
                else cand.Set(f.Key, v);
            }
            var pwshCurrent = cand.GetSubsystem("powershell");
            var pwshWanted = PwshWanted();
            if (pwshWanted != pwshCurrent) cand.SetSubsystem("powershell", pwshWanted);
            // Nothing to write in sshd_config (only the default shell, or nothing, changed): no sshd -t, backup, recovery
            // record or new file time, which would also report a restart as needed.
            if (cand.Text == _cfg.Text && File.Exists(cand.Path))
            {
                await LoadSettings(false);
                bool shellSaved = (shellChanged || optionChanged) && await SaveDefaultShell(shell, shellOption, false);
                if (restart) { await RestartApplyingSaved(false); return; }
                Status(shellSaved ? "Default shell saved; it applies to new sessions at once. sshd_config is unchanged." : "Nothing to save: sshd_config is unchanged.");
                return;
            }
            var before = _cfg;
            var backup = await SaveConfig(cand, changed.Count == 0 ? "Save the settings of the Settings tab." : "Save " + string.Join(", ", changed.Select(f => f.Label)) + ".", restart ? "Save and restart" : "Save");
            // The window adopts the saved file first, so that nothing below can leave it with the old file's state.
            await UseConfig(cand, false, true);
            // The registry value is written only when it changed (HKLM\SOFTWARE\OpenSSH\DefaultShell applies to new sessions at once).
            if (shellChanged || optionChanged) await SaveDefaultShell(shell, shellOption, true);
            ReportOverridden(changed);
            var firewallBack = ChecksFirewall(before, cand, restart) ? await OpenFirewallForPort(EndpointsChanged(before, cand)) : null;
            if (restart)
            {
                await RestartWithRollback(backup, firewallBack == null ? null : firewallBack.Undo,
                    firewallBack == null ? null : firewallBack.Apply, firewallBack == null ? null : firewallBack.Keep);
            }
            else
            {
                if (firewallBack != null)
                {
                    try { await firewallBack.Apply(); }
                    catch (OperationCanceledException) { throw; }
                    catch (Exception ex) { throw new ConfigException("Settings were saved, but the firewall rule could not be updated for the new port: " + ex.Message + "\n\nRestart sshd when the Firewall tab allows the new port."); }
                }
                Status("Saved. Restart sshd to apply (default shell applies immediately)." + (firewallBack != null ? " The firewall allows the old and the new ports until then." : ""));
            }
        }

        /// <summary>Writes the default shell (HKLM\SOFTWARE\OpenSSH, applies to new sessions at once). False when it was refused.</summary>
        private async Task<bool> SaveDefaultShell(string shell, string option, bool configSaved)
        {
            try { await BgAsync("Saving the default shell...", () => _writeDefaultShell(shell, option)); await LoadSettings(true); return true; }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                // Keep a rejected registry edit available for correction or retry.
                _cmbShell.Text = shell; _txtShellOption.Text = option; UpdatePending();
                Log.Error(configSaved ? "sshd_config was saved, but the default shell could not be set" : "The default shell could not be set", ex, true);
                return false;
            }
        }

        /// <summary>Whether the top-level Port or ListenAddress lines differ: only then can a save change the ports sshd listens on.</summary>
        internal static bool EndpointsChanged(SshdConfig before, SshdConfig after)
        {
            Func<SshdConfig, string> endpoints = c => string.Join("\n", c.GetAll("Port").Concat(c.GetAll("ListenAddress")).Select(o => o.Value));
            return endpoints(before) != endpoints(after);
        }

        /// <summary>Whether a Settings save checks the firewall: it changes the ports, or it restarts sshd, which also applies a port saved earlier without a restart.</summary>
        internal static bool ChecksFirewall(SshdConfig before, SshdConfig after, bool restart) { return restart || EndpointsChanged(before, after); }

        /// <summary>A change to the firewall rule that goes with a change of sshd's port: undone with the settings, or finished when they are kept.</summary>
        private sealed class FirewallChange { public Func<Task> Apply; public Action Undo; public Func<Task> Keep; }

        /// <summary>
        /// When the firewall rule does not admit the port sshd will listen on, asks to add it. The rule keeps its old ports
        /// meanwhile, so sshd stays reachable whether the new settings are kept or not. Returns how to undo the change (a
        /// restart that is rolled back) and how to finish it (the new settings are kept: a rule that had a single port then
        /// drops the old one when sshd no longer uses it), or null when nothing changed. A rule that cannot be checked is a
        /// warning when this save changed the ports (portChanged), and only logged for a restart of ports saved earlier.
        /// </summary>
        private async Task<FirewallChange> OpenFirewallForPort(bool portChanged)
        {
            if (Program.Unattended) return null;
            ServerStateSnapshot state = null; FirewallRule fw = null; string notChecked = null;
            try
            {
                state = await BgAsync("Resolving the saved server endpoints...", ServerState.Read);
                if (!state.Verified) notChecked = "the SSH endpoints could not be verified. " + state.Error;
                else fw = await BgAsync("Reading the firewall rule...", () => Firewall.Find());
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex) { notChecked = "the firewall rule could not be read. " + ex.Message; }
            // The file is saved already: a firewall that cannot be checked is a warning, and a requested restart still runs.
            if (notChecked != null)
            {
                Log.Info("Firewall rule not checked " + (portChanged ? "after a port change: " : "before a restart: ") + notChecked);
                if (portChanged) MessageBox.Show(this, "Settings were saved, but the firewall rule was not checked for the new port: " + notChecked +
                    "\n\nCheck the Firewall tab: other computers can connect only on the ports it allows.", Program.AppName, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return null;
            }
            if (fw == null) return null;
            var missing = state.Ports.Where(p => !Firewall.Covers(fw.Ports, p)).ToArray();
            if (missing.Length == 0) return null;
            bool single = Firewall.IsSinglePort(fw.Ports);
            var question = "The firewall rule allows port" + (single ? " " : "s ") + fw.Ports + " but not " + string.Join(", ", missing) + ".\n\nAdd the missing configured or running SSH ports to the rule?" +
                           (single ? " Port " + fw.Ports + " stays open until the new settings are kept after the restart, so you can still connect if they are not." : "");
            if (MessageBox.Show(this, question, Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return null;
            var before = fw;
            var pending = fw.Ports + "," + string.Join(",", missing);
            return new FirewallChange
            {
                Apply = async () => { await BgAsync("Updating the firewall ports...", () => Firewall.Apply(before.Enabled, before.Profiles, pending)); await LoadFirewall(); Log.Info("Firewall ports expanded to " + pending); },
                Undo = () => { Firewall.Apply(before.Enabled, before.Profiles, before.Ports); Log.Info("Firewall rule: ports back to " + before.Ports); },
                Keep = async () =>
                {
                    if (!single) return;
                    var running = await BgAsync("Verifying the running listeners...", ServerState.Read);
                    if (!running.Verified) throw new ConfigException("The running listeners could not be verified, so the firewall rule could not be narrowed to them: " + running.Error);
                    await BgAsync("Keeping the firewall ports...", () => Firewall.Apply(before.Enabled, before.Profiles, running.FirewallPorts)); await LoadFirewall();
                    Status("New settings kept; the firewall allows all configured and running SSH ports: " + running.FirewallPorts);
                    Log.Info("Firewall rule kept ports " + running.FirewallPorts);
                },
            };
        }

        // ---------------- saving sshd_config, restarting, going back ----------------

        /// <summary>
        /// Saves a candidate configuration the way every tab does: warns when the account running this program would be
        /// refused afterwards, shows what changes (unless switched off), checks it with sshd -t, asks before writing over a
        /// file another program changed, keeps a backup. Returns the backup, or null when there was no file before.
        /// Throws OperationCanceledException (nothing written) when the person cancels.
        /// </summary>
        private async Task<string> SaveConfig(SshdConfig cand, string what, string okText = "Save")
        {
            var access = await BgAsync("Checking that you can still log in with the new settings...", () =>
            {
                // Text that is not UTF-8 would be replaced for good: refused before any question.
                var refusal = SshdConfig.NonUtf8Refusal(cand, File.Exists(cand.Path) ? File.ReadAllBytes(cand.Path) : null);
                if (refusal != null) throw new ConfigException(refusal);
                var tmp = WriteCandidate(cand);
                try { return AuthConfig.AccessWarning(tmp, cand.EffectivePort); } finally { try { File.Delete(tmp); } catch { } }
            });
            if (access != null && !Program.Unattended &&
                MessageBox.Show(this, "Warning: " + access + "\n\nOpen sessions stay connected, but new logins of your account would fail. Save anyway?", Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes)
                throw new OperationCanceledException();
            if (!ConfirmChanges(cand, what, okText)) throw new OperationCanceledException();
            try { return await SaveChecked(cand); }
            catch (PendingRecoveryException ex)
            {
                // Only a record that cannot complete by itself is offered; one within its deadline belongs to a running change.
                if (Program.Unattended || !ex.Record.Stuck(DateTime.UtcNow)) throw;
                var resolution = await ResolvePendingRecovery(ex.Record);
                if (resolution == RecoveryResolution.None) throw new OperationCanceledException();
                if (resolution == RecoveryResolution.Restored)
                    throw new ConfigException("The previous settings of the earlier change were restored, and sshd restarted. This change was NOT saved: the window now shows the restored file. Make the change again if you still want it.");
                return await SaveChecked(cand);
            }
        }

        private async Task<string> SaveChecked(SshdConfig cand)
        {
            try { return await BgAsync("Checking with sshd -t and saving...", () => cand.SaveValidated()); }
            catch (ConfigChangedException)
            {
                if (Program.Unattended) throw;
                var answer = MessageBox.Show(this, "sshd_config was changed by another program (or in Notepad) after this window read it.\n\n" +
                    "Yes: save anyway; the file as it is now is kept as a backup.\nNo: save nothing, so you can reload the file and make your change again.",
                    Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2);
                if (answer != DialogResult.Yes) throw new OperationCanceledException();
                return await BgAsync("Saving...", () => cand.SaveValidated(true));
            }
        }

        /// <summary>The preview before a save: true to go on. Not shown when switched off, in unattended modes, or when nothing changes.</summary>
        private bool ConfirmChanges(SshdConfig cand, string what, string okText)
        {
            if (Program.Unattended || !Prefs.PreviewChanges) return true;
            string current = "";
            try { if (File.Exists(cand.Path)) current = File.ReadAllText(cand.Path); } catch (Exception ex) { Log.Error("Reading " + cand.Path, ex, false); }
            if (Diff.SplitLines(current).SequenceEqual(Diff.SplitLines(cand.Text))) return true;
            using (var d = new ChangesDialog("Changes to sshd_config", what + " This is what changes in " + cand.Path + ". The file is checked with sshd -t before it is written, and the file as it is now is kept as a backup.", current, cand.Text, okText))
                return d.ShowDialog(this) == DialogResult.OK;
        }

        private enum RecoveryResolution { None, Restored, Cleared }

        /// <summary>
        /// At startup: a change whose recovery cannot complete by itself blocks every save, so it is offered for resolution.
        /// A record within its deadline belongs to a running change, perhaps in another window, and is left alone.
        /// </summary>
        private async Task CheckPendingRecovery()
        {
            if (Program.Unattended || !Elevation.IsAdministrator()) return;
            RecoveryRecordInfo info;
            try { info = await BgAsync("Checking configuration recovery...", () => ConfigurationRecovery.PendingInfo(Ssh.ConfigPath)); }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex) { Log.Error("Checking configuration recovery at startup", ex, false); return; }
            if (info != null && info.Stuck(DateTime.UtcNow)) await ResolvePendingRecovery(info);
        }

        /// <summary>
        /// The way out of a stuck recovery: restore the previous settings now, or keep the files as they are and cancel the
        /// recovery (confirmed once more, worded by how far the recovery got). An unreadable record can only be set aside.
        /// Cleared: nothing blocks a save any more and this window did not change the files.
        /// </summary>
        private async Task<RecoveryResolution> ResolvePendingRecovery(RecoveryRecordInfo info)
        {
            if (info.Damaged)
            {
                if (MessageBox.Show(this, "The recovery record of an earlier configuration change cannot be read:\n" + info.Error + "\n\n" + info.JournalPath +
                        "\n\nNo change to sshd_config can be saved while it is there. Set it aside? It stays beside the record for inspection; nothing restores the settings of the change it describes.",
                        Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes) return RecoveryResolution.None;
                var aside = await BgAsync("Setting the recovery record aside...", () => ConfigurationRecovery.OpenForPath(Ssh.ConfigPath).SetAsideDamaged());
                Log.Info("Unreadable recovery record set aside as " + aside);
                Status("The unreadable recovery record was set aside");
                return RecoveryResolution.Cleared;
            }
            string state = info.Phase == "configuration-restored" ? " (the previous sshd_config is back, but not the firewall rule, and sshd did not restart)"
                         : info.Phase == "firewall-restored" ? " (the previous sshd_config and firewall rule are back, but sshd did not restart)" : "";
            var answer = MessageBox.Show(this, "An earlier change to the SSH server configuration was not kept, and its previous settings could not be restored automatically" + state + ".\n\n" +
                "Recorded error: " + (info.Error.Length > 0 ? info.Error : "none; the recovery task has not run") + "\n\nNo other change can be saved until this is resolved.\n\n" +
                "Yes: restore the previous settings now (sshd restarts).\nNo: keep the files as they are now and cancel the recovery.\nCancel: decide later.",
                Program.AppName, MessageBoxButtons.YesNoCancel, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button3);
            if (answer == DialogResult.Yes)
            {
                Exception failure = null; RestoreResult result = null;
                try { result = await BgAsync("Restoring the previous settings...", () => ConfigurationRecovery.Open().RestoreNow(info.Id, DateTime.UtcNow)); }
                catch (OperationCanceledException) { throw; }
                catch (Exception ex) { failure = ex; }
                await ReloadAfterRecovery();
                if (failure != null) throw new ConfigException("The previous settings could not be restored: " + failure.Message);
                if (result.Outcome == RestoreOutcome.InProgressElsewhere) throw new ConfigException(RestoreText(result));
                if (!result.Restored) { Status(RestoreText(result)); return RecoveryResolution.Cleared; }
                if (result.Outcome == RestoreOutcome.Restored) Log.Info("Pending configuration recovery completed from the manager");
                ShowRestored(result);
                return RecoveryResolution.Restored;
            }
            if (answer != DialogResult.No) return RecoveryResolution.None;
            var question = info.Phase == "configuration-restored"
                ? "The previous sshd_config is back already, but the firewall rule is still as the unconfirmed change left it: a port the previous settings use may be closed.\n\nCancel the recovery anyway, and leave the firewall rule and sshd as they are? Check the Firewall tab afterwards."
                : info.Phase == "firewall-restored"
                ? "The previous sshd_config and firewall rule are back; only the restart of sshd failed.\n\nCancel the recovery, and restart sshd yourself later?"
                : "Keep the current sshd_config, which was never confirmed to work, and cancel the recovery? The firewall rule and sshd stay as they are, and nothing restores the previous settings afterwards.";
            if (MessageBox.Show(this, question, Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes) return RecoveryResolution.None;
            await BgAsync("Cancelling the recovery...", () => ConfigurationRecovery.OpenForPath(Ssh.ConfigPath).Abandon(info.Id, "Cancelled in the manager by " + Environment.UserName + "; the files were kept as they were."));
            Log.Info("Pending configuration recovery cancelled in the manager; the files were kept as they were (phase " + info.Phase + ")");
            Status("Recovery cancelled; the files are kept as they are");
            return RecoveryResolution.Cleared;
        }

        private async Task ReloadAfterRecovery()
        {
            await UseConfig(await BgAsync("Reading the configuration and Includes...", () => SshdConfig.Load())); await RefreshDashboard(); await LoadFirewall();
        }

        /// <summary>After a Settings save: a changed value that sshd does not use (an Include or a Match all block sets it first) is reported.</summary>
        private void ReportOverridden(List<Field> changed)
        {
            var eff = _effective; // LoadSettings (in UseConfig) read sshd -T again
            if (eff == null || eff.Count == 0) return;
            var notes = new List<string>();
            foreach (var f in changed.Where(x => x.Numeric || x.Choices != null))
            {
                var want = FieldValue(f); string have;
                if (want.Length == 0 || !eff.TryGetValue(f.Key, out have)) continue;
                if (f.Key.Equals("LogLevel", StringComparison.OrdinalIgnoreCase) && want.Equals("DEBUG", StringComparison.OrdinalIgnoreCase)) want = "DEBUG1";
                if (f.Key.Equals("Port", StringComparison.OrdinalIgnoreCase)) { if (!have.Split(new[] { ' ', ',' }, StringSplitOptions.RemoveEmptyEntries).Contains(want)) notes.Add(f.Label + ": sshd uses " + have); continue; }
                if (!have.Equals(want, StringComparison.OrdinalIgnoreCase)) notes.Add(f.Label + ": saved " + want + ", but sshd uses " + have);
            }
            if (notes.Count == 0) return;
            Status("Saved, but sshd uses other values for " + notes.Count + " setting(s)");
            if (!Program.Unattended)
                MessageBox.Show(this, "Saved, but sshd does not use these values:\n\n" + string.Join("\n", notes) + "\n\nAn Include file or a \"Match all\" block sets them before this line does. Look on the sshd_config (text) tab.", Program.AppName, MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }

        /// <summary>The result of checking a restarted server: what to show, and whether something looks wrong.</summary>
        private sealed class ServerCheck { public string Text; public bool Problems; public string Summary; }

        /// <summary>
        /// Checks the running server against a configuration: every port it should listen on has a listener that answers
        /// with an SSH banner, the firewall rule admits the ports, and the account running this program is not refused.
        /// Waits up to five seconds for listeners after a restart. Runs on a background thread.
        /// </summary>
        private static ServerCheck CheckServer(SshdConfig cfg)
        {
            var state = ServerState.Read();
            if (!state.Verified) return new ServerCheck { Problems = true, Summary = "Server inspection unavailable", Text = state.Error };
            var ports = state.ConfiguredPorts.ToList();
            var lines = new List<string>(); bool problems = false; var listening = new List<string>();
            var until = DateTime.UtcNow.AddSeconds(5);
            foreach (var port in ports)
            {
                var l = Net.Listeners(port);
                while (l.Count == 0 && DateTime.UtcNow < until) { Thread.Sleep(250); l = Net.Listeners(port); }
                if (l.Count == 0) { lines.Add("Nothing listens on port " + port + "."); problems = true; continue; }
                var banner = Net.BannerAt(l[0]);
                bool ssh = banner.StartsWith("SSH-", StringComparison.Ordinal);
                if (!ssh) problems = true;
                listening.AddRange(l);
                lines.Add("Listening on " + string.Join(", ", l) + (ssh ? "; answers " + banner : "; but " + l[0] + " gives no SSH answer: " + banner));
            }
            try
            {
                var fw = Firewall.Find();
                var blocked = fw == null ? ports : ports.Where(p => !Firewall.Covers(fw.Ports, p)).ToList();
                if (fw == null) { lines.Add("There is no inbound firewall rule for sshd: other computers cannot connect."); problems = true; }
                else if (!fw.Enabled) { lines.Add("The firewall rule for sshd is disabled: other computers cannot connect."); problems = true; }
                else if (blocked.Count > 0) { lines.Add("The firewall rule allows port " + fw.Ports + " but not " + string.Join(", ", blocked) + ": other computers cannot connect there."); problems = true; }
            }
            catch (Exception ex) { lines.Add("Firewall not checked: " + ex.Message); problems = true; }
            try
            {
                var access = AuthConfig.AccessWarning(null, ports[0]);
                if (access != null) { lines.Add(access); problems = true; }
                string err; var me = Accounts.AsciiLower(KeyGen.LoginName());
                var offered = AuthConfig.Probe(me, "localhost", ports[0], out err);
                if (offered != null) lines.Add("It offers " + me + " (you): " + AuthConfig.MethodNames(offered) + ".");
            }
            catch (Exception ex) { lines.Add("Login methods could not be checked: " + ex.Message); problems = true; Log.Error("Checking the login methods after a restart", ex, false); }
            return new ServerCheck { Text = string.Join("\n", lines), Problems = problems, Summary = listening.Count > 0 ? "sshd restarted; listening on " + string.Join(", ", listening) : "sshd restarted, but nothing is listening on port " + string.Join(", ", ports) };
        }

        /// <summary>
        /// The ports sshd listens on with a configuration, as servconf.c decides: a ListenAddress with a port uses that port,
        /// one without uses every Port (22 when there is none); without ListenAddress, every Port is used. A Port that no
        /// ListenAddress needs is not listened on, so it is not expected either.
        /// </summary>
        internal static List<int> ExpectedPorts(SshdConfig cfg)
        {
            var portLines = new List<int>();
            foreach (var p in cfg.GetAll("Port")) { int n; if (int.TryParse(p.Value, out n) && n > 0 && n < 65536 && !portLines.Contains(n)) portLines.Add(n); }
            if (portLines.Count == 0) portLines.Add(22);
            var addresses = cfg.GetAll("ListenAddress");
            if (addresses.Count == 0) return portLines;
            var ports = new List<int>();
            foreach (var la in addresses)
            {
                int n = SshdConfig.ListenPort(la.Value);
                foreach (var p in n > 0 ? new List<int> { n } : portLines) if (!ports.Contains(p)) ports.Add(p);
            }
            return ports;
        }

        /// <summary>Puts a backup back in place of sshd_config (the current file is kept as another backup first). Returns that backup.</summary>
        private static string RestoreFile(string backup)
        {
            string kept = null;
            if (File.Exists(Ssh.ConfigPath)) { kept = SshdConfig.NewBackupPath(Ssh.ConfigPath, DateTime.Now); File.Copy(Ssh.ConfigPath, kept, false); }
            ConfigurationTransaction.AtomicBytes(Ssh.ConfigPath, File.ReadAllBytes(backup)); // byte for byte, whatever its encoding
            Log.Info("Restored " + backup + " to " + Ssh.ConfigPath + (kept != null ? " (the replaced file is kept as " + kept + ")" : ""));
            return kept;
        }

        /// <summary>When sshd was restarted or started by this window (or a stop is expected): no "sshd stopped" notification then.</summary>
        private DateTime _expectedStateChange = DateTime.MinValue;

        /// <summary>
        /// Restarts sshd with the saved configuration. When it does not start, the previous file (backup) goes back and sshd
        /// starts again, without a question. When it starts, the server is checked (listening, answering, firewall, your
        /// access) and, unless switched off, you are asked to keep the new settings; without an answer in time, or with
        /// "Restore", the previous file goes back. True when sshd runs the new configuration. freshRecord: a restart that
        /// applies a file saved earlier, armed with a new record for backup (ArmFresh).
        /// </summary>
        private async Task<bool> RestartWithRollback(string backup, Action undo = null, Func<Task> apply = null, Func<Task> keep = null, bool freshRecord = false)
        {
            ConfigurationRecoveryTransaction recovery = null; string recoveryId = null;
            if (!Program.Unattended)
            {
                try
                {
                    recovery = ConfigurationRecovery.Open();
                    var armed = recovery; var due = DateTime.UtcNow.AddMinutes(5);
                    recoveryId = await BgAsync("Arming configuration recovery...", () => freshRecord ? armed.ArmFresh(backup, Firewall.CaptureForRecovery(), due) : armed.Arm(backup, Firewall.CaptureForRecovery(), due));
                }
                catch (OperationCanceledException) { throw; }
                catch (Exception ex)
                {
                    var message = "sshd_config is saved, but sshd was NOT restarted, so the saved settings are not in effect yet: configuration recovery could not be armed.\n\n" + ex.Message;
                    if (!RestartWithoutRecoveryAllowed(ex)) throw new ConfigException(message);
                    throw new RecoveryNotArmedException(message, ex.Message);
                }
            }
            if (apply != null)
            {
                if (recovery == null) await apply();
                else await AfterArm(recovery, recoveryId, apply, "The firewall could not be prepared for the new settings, so they were not applied.");
            }
            _expectedStateChange = DateTime.UtcNow;
            var failure = await BgAsync("Restarting sshd...", () => { try { Services.Restart("sshd"); return (Exception)null; } catch (Exception ex) { return ex; } });
            _expectedStateChange = DateTime.UtcNow;
            if (failure != null)
            {
                if (recovery != null)
                {
                    var error = await RestoredAfter(recovery, recoveryId, work => BgAsync("Restoring the previous settings...", work), "sshd did not start with the new settings.", failure);
                    await ReloadAfterRecovery();
                    throw error;
                }
                if (backup == null || !File.Exists(backup)) { await RefreshDashboard(); throw failure; }
                string kept = null; Exception again = null;
                await BgAsync("sshd did not start: restoring the previous configuration...", () =>
                {
                    kept = RestoreFile(backup);
                    if (undo != null) { try { undo(); } catch (Exception ex) { Log.Error("Undoing the change that went with the new settings", ex, false); } }
                    try { Services.Start("sshd"); } catch (Exception ex) { again = ex; }
                });
                _expectedStateChange = DateTime.UtcNow;
                await UseConfig(await BgAsync("Reading the configuration and Includes...", () => SshdConfig.Load())); await RefreshDashboard(); if (undo != null) await LoadFirewall();
                Status(again == null ? "sshd did not start with the new configuration; the previous one was restored and sshd runs" : "sshd did not start, not even with the previous configuration");
                if (!Program.Unattended)
                    MessageBox.Show(this, "sshd did not start with the new configuration:\n" + failure.Message + "\n\n" +
                        (again == null ? "The previous sshd_config was restored and sshd started again." : "The previous sshd_config was restored, but sshd did not start either: " + again.Message + "\nSee the Logs tab.") +
                        (kept != null ? "\n\nThe configuration that failed is kept as " + Path.GetFileName(kept) + " (Settings tab, Backups)." : ""),
                        Program.AppName, MessageBoxButtons.OK, MessageBoxIcon.Error);
                return false;
            }
            var cfg = _cfg;
            var check = await BgAsync("Checking the restarted server...", () => CheckServer(cfg));
            await LoadSettings(true); await RefreshDashboard(); // the effective values after the restart
            Status(check.Summary);
            const string notKept = "The new settings could not be finalized, so they were NOT kept.";
            if (Program.Unattended || !Prefs.ConfirmAfterRestart)
            {
                if (recovery != null) await AfterArm(recovery, recoveryId, () => recovery.ConfirmAsync(recoveryId, keep), notKept);
                else if (keep != null) await keep();
                return true;
            }
            var deadline = DateTime.UtcNow.AddSeconds(Prefs.ConfirmSeconds);
            if (recovery != null) await BgAsync("Starting the confirmation deadline...", () => recovery.SetDeadline(recoveryId, deadline));
            DialogResult answer;
            using (var d = new KeepSettingsDialog(check.Text, check.Problems, deadline, async () => { var c = await BgAsync("Checking...", () => CheckServer(cfg)); return new KeyValuePair<string, bool>(c.Text, c.Problems); }))
                answer = d.ShowDialog(this);
            if (answer == DialogResult.OK)
            {
                if (recovery != null) await AfterArm(recovery, recoveryId, () => recovery.ConfirmAsync(recoveryId, keep), notKept);
                else if (keep != null) await keep();
                Status("New settings kept. " + check.Summary); Log.Info("New settings kept after the restart"); return true;
            }
            if (recovery != null)
            {
                Exception restoreError = null; RestoreResult result = null;
                try { result = await BgAsync("Restoring the previous settings...", () => recovery.RestoreNow(recoveryId, DateTime.UtcNow)); }
                catch (OperationCanceledException) { throw; }
                catch (Exception ex) { restoreError = ex; }
                await ReloadAfterRecovery();
                if (restoreError != null) throw new ConfigException("The new settings were not kept, but restoring the previous settings failed, so the recovery task keeps trying every minute: " + restoreError.Message);
                if (!result.Restored) throw new ConfigException("The new settings were not kept here. " + RestoreText(result));
                ShowRestored(result);
                return false;
            }
            Exception startError = null; string replaced = null;
            await BgAsync("Restoring the previous settings...", () =>
            {
                replaced = RestoreFile(backup);
                if (undo != null) { try { undo(); } catch (Exception ex) { Log.Error("Undoing the change that went with the new settings", ex, false); } }
                try { Services.Restart("sshd"); } catch (Exception ex) { startError = ex; }
            });
            _expectedStateChange = DateTime.UtcNow;
            await UseConfig(await BgAsync("Reading the configuration and Includes...", () => SshdConfig.Load())); await RefreshDashboard(); if (undo != null) await LoadFirewall();
            Log.Info("The previous settings were restored after the restart (" + (answer == DialogResult.Abort ? "no answer or Restore" : answer.ToString()) + ")");
            Status(startError == null ? "The previous settings were restored and sshd restarted" : "The previous settings were restored, but sshd did not start: " + startError.Message);
            MessageBox.Show(this, (startError == null ? "The previous settings were restored and sshd restarted with them." : "The previous settings were restored, but sshd did not start: " + startError.Message) +
                (replaced != null ? "\n\nThe new settings are kept as " + Path.GetFileName(replaced) + " (Settings tab, Backups), in case you want them back." : ""),
                Program.AppName, MessageBoxButtons.OK, startError == null ? MessageBoxIcon.Information : MessageBoxIcon.Error);
            return false;
        }

        /// <summary>Recovery could not be armed for a restart, and nothing was changed: a restart without it may be offered.</summary>
        private sealed class RecoveryNotArmedException : ConfigException
        {
            public readonly string Reason;
            public RecoveryNotArmedException(string message, string reason) : base(message) { Reason = reason; }
        }

        /// <summary>
        /// Whether a restart without recovery may be offered after arming failed: only when recovery itself is unavailable
        /// (service definition, storage, firewall capture, task), never when the journal refused the restart because another
        /// change is pending or another operation runs, or the file changed meanwhile.
        /// </summary>
        internal static bool RestartWithoutRecoveryAllowed(Exception armingFailure)
        {
            return !(armingFailure is PendingRecoveryException || armingFailure is ConfigChangedException || armingFailure is ConfigurationBusyException);
        }

        /// <summary>A step after recovery was armed; when it fails, the previous settings are restored at once and the window reloaded.</summary>
        private async Task AfterArm(ConfigurationRecoveryTransaction recovery, string id, Func<Task> step, string failed)
        {
            ConfigException error = null;
            try { await RecoverOnFailure(recovery, id, step, work => BgAsync("Restoring the previous settings...", work), failed); }
            catch (ConfigException ex) { error = ex; }
            if (error == null) return;
            try { await ReloadAfterRecovery(); }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex) { Log.Error("Reloading after the previous settings were restored", ex, false); }
            throw error;
        }

        /// <summary>
        /// Runs a step after recovery was armed (the firewall before the restart, Keep after it). When it fails other than by
        /// cancellation, the previous settings are restored at once instead of staying armed behind a message that suggests
        /// the new ones are in effect; the ConfigException says what became of them.
        /// </summary>
        internal static async Task RecoverOnFailure(ConfigurationRecoveryTransaction recovery, string id, Func<Task> step, Func<Func<RestoreResult>, Task<RestoreResult>> background, string failed)
        {
            Exception failure;
            try { await step(); return; }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex) { failure = ex; }
            throw await RestoredAfter(recovery, id, background, failed, failure);
        }

        /// <summary>Restores the previous settings now, after a failure, and returns the exception that says how that went.</summary>
        internal static async Task<ConfigException> RestoredAfter(ConfigurationRecoveryTransaction recovery, string id, Func<Func<RestoreResult>, Task<RestoreResult>> background, string failed, Exception failure)
        {
            RestoreResult result;
            try { result = await background(() => recovery.RestoreNow(id, DateTime.UtcNow)); }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex) { return new ConfigException(failed + " Restoring the previous settings failed as well, so the recovery task keeps trying every minute: " + ex.Message + "\n\n" + failure.Message); }
            return new ConfigException(failed + " " + RestoreText(result) + "\n\n" + failure.Message);
        }

        /// <summary>What became of the previous settings after a window asked to restore them, in words that match the outcome.</summary>
        internal static string RestoreText(RestoreResult result)
        {
            switch (result.Outcome)
            {
                case RestoreOutcome.InProgressElsewhere:
                    return "Another process is restoring the previous settings right now (normally the recovery task, at the deadline). Look at the Dashboard in a moment, or reload, to see the result.";
                case RestoreOutcome.ResolvedElsewhere:
                    return "The change was already resolved elsewhere (kept, cancelled or followed by another change in another manager window); the window shows the file as it is now.";
            }
            var text = result.Outcome == RestoreOutcome.RestoredElsewhere
                ? "The recovery task (or another manager window) got there first: the previous settings were restored and sshd restarted."
                : "The previous settings were restored and sshd restarted.";
            if (result.SavedMeanwhile != null)
                text += " These are the settings sshd ran before this restart: the file saved without a restart in between, which sshd never ran, is no longer in sshd_config and is kept as " +
                        Path.GetFileName(result.SavedMeanwhile) + " (Settings tab, Backups).";
            return text;
        }

        /// <summary>A restore that went through: the status line, and a message when a file saved without a restart was set aside.</summary>
        private void ShowRestored(RestoreResult result)
        {
            Status(result.Outcome == RestoreOutcome.RestoredElsewhere ? "The previous settings were restored (by the recovery task or another window) and sshd restarted" : "The previous settings were restored and sshd restarted");
            if (result.SavedMeanwhile != null && !Program.Unattended) MessageBox.Show(this, RestoreText(result), Program.AppName, MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        /// <summary>Reload on the Settings tab (discardRaw false) or on the text tab (discardSettings false): the tab's own edits are discarded.</summary>
        private async Task ReloadFromFile(bool discardSettings = true, bool discardRaw = false) { await UseConfig(await BgAsync("Reading the configuration and Includes...", () => SshdConfig.Load()), !discardSettings, !discardRaw); Status("Reloaded"); }

        /// <summary>
        /// Makes c the configuration every tab works on, after it was saved or read from the file, and shows it on every tab.
        /// Edits are made on a copy (SshdConfig.Copy) and adopted only after the save succeeded, so an edit that was not
        /// saved never reaches the next save of another tab. Login-method changes not applied yet are kept when the file
        /// has the same login methods as when they were made; otherwise the tab shows the file. Unsaved edits on the Settings
        /// and text tabs are kept (keep...Edits) unless it is that tab's own save or reload.
        /// </summary>
        private async Task UseConfig(SshdConfig c, bool keepSettingsEdits = true, bool keepRawEdits = true)
        {
            _cfg = c;
            await LoadSettings(keepSettingsEdits); LoadRaw(keepRawEdits);
            var fromFile = AuthConfig.Read(c);
            if (!AuthEdited() || !SameAuth(fromFile, _auState)) { bool lost = AuthEdited(); LoadAuth(); if (lost) Status("sshd_config changed: the login-method changes not applied yet were replaced by the file"); }
            else { _auState = fromFile; FillRules(); UpdateAuthUi(); }
            var sftpFromFile = SftpConfig.Read(c);
            if (!SftpEdited() || !SameSftp(sftpFromFile, _sfFile)) { bool lost = SftpEdited(); LoadSftp(); if (lost) Status("sshd_config changed: the SFTP changes not applied yet were replaced by the file"); }
            else { _sfFile = sftpFromFile; FillSftpRules(); UpdateSftpUi(); }
            _lvChecks.Items.Clear(); // run again from the new configuration when the tab is opened
            _ptLoaded = false; // the partner setup depends on sshd_config: read again when the tab is opened
            if (_pgPartners != null && _tabs.SelectedTab == _pgPartners) await SafeAsync(LoadPartners, false);
        }

        private static bool SameAuth(AuthState a, AuthState b)
        {
            return a.RulesProblem == b.RulesProblem && a.Global.SameAs(b.Global) && a.Rules.Count == b.Rules.Count && a.Rules.Where((r, i) => !r.SameAs(b.Rules[i])).Count() == 0;
        }

        private async Task RestoreBackup()
        {
            string chosen;
            var current = File.Exists(Ssh.ConfigPath) ? File.ReadAllText(Ssh.ConfigPath) : "";
            using (var dlg = new BackupsDialog(Ssh.ConfigPath, current))
            {
                if (dlg.ShowDialog(this) != DialogResult.OK || dlg.Chosen == null) return;
                chosen = dlg.Chosen;
            }
            // Its exact bytes are checked and written, so text that is not UTF-8 comes back unchanged.
            var cand = await BgAsync("Reading the backup and Includes...", () => SshdConfig.LoadExact(chosen)); cand.Path = Ssh.ConfigPath; cand.LoadedHash = _cfg.LoadedHash;
            var backup = await SaveConfig(cand, "Restore the backup " + Path.GetFileName(chosen) + ".", "Restore");
            await UseConfig(await BgAsync("Reading the configuration and Includes...", () => SshdConfig.Load()));
            if (MessageBox.Show(this, "Backup restored (previous file saved as " + (backup == null ? "none" : Path.GetFileName(backup)) + "). Restart sshd now?", Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes) await RestartWithRollback(backup);
        }

        private async Task ResetToDefault()
        {
            if (!File.Exists(Ssh.DefaultConfigPath)) throw new Exception("sshd_config_default not found in " + Ssh.InstallDir);
            var cand = await BgAsync("Reading the default configuration and Includes...", () => SshdConfig.Load(Ssh.DefaultConfigPath)); cand.Path = Ssh.ConfigPath; cand.LoadedHash = _cfg.LoadedHash;
            if (!Prefs.PreviewChanges && MessageBox.Show(this, "Replace sshd_config with the shipped sshd_config_default? Your current file is backed up first.", Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;
            var backup = await SaveConfig(cand, "Replace sshd_config with the shipped sshd_config_default: every setting and rule made here is removed.", "Replace");
            await UseConfig(await BgAsync("Reading the configuration and Includes...", () => SshdConfig.Load()));
            Status("Defaults written; backup " + (backup == null ? "none" : Path.GetFileName(backup)) + ". Restart sshd to apply.");
        }

        // ---------------- Authentication ----------------
        private TabPage BuildAuthentication()
        {
            var page = new TabPage("Authentication");
            var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 7, Padding = new Padding(8) };
            for (int i = 0; i < 7; i++) root.RowStyles.Add(i == 2 ? new RowStyle(SizeType.Percent, 100) : new RowStyle(SizeType.AutoSize));

            var top = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoSize = true, Dock = DockStyle.Top };
            top.Controls.Add(Lbl("Login methods for all accounts", true));
            _auPassword = new CheckBox { Text = "Windows authentication: the Windows account name and password (local and domain accounts)", AutoSize = true, Margin = new Padding(16, 4, 4, 1) };
            _auKey = new CheckBox { Text = "Public key: a key in the account's authorized_keys file (create one on the Key generator tab)", AutoSize = true, Margin = new Padding(16, 1, 4, 1) };
            _auKerberos = new CheckBox { Text = "Kerberos single sign-on: domain accounts on domain computers, without a password prompt", AutoSize = true, Margin = new Padding(16, 1, 4, 1) };
            top.Controls.Add(_auPassword); top.Controls.Add(_auKey); top.Controls.Add(_auKerberos);
            top.Controls.Add(new Label { Text = "When Windows authentication and public key are both ticked:", AutoSize = true, Margin = new Padding(16, 8, 4, 1) });
            _auEither = new RadioButton { Text = "Either one is enough", AutoSize = true, Margin = new Padding(36, 1, 4, 0) };
            _auBoth = new RadioButton { Text = "Both are required: the key first, then the Windows password (two-factor)", AutoSize = true, Margin = new Padding(36, 0, 4, 0) };
            _auCustom = new RadioButton { AutoSize = true, Margin = new Padding(36, 0, 4, 0), Visible = false };
            top.Controls.Add(_auEither); top.Controls.Add(_auBoth); top.Controls.Add(_auCustom);
            _auSummary = new Label { AutoSize = true, Margin = new Padding(16, 8, 4, 1) };
            _auSummary.Font = BoldFont();
            top.Controls.Add(_auSummary);
            top.Controls.Add(new Label
            {
                AutoSize = true, ForeColor = Theme.Muted, MaximumSize = new Size(Ui.Px(980), 0), Margin = new Padding(16, 2, 4, 6),
                Text = "Keyboard-interactive is switched off when you apply: OpenSSH for Windows has no back end for it, so it never logs anyone in, and each client attempt at it counts against MaxAuthTries. Windows passwords use the password method."
            });
            root.Controls.Add(top, 0, 0);

            var head = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoSize = true, Dock = DockStyle.Top };
            head.Controls.Add(Lbl("Rules for specific users and groups", true));
            _auRulesNote = new Label { AutoSize = true, MaximumSize = new Size(Ui.Px(980), 0), Margin = new Padding(16, 0, 4, 4), ForeColor = Theme.Muted };
            head.Controls.Add(_auRulesNote);
            root.Controls.Add(head, 0, 1);

            _lvRules = Lv("Applies to|90", "Name|220", "Login methods|560"); _lvRules.AccessibleName = "Rules for users and groups";
            _lvRules.Margin = new Padding(16, 0, 4, 0);
            ListSorter.Disable(_lvRules); // the order is the precedence: the first rule that matches applies
            _lvRules.ItemActivate += (s, e) => Safe(EditRule); // double-click or Enter
            _lvRules.KeyDown += (s, e) => { if (e.KeyCode == System.Windows.Forms.Keys.Delete) { e.Handled = true; Safe(RemoveRule); } };
            _lvRules.SelectedIndexChanged += (s, e) => UpdateRuleButtons();
            root.Controls.Add(_lvRules, 0, 2);
            var rb = Flow();
            rb.Padding = new Padding(12, 0, 4, 0);
            _auRuleButtons = new[]
            {
                Btn("Add...", (s, e) => Safe(AddRule), 110), Btn("Edit...", (s, e) => Safe(EditRule), 110), Btn("Remove", (s, e) => Safe(RemoveRule), 110),
                Btn("Move up", (s, e) => Safe(() => MoveRule(-1)), 110), Btn("Move down", (s, e) => Safe(() => MoveRule(1)), 110),
            };
            foreach (var b in _auRuleButtons) rb.Controls.Add(b);
            _tips.SetToolTip(_auRuleButtons[3], "The first rule that matches an account applies: move a rule up to give it precedence.");
            root.Controls.Add(rb, 0, 3);

            var check = Flow();
            check.Controls.Add(Lbl("Check an account:"));
            _auAccount = new TextBox { Width = Ui.Px(240), Margin = new Padding(4, 6, 4, 4), Text = KeyGen.LoginName(), AccessibleName = "Account to check" };
            check.Controls.Add(_auAccount);
            var btnShow = Btn("Show its login methods", async (s, e) => await SafeAsync(async () => await CheckAccount(false)), 190);
            var btnAsk = Btn("Ask the running server", async (s, e) => await SafeAsync(async () => await CheckAccount(true)), 190);
            check.Controls.Add(btnShow); check.Controls.Add(btnAsk);
            _tips.SetToolTip(btnShow, "What sshd works out for this account from the settings on this tab, applied or not (sshd -T with the rules and any other Match blocks; run as SYSTEM for other accounts, like the service).");
            _tips.SetToolTip(btnAsk, "Connects to this server with the account name only (no password, no key) and shows the methods the server offers.");
            root.Controls.Add(check, 0, 4);

            _auResult = new Label
            {
                AutoSize = true, MaximumSize = new Size(Ui.Px(980), 0), Margin = new Padding(8, 2, 4, 4), ForeColor = Theme.Muted,
                Text = "Apply checks the settings with sshd -t, keeps the previous sshd_config as a backup, restarts sshd (and restores the backup if sshd does not start), then asks the running server which methods it offers you. Connected sessions stay connected."
            };
            root.Controls.Add(_auResult, 0, 5);

            var bar = Flow();
            bar.Controls.Add(Btn("Apply and restart sshd", async (s, e) => await SafeAsync(ApplyAuth), 190));
            bar.Controls.Add(Btn("Undo changes", (s, e) => Safe(() => { LoadAuth(); Status("Login methods reloaded from sshd_config"); }), 130));
            _auPending = new Label { AutoSize = true, Margin = new Padding(12, 10, 4, 4), ForeColor = Orange };
            bar.Controls.Add(_auPending);
            root.Controls.Add(bar, 0, 6);

            EventHandler changed = (s, e) => { if (!_auLoading) UpdateAuthUi(); };
            _auPassword.CheckedChanged += changed; _auKey.CheckedChanged += changed; _auKerberos.CheckedChanged += changed;
            _auEither.CheckedChanged += changed; _auBoth.CheckedChanged += changed; _auCustom.CheckedChanged += changed;
            _tips.SetToolTip(_auPassword, "PasswordAuthentication. Windows checks the password (LogonUser), so its password and account lockout policies apply.");
            _tips.SetToolTip(_auKey, "PubkeyAuthentication. Administrators use administrators_authorized_keys, other accounts .ssh\\authorized_keys in their profile (see the Keys tab).");
            _tips.SetToolTip(_auBoth, "AuthenticationMethods publickey,password");
            page.Controls.Add(root);
            return page;
        }

        private void LoadAuth()
        {
            _auState = AuthConfig.Read(_cfg);
            _auRules = _auState.Rules.Select(r => r.Clone()).ToList();
            var g = _auState.Global;
            bool domain = Accounts.DomainJoined();
            _auLoading = true;
            try
            {
                _auPassword.Checked = g.Password; _auKey.Checked = g.PublicKey; _auKerberos.Checked = g.Kerberos;
                _auCustom.Visible = g.Custom != null;
                _auCustom.Text = g.Custom == null ? "" : "Keep the rule written in sshd_config: AuthenticationMethods " + g.Custom;
                if (g.Custom != null) _auCustom.Checked = true; else if (g.RequireBoth) _auBoth.Checked = true; else _auEither.Checked = true;
                // Kerberos needs an Active Directory domain; where it is on already it can still be switched off.
                _auKerberos.Enabled = domain || g.Kerberos;
                _tips.SetToolTip(_auKerberos, domain ? "GSSAPIAuthentication. Clients: ssh -K, or GSSAPIAuthentication yes, while logged on with a domain account."
                                                     : "This computer is not joined to an Active Directory domain, so Kerberos cannot work here (GSSAPIAuthentication).");
            }
            finally { _auLoading = false; }
            FillRules();
            UpdateAuthUi();
        }

        private void FillRules()
        {
            _lvRules.BeginUpdate(); _lvRules.Items.Clear();
            foreach (var r in _auRules) _lvRules.Items.Add(new ListViewItem(new[] { r.Kind, r.Name, r.Methods.Describe() }));
            _lvRules.EndUpdate();
            var notes = new List<string>();
            if (_auState.RulesProblem != null)
                notes.Add("The rules section in sshd_config was changed by hand (" + _auState.RulesProblem + "), so it is left as it is. Correct it on the sshd_config (text) tab, or delete it to manage the rules here.");
            else
                notes.Add("The first rule that matches an account applies; accounts without a rule use the methods above. Group rules work with local, built-in and domain groups.");
            if (_auState.OtherMatchSettings.Count > 0)
                notes.Add("Other Match blocks in sshd_config set login methods too, as written there: " + string.Join("; ", _auState.OtherMatchSettings.Take(3)) + (_auState.OtherMatchSettings.Count > 3 ? "; ..." : "") + ".");
            _auRulesNote.Text = string.Join("\n", notes);
            _auRulesNote.ForeColor = _auState.RulesProblem != null || _auState.OtherMatchSettings.Count > 0 ? Orange : Theme.Muted;
            UpdateRuleButtons();
        }

        private void UpdateRuleButtons()
        {
            bool editable = _auState.RulesProblem == null;
            int i = _lvRules.SelectedIndices.Count > 0 ? _lvRules.SelectedIndices[0] : -1;
            _auRuleButtons[0].Enabled = editable;
            _auRuleButtons[1].Enabled = _auRuleButtons[2].Enabled = editable && i >= 0;
            _auRuleButtons[3].Enabled = editable && i > 0;
            _auRuleButtons[4].Enabled = editable && i >= 0 && i < _auRules.Count - 1;
        }

        /// <summary>The methods for all accounts as ticked on the tab.</summary>
        private AuthMethods AuthFromUi()
        {
            var m = new AuthMethods { Password = _auPassword.Checked, PublicKey = _auKey.Checked, Kerberos = _auKerberos.Checked };
            if (_auCustom.Visible && _auCustom.Checked) m.Custom = _auState.Global.Custom;
            else m.RequireBoth = _auBoth.Checked;
            return m;
        }

        private void UpdateAuthUi()
        {
            _auEither.Enabled = _auBoth.Enabled = _auPassword.Checked && _auKey.Checked;
            var m = AuthFromUi();
            _auSummary.Text = m.AnyEnabled ? "Accounts without a rule log in with: " + m.Describe() : "Tick at least one login method.";
            _auSummary.ForeColor = m.AnyEnabled ? Theme.Text : Red;
            _auPending.Text = AuthEdited() ? "Changes not applied yet" : "";
            UpdatePending();
        }

        /// <summary>True when the Authentication tab has changes that were not applied.</summary>
        private bool AuthEdited()
        {
            var m = AuthFromUi();
            return !m.SameAs(_auState.Global) || _auRules.Count != _auState.Rules.Count || _auRules.Where((r, i) => !r.SameAs(_auState.Rules[i])).Any();
        }

        private void AddRule()
        {
            using (var dlg = new RuleDialog(null, _auRules, _auKerberos.Enabled))
            {
                if (dlg.ShowDialog(this) != DialogResult.OK) return;
                _auRules.Add(dlg.Result); FillRules(); UpdateAuthUi();
                _lvRules.Items[_lvRules.Items.Count - 1].Selected = true;
            }
        }

        private void EditRule()
        {
            if (_auState.RulesProblem != null || _lvRules.SelectedIndices.Count == 0) return;
            int i = _lvRules.SelectedIndices[0];
            using (var dlg = new RuleDialog(_auRules[i], _auRules.Where((r, j) => j != i).ToList(), _auKerberos.Enabled))
            {
                if (dlg.ShowDialog(this) != DialogResult.OK) return;
                _auRules[i] = dlg.Result; FillRules(); UpdateAuthUi();
                _lvRules.Items[i].Selected = true;
            }
        }

        private void RemoveRule()
        {
            if (_auState.RulesProblem != null || _lvRules.SelectedIndices.Count == 0) return;
            _auRules.RemoveAt(_lvRules.SelectedIndices[0]); FillRules(); UpdateAuthUi();
        }

        private void MoveRule(int delta)
        {
            if (_auState.RulesProblem != null || _lvRules.SelectedIndices.Count == 0) return;
            int i = _lvRules.SelectedIndices[0], j = i + delta;
            if (j < 0 || j >= _auRules.Count) return;
            var r = _auRules[i]; _auRules[i] = _auRules[j]; _auRules[j] = r;
            FillRules(); UpdateAuthUi();
            _lvRules.Items[j].Selected = true; _lvRules.Focus();
        }

        /// <summary>sshd_config as it would be with the settings on this tab (nothing is saved).</summary>
        private SshdConfig AuthCandidate()
        {
            var cand = _cfg.Copy();
            AuthConfig.Apply(cand, AuthFromUi(), _auState.RulesProblem == null ? _auRules : null);
            return cand;
        }

        private static string WriteCandidate(SshdConfig c)
        {
            var tmp = Path.Combine(Path.GetTempPath(), "sshd_config.candidate." + Guid.NewGuid().ToString("N"));
            File.WriteAllText(tmp, c.Text, new UTF8Encoding(false));
            return tmp;
        }

        private async Task ApplyAuth()
        {
            var global = AuthFromUi();
            var cand = AuthCandidate();
            string warning = null; RunResult t = null;
            var tmp = WriteCandidate(cand);
            try
            {
                await BgAsync("Checking the new settings with sshd...", () =>
                {
                    t = Ssh.TestConfig(tmp);
                    if (t.Ok) warning = AuthConfig.LockoutWarning(tmp, cand.EffectivePort);
                });
            }
            finally { try { File.Delete(tmp); } catch { } }
            if (!t.Ok) throw new ConfigException("The login methods were NOT applied because sshd rejected them:\n\n" + t.Output.Replace(tmp, "sshd_config"));
            var rules = _auState.RulesProblem != null ? "The rules section edited by hand is left as it is."
                      : _auRules.Count == 0 ? "No rules for users or groups."
                      : string.Join("\n", _auRules.Select((r, i) => (i + 1) + ". " + r.Kind + " " + r.Name + ": " + r.Methods.Describe()));
            var text = (warning != null ? "Warning: " + warning + "\n\n" : "") + "Apply these login methods and restart sshd?\n\nAccounts without a rule: " + global.Describe() + ".\n" + rules +
                       "\n\nsshd_config is backed up first. Connected sessions stay connected.";
            if (MessageBox.Show(this, text, Program.AppName, MessageBoxButtons.YesNo, warning != null ? MessageBoxIcon.Warning : MessageBoxIcon.Question,
                    warning != null ? MessageBoxDefaultButton.Button2 : MessageBoxDefaultButton.Button1) != DialogResult.Yes) { Status("Login methods not applied"); return; }
            var backup = await SaveConfig(cand, "Apply the login methods of the Authentication tab.", "Apply");
            Log.Info("Login methods applied: " + global.Describe() + "; " + (_auState.RulesProblem == null ? _auRules.Count + " rule(s)" : "rules section left as it is"));
            _cfg = await BgAsync("Reading the configuration and Includes...", () => SshdConfig.Load()); LoadAuth(); await UseConfig(_cfg); // the applied methods are now the file's
            if (await RestartWithRollback(backup)) await VerifyAuth();
        }

        /// <summary>After Apply: asks the running server which methods it offers the current account, and compares with sshd -T.</summary>
        private async Task VerifyAuth()
        {
            var me = Accounts.AsciiLower(KeyGen.LoginName());
            int port = _cfg.EffectivePort;
            string e1 = null, e2 = null; AuthMethods expected = null; SortedSet<string> offered = null;
            await BgAsync("Asking the running server which login methods it offers...", () =>
            {
                expected = AuthConfig.EffectiveFor(me, null, port, out e1);
                offered = AuthConfig.Probe(me, "localhost", port, out e2);
            });
            if (expected == null || offered == null)
                SetAuthResult("Applied. The running server could not be asked which methods it offers (" + (e1 ?? e2) + ").", Orange);
            else if (expected.Offered().SetEquals(offered))
                SetAuthResult("Applied and verified: the running server offers " + me + " (you) " + AuthConfig.MethodNames(offered) + (expected.BothRequired ? ", then the Windows password" : "") + ".", Green);
            else
                SetAuthResult("Applied, but the running server offers " + me + " (you) " + AuthConfig.MethodNames(offered) + " instead of " + AuthConfig.MethodNames(expected.Offered()) + ". Look for other Match blocks on the sshd_config (text) tab.", Red);
            Status("Login methods applied");
        }

        private void SetAuthResult(string text, Color color) { _auResult.Text = text; _auResult.ForeColor = color; }

        /// <summary>Shows the login methods of one account: from the settings on this tab (sshd -T), or as the running server offers them.</summary>
        private async Task CheckAccount(bool live)
        {
            string err = null;
            var typed = _auAccount.Text.Trim();
            var input = typed.Length == 0 ? KeyGen.LoginName() : typed;
            // Name lookups can wait for a domain controller: never on the window's thread.
            var name = await BgAsync("Looking up the account...", () => Accounts.Canonical(input, false, out err));
            if (name == null) throw new ConfigException(err);
            int port = _cfg.EffectivePort;
            if (live)
            {
                SortedSet<string> offered = null;
                await BgAsync("Asking the running server...", () => offered = AuthConfig.Probe(name, "localhost", port, out err));
                if (offered == null) { SetAuthResult("The running server gave no list of methods for " + name + ": " + err, Red); return; }
                SetAuthResult("The running server offers " + name + ": " + AuthConfig.MethodNames(offered) + "." + (_auPending.Text.Length > 0 ? " Changes on this tab count only after Apply." : ""), Theme.Text);
                return;
            }
            var tmp = WriteCandidate(AuthCandidate());
            Dictionary<string, string> d = null;
            try { await BgAsync("Asking sshd...", () => d = AuthConfig.EffectiveSettingsFor(name, tmp, port, out err)); }
            finally { try { File.Delete(tmp); } catch { } }
            if (d == null) throw new ConfigException("sshd could not work out the settings for " + name + ":\n\n" + (err ?? "").Replace(tmp, "sshd_config"));
            var m = AuthConfig.MethodsFrom(d);
            var sb = new StringBuilder(name + " logs in with: " + m.Describe() + (_auPending.Text.Length > 0 ? " (the settings on this tab, not applied yet)" : "") + ".");
            if (m.PublicKey)
            {
                string value; d.TryGetValue("authorizedkeysfile", out value);
                string home = null, file = null; int n = 0;
                await BgAsync("Reading the authorized keys...", () =>
                {
                    home = Accounts.ProfileDir(Acl.SidOfAccount(name));
                    file = Ssh.ResolveKeysFile(value, name, home);
                    if (file != null) { try { n = Keys.Read(file).Count(k => k.Type != "?"); } catch { } }
                });
                if (file == null) sb.Append(home == null ? " The account has not logged on yet, so it has no profile and no authorized_keys file." : " No authorized_keys file is configured.");
                else sb.Append(" Keys authorized: " + n + " in " + file + ".");
            }
            var limits = new[] { "allowusers", "allowgroups", "denyusers", "denygroups" }.Where(k => d.ContainsKey(k) && d[k].Length > 0).Select(k => k + " " + d[k]).ToList();
            if (limits.Count > 0) sb.Append(" sshd_config also limits who may log in: " + string.Join("; ", limits) + ".");
            SetAuthResult(sb.ToString(), Theme.Text);
        }

        // ---------------- SFTP ----------------
        private TabPage BuildSftp()
        {
            var page = new TabPage("SFTP");
            var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 7, Padding = new Padding(8) };
            for (int i = 0; i < 7; i++) root.RowStyles.Add(i == 2 ? new RowStyle(SizeType.Percent, 100) : new RowStyle(SizeType.AutoSize));

            var top = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoSize = true, Dock = DockStyle.Top };
            top.Controls.Add(Lbl("SFTP server", true));
            _sfEnabled = new CheckBox { Text = "SFTP: clients such as WinSCP, FileZilla and sftp can transfer files (the sftp subsystem)", AutoSize = true, Margin = new Padding(16, 4, 4, 1) };
            _sfLog = new CheckBox { Text = "Log file transfers: each file uploaded, downloaded, renamed or removed, with the bytes, in the OpenSSH event log", AutoSize = true, Margin = new Padding(16, 1, 4, 1) };
            top.Controls.Add(_sfEnabled); top.Controls.Add(_sfLog);
            _sfServer = new Label { AutoSize = true, MaximumSize = new Size(Ui.Px(980), 0), Margin = new Padding(16, 6, 4, 1), ForeColor = Theme.Muted };
            top.Controls.Add(_sfServer);
            top.Controls.Add(new Label
            {
                AutoSize = true, ForeColor = Theme.Muted, MaximumSize = new Size(Ui.Px(980), 0), Margin = new Padding(16, 2, 4, 6),
                Text = "Speed: the client chooses the cipher. On x64 processors the AES ciphers are the fastest, up to twice chacha20-poly1305: WinSCP and FileZilla use AES by default; with sftp and scp add -c aes128-gcm@openssh.com. Compression slows transfers down on a fast network."
            });
            root.Controls.Add(top, 0, 0);

            var head = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoSize = true, Dock = DockStyle.Top };
            head.Controls.Add(Lbl("SFTP-only accounts", true));
            _sfRulesNote = new Label { AutoSize = true, MaximumSize = new Size(Ui.Px(980), 0), Margin = new Padding(16, 0, 4, 4), ForeColor = Theme.Muted };
            head.Controls.Add(_sfRulesNote);
            root.Controls.Add(head, 0, 1);

            _lvSftp = Lv("Applies to|90", "Name|200", "Folder, seen as /|380", "Access|190"); _lvSftp.AccessibleName = "SFTP-only accounts and groups";
            _lvSftp.Margin = new Padding(16, 0, 4, 0);
            ListSorter.Disable(_lvSftp); // the order is the precedence: the first rule that matches applies
            _lvSftp.ItemActivate += (s, e) => Safe(EditSftpRule);
            _lvSftp.KeyDown += (s, e) => { if (e.KeyCode == System.Windows.Forms.Keys.Delete) { e.Handled = true; Safe(RemoveSftpRule); } };
            _lvSftp.SelectedIndexChanged += (s, e) => UpdateSftpRuleButtons();
            root.Controls.Add(_lvSftp, 0, 2);
            var rb = Flow();
            rb.Padding = new Padding(12, 0, 4, 0);
            _sfRuleButtons = new[]
            {
                Btn("Add...", (s, e) => Safe(AddSftpRule), 110), Btn("Edit...", (s, e) => Safe(EditSftpRule), 110), Btn("Remove", (s, e) => Safe(RemoveSftpRule), 110),
                Btn("Move up", (s, e) => Safe(() => MoveSftpRule(-1)), 110), Btn("Move down", (s, e) => Safe(() => MoveSftpRule(1)), 110),
            };
            foreach (var b in _sfRuleButtons) rb.Controls.Add(b);
            _tips.SetToolTip(_sfRuleButtons[3], "The first rule that matches an account applies: move a rule up to give it precedence.");
            root.Controls.Add(rb, 0, 3);

            var check = Flow();
            check.Controls.Add(Lbl("Check an account:"));
            _sfAccount = new TextBox { Width = Ui.Px(240), Margin = new Padding(4, 6, 4, 4), Text = KeyGen.LoginName(), AccessibleName = "Account to check for SFTP" };
            check.Controls.Add(_sfAccount);
            var btnShow = Btn("Show its SFTP access", async (s, e) => await SafeAsync(CheckSftpAccount), 180);
            check.Controls.Add(btnShow);
            _tips.SetToolTip(btnShow, "What sshd works out for this account from the settings on this tab, applied or not (sshd -T with the rules and any other Match blocks; run as SYSTEM for other accounts, like the service).");
            root.Controls.Add(check, 0, 4);

            _sfResult = new Label
            {
                AutoSize = true, MaximumSize = new Size(Ui.Px(980), 0), Margin = new Padding(8, 2, 4, 4), ForeColor = Theme.Muted,
                Text = "Apply checks the settings with sshd -t, keeps the previous sshd_config as a backup, creates the folders of the rules and gives the accounts access, and restarts sshd (the backup comes back if sshd does not start). Connected sessions stay connected."
            };
            root.Controls.Add(_sfResult, 0, 5);

            var bar = Flow();
            bar.Controls.Add(Btn("Apply and restart sshd", async (s, e) => await SafeAsync(ApplySftp), 190));
            bar.Controls.Add(Btn("Undo changes", (s, e) => Safe(() => { LoadSftp(); Status("SFTP settings reloaded from sshd_config"); }), 130));
            _sfPending = new Label { AutoSize = true, Margin = new Padding(12, 10, 4, 4), ForeColor = Orange };
            bar.Controls.Add(_sfPending);
            root.Controls.Add(bar, 0, 6);

            EventHandler changed = (s, e) => { if (!_sfLoading) UpdateSftpUi(); };
            _sfEnabled.CheckedChanged += changed; _sfLog.CheckedChanged += changed;
            _tips.SetToolTip(_sfEnabled, "Subsystem sftp sftp-server.exe. Off: no SFTP at all, also not for the SFTP-only accounts below.");
            _tips.SetToolTip(_sfLog, "sftp-server -l INFO: the OpenSSH/Operational event log gets a line for every file opened and closed (with the bytes read and written), renamed and removed. See the Logs tab.");
            page.Controls.Add(root);
            return page;
        }

        private void LoadSftp()
        {
            _sfFile = SftpConfig.Read(_cfg);
            _sfRules = _sfFile.Rules.Select(r => r.Clone()).ToList();
            _sfLoading = true;
            try { _sfEnabled.Checked = _sfFile.Enabled; _sfLog.Checked = _sfFile.Enabled && _sfFile.LogTransfers; }
            finally { _sfLoading = false; }
            FillSftpRules();
            UpdateSftpUi();
        }

        private void FillSftpRules()
        {
            _lvSftp.BeginUpdate(); _lvSftp.Items.Clear();
            foreach (var r in _sfRules) _lvSftp.Items.Add(new ListViewItem(new[] { r.Kind, r.Name, r.Folder ?? "(not confined)", r.ReadOnly ? "download only" : "upload and download" }));
            _lvSftp.EndUpdate();
            var notes = new List<string>();
            if (_sfFile.RulesProblem != null)
                notes.Add("The section of SFTP-only accounts in sshd_config was changed by hand (" + _sfFile.RulesProblem + "), so it is left as it is. Correct it on the sshd_config (text) tab, or delete it to manage the rules here.");
            else
                notes.Add("These accounts and groups can only transfer files: no shell, no commands, no terminal, no forwarding. In a folder they see it as / and cannot leave it; %u in the folder stands for the account name. The first rule that matches an account applies.");
            if (_sfFile.OtherMatchSettings.Count > 0)
                notes.Add("sshd_config also forces a command or a folder elsewhere, as written there: " + string.Join("; ", _sfFile.OtherMatchSettings.Take(3)) + (_sfFile.OtherMatchSettings.Count > 3 ? "; ..." : "") + ".");
            _sfRulesNote.Text = string.Join("\n", notes);
            _sfRulesNote.ForeColor = _sfFile.RulesProblem != null || _sfFile.OtherMatchSettings.Count > 0 ? Orange : Theme.Muted;
            UpdateSftpRuleButtons();
        }

        private void UpdateSftpRuleButtons()
        {
            bool editable = _sfFile.RulesProblem == null;
            int i = _lvSftp.SelectedIndices.Count > 0 ? _lvSftp.SelectedIndices[0] : -1;
            _sfRuleButtons[0].Enabled = editable;
            _sfRuleButtons[1].Enabled = _sfRuleButtons[2].Enabled = editable && i >= 0;
            _sfRuleButtons[3].Enabled = editable && i > 0;
            _sfRuleButtons[4].Enabled = editable && i >= 0 && i < _sfRules.Count - 1;
        }

        private void UpdateSftpUi()
        {
            _sfLog.Enabled = _sfEnabled.Checked;
            var level = _sfFile.Subsystem == null ? null : SftpConfig.LogLevel(_sfFile.Subsystem);
            _sfServer.Text = _sfFile.Subsystem == null
                ? "sshd_config has no Subsystem sftp line, so SFTP is off."
                : "sshd_config: Subsystem sftp " + _sfFile.Subsystem + (level == null ? "  (sftp-server logs errors only)" : "");
            if (!_sfEnabled.Checked && (_sfFile.RulesProblem != null || _sfRules.Count > 0))
            {
                _sfServer.Text += "\nSFTP-only accounts need SFTP: " + (_sfFile.RulesProblem != null ? "delete their section (changed by hand) on the sshd_config (text) tab" : "remove their rules") + " to switch it off.";
                _sfServer.ForeColor = Red;
            }
            else _sfServer.ForeColor = Theme.Muted;
            _sfPending.Text = SftpEdited() ? "Changes not applied yet" : "";
            UpdatePending();
        }

        /// <summary>True when the SFTP tab has changes that were not applied.</summary>
        private bool SftpEdited()
        {
            if (_sfEnabled.Checked != _sfFile.Enabled) return true;
            if (_sfEnabled.Checked && _sfLog.Checked != _sfFile.LogTransfers) return true;
            return _sfRules.Count != _sfFile.Rules.Count || _sfRules.Where((r, i) => !r.SameAs(_sfFile.Rules[i])).Any();
        }

        private static bool SameSftp(SftpState a, SftpState b)
        {
            return a.RulesProblem == b.RulesProblem && a.Subsystem == b.Subsystem && a.Rules.Count == b.Rules.Count && a.Rules.Where((r, i) => !r.SameAs(b.Rules[i])).Count() == 0;
        }

        private void AddSftpRule()
        {
            using (var dlg = new SftpRuleDialog(null, _sfRules))
            {
                if (dlg.ShowDialog(this) != DialogResult.OK) return;
                _sfRules.Add(dlg.Result); FillSftpRules(); UpdateSftpUi();
                _lvSftp.Items[_lvSftp.Items.Count - 1].Selected = true;
            }
        }

        private void EditSftpRule()
        {
            if (_sfFile.RulesProblem != null || _lvSftp.SelectedIndices.Count == 0) return;
            int i = _lvSftp.SelectedIndices[0];
            using (var dlg = new SftpRuleDialog(_sfRules[i], _sfRules.Where((r, j) => j != i).ToList()))
            {
                if (dlg.ShowDialog(this) != DialogResult.OK) return;
                _sfRules[i] = dlg.Result; FillSftpRules(); UpdateSftpUi();
                _lvSftp.Items[i].Selected = true;
            }
        }

        private void RemoveSftpRule()
        {
            if (_sfFile.RulesProblem != null || _lvSftp.SelectedIndices.Count == 0) return;
            _sfRules.RemoveAt(_lvSftp.SelectedIndices[0]); FillSftpRules(); UpdateSftpUi();
        }

        private void MoveSftpRule(int delta)
        {
            if (_sfFile.RulesProblem != null || _lvSftp.SelectedIndices.Count == 0) return;
            int i = _lvSftp.SelectedIndices[0], j = i + delta;
            if (j < 0 || j >= _sfRules.Count) return;
            var r = _sfRules[i]; _sfRules[i] = _sfRules[j]; _sfRules[j] = r;
            FillSftpRules(); UpdateSftpUi();
            _lvSftp.Items[j].Selected = true; _lvSftp.Focus();
        }

        /// <summary>sshd_config as it would be with the settings on this tab (nothing is saved).</summary>
        private SshdConfig SftpCandidate()
        {
            var cand = _cfg.Copy();
            SftpConfig.Apply(cand, _sfEnabled.Checked, _sfEnabled.Checked && _sfLog.Checked, _sfFile.RulesProblem == null ? _sfRules : null);
            return cand;
        }

        /// <summary>A folder that a rule needs: created, or given access to; or a note when it cannot be prepared from here.</summary>
        private sealed class FolderStep { public string Path; public SecurityIdentifier Sid; public bool ReadOnly; public string Text; }

        /// <summary>
        /// What the folders of the rules need before their accounts can log in: a user rule's folder (with %u and %h worked
        /// out as sshd does) and a group rule's shared folder are created or given access; a group rule with %u needs one
        /// folder per member, which is only noted.
        /// </summary>
        private static List<FolderStep> FolderPlan(List<SftpRule> rules)
        {
            var l = new List<FolderStep>();
            foreach (var r in rules.Where(x => x.Folder != null))
            {
                var who = r.Kind.ToLowerInvariant() + " " + r.Name;
                var sid = Acl.SidOfAccount(r.Name);
                if (r.IsGroup && (r.Folder.Contains("%u") || r.Folder.Contains("%h")))
                {
                    var partners = PartnerGroups.Default;
                    bool partnerGroup = r.Name == PartnerGroups.Sshd(partners.Full) || r.Name == PartnerGroups.Sshd(partners.ReadOnly);
                    l.Add(new FolderStep { Text = who + ": one folder per member, " + r.Folder + (partnerGroup ? " (the Partners tab makes the folder of each partner)" : " (not created here: add a rule for each user, or create the folders)") });
                    continue;
                }
                var path = r.IsGroup ? SftpConfig.ExpandFolder(r.Folder, "", null) : SftpConfig.ExpandFolder(r.Folder, r.Name, Accounts.ProfileDir(sid));
                if (path == null) { l.Add(new FolderStep { Text = who + ": " + r.Folder + " uses %h, the profile folder, which the account gets at its first logon (not created here)" }); continue; }
                if (sid == null) { l.Add(new FolderStep { Text = who + ": " + path + " not prepared, the " + (r.IsGroup ? "group" : "account") + " was not found" }); continue; }
                bool exists = Directory.Exists(path);
                if (exists && SftpFolderAccess(path, sid, r.ReadOnly)) continue;
                var note = exists ? SftpConfig.FolderNote(path, sid) : null;
                l.Add(new FolderStep { Path = path, Sid = sid, ReadOnly = r.ReadOnly, Text = who + ": " + (exists ? "give " + (r.ReadOnly ? "read" : "modify") + " rights to " : "create ") + path + (note == null ? "" : " (" + note + ")") });
            }
            return l;
        }

        private static bool SftpFolderAccess(string path, SecurityIdentifier sid, bool readOnly)
        {
            try
            {
                var rights = readOnly ? FileSystemRights.ReadAndExecute : FileSystemRights.Modify;
                return Directory.GetAccessControl(path).GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>()
                    .Any(a => a.AccessControlType == AccessControlType.Allow && sid.Equals(a.IdentityReference) && (a.FileSystemRights & rights) == rights);
            }
            catch { return false; }
        }

        private async Task ApplySftp()
        {
            bool enabled = _sfEnabled.Checked, log = enabled && _sfLog.Checked;
            var cand = SftpCandidate();
            var steps = _sfFile.RulesProblem == null ? await BgAsync("Looking at the folders of the rules...", () => FolderPlan(_sfRules)) : new List<FolderStep>();
            // A rule for a group such as Users covers the administrator running this window too: say so before it applies.
            string warning = null;
            var tmp = WriteCandidate(cand);
            try
            {
                await BgAsync("Checking what the new settings mean for your account...", () =>
                {
                    string err; var me = Accounts.Canonical(KeyGen.LoginName(), false, out err) ?? Accounts.AsciiLower(KeyGen.LoginName());
                    var lines = AuthConfig.EffectiveLinesFor(me, tmp, cand.EffectivePort, out err);
                    var force = lines == null ? null : lines.Where(x => x.Key == "forcecommand").Select(x => x.Value).FirstOrDefault();
                    if (force != null && force.StartsWith("internal-sftp"))
                        warning = "your own account, " + me + ", becomes SFTP-only: no shell and no commands over SSH for you any more (this window keeps working).";
                });
            }
            finally { try { File.Delete(tmp); } catch { } }
            var rules = _sfFile.RulesProblem != null ? "The section of SFTP-only accounts edited by hand is left as it is."
                      : _sfRules.Count == 0 ? "No SFTP-only accounts."
                      : string.Join("\n", _sfRules.Select((r, i) => (i + 1) + ". " + r.Kind + " " + r.Name + ": SFTP only, " + r.Describe()));
            var text = (warning != null ? "Warning: " + warning + "\n\n" : "") + "Apply these SFTP settings and restart sshd?\n\nSFTP: " + (enabled ? "on" + (log ? ", file transfers logged" : ", file transfers not logged") : "off") + ".\n" + rules +
                       (steps.Count > 0 ? "\n\nFolders:\n" + string.Join("\n", steps.Select(s => "- " + s.Text)) : "") +
                       "\n\nsshd_config is backed up first. Connected sessions stay connected.";
            if (MessageBox.Show(this, text, Program.AppName, MessageBoxButtons.YesNo, warning != null ? MessageBoxIcon.Warning : MessageBoxIcon.Question,
                    warning != null ? MessageBoxDefaultButton.Button2 : MessageBoxDefaultButton.Button1) != DialogResult.Yes) { Status("SFTP settings not applied"); return; }
            var backup = await SaveConfig(cand, "Apply the SFTP settings of the SFTP tab.", "Apply");
            Log.Info("SFTP settings applied: " + (enabled ? "on" + (log ? ", transfers logged" : "") : "off") + "; " + (_sfFile.RulesProblem == null ? _sfRules.Count + " SFTP-only rule(s)" : "section left as it is"));
            var done = new List<string>(); var failed = new List<string>();
            if (steps.Any(s => s.Path != null))
                await BgAsync("Preparing the folders...", () =>
                {
                    foreach (var s in steps.Where(x => x.Path != null))
                    {
                        try { done.Add(SftpConfig.PrepareFolder(s.Path, s.Sid, s.ReadOnly)); Log.Info("SFTP folder: " + done[done.Count - 1]); }
                        catch (Exception ex) { failed.Add(s.Path + ": " + ex.Message); Log.Error("SFTP folder " + s.Path, ex, false); }
                    }
                });
            _cfg = await BgAsync("Reading the configuration and Includes...", () => SshdConfig.Load()); LoadSftp(); await UseConfig(_cfg); // the applied settings are now the file's
            bool running = await RestartWithRollback(backup);
            var summary = (running ? "Applied: SFTP " + (enabled ? "on" + (log ? ", file transfers logged in the OpenSSH event log" : "") : "off") + ", " + _sfFile.Rules.Count + " SFTP-only rule(s)." : "Not applied: the previous settings are back.") +
                          (done.Count > 0 ? " Folders: " + string.Join("; ", done) + "." : "") + (failed.Count > 0 ? " Folders not prepared: " + string.Join("; ", failed) + "." : "");
            _sfResult.Text = summary; _sfResult.ForeColor = !running || failed.Count > 0 ? Red : Green;
            Status(running ? "SFTP settings applied" : "SFTP settings not applied");
        }

        /// <summary>Shows what SFTP means for one account from the settings on this tab (sshd -T with the rules applied).</summary>
        private async Task CheckSftpAccount()
        {
            string err = null;
            var typed = _sfAccount.Text.Trim();
            var input = typed.Length == 0 ? KeyGen.LoginName() : typed;
            var name = await BgAsync("Looking up the account...", () => Accounts.Canonical(input, false, out err));
            if (name == null) throw new ConfigException(err);
            int port = _cfg.EffectivePort;
            var tmp = WriteCandidate(SftpCandidate());
            List<KeyValuePair<string, string>> lines = null;
            try { await BgAsync("Asking sshd...", () => lines = AuthConfig.EffectiveLinesFor(name, tmp, port, out err)); }
            finally { try { File.Delete(tmp); } catch { } }
            if (lines == null) throw new ConfigException("sshd could not work out the settings for " + name + ":\n\n" + (err ?? "").Replace(tmp, "sshd_config"));
            Func<string, string> value = k => lines.Where(x => x.Key == k).Select(x => x.Value).FirstOrDefault() ?? "";
            var subsystem = lines.Where(x => x.Key == "subsystem" && x.Value.StartsWith("sftp ", StringComparison.OrdinalIgnoreCase)).Select(x => x.Value.Substring(5).Trim()).FirstOrDefault();
            // sshd -T prints "forcecommand none" when no command is forced.
            var force = value("forcecommand"); if (force.Equals("none", StringComparison.OrdinalIgnoreCase)) force = "";
            var chroot = value("chrootdirectory");
            var pending = _sfPending.Text.Length > 0 ? " (the settings on this tab, not applied yet)" : "";
            string text; Color color = Theme.Text;
            if (subsystem == null) { text = name + " cannot use SFTP: SFTP is off" + pending + "."; color = Orange; }
            else if (force.Length > 0 && !force.StartsWith("internal-sftp")) { text = name + ": sshd forces the command \"" + force + "\" for every session, so SFTP does not start" + pending + "."; color = Orange; }
            else
            {
                bool only = force.StartsWith("internal-sftp");
                string readOnlyNote = only && Regex.IsMatch(force, @"(^|\s)-R(\s|$)") ? ", download only" : "";
                var sb = new StringBuilder(name + (only ? " is an SFTP-only account" + readOnlyNote : " can use SFTP, and also a shell and commands") + pending + ".");
                if (chroot.Length > 0 && !chroot.Equals("none", StringComparison.OrdinalIgnoreCase))
                {
                    string path = null; bool exists = false;
                    await BgAsync("Looking for the folder...", () => { path = SftpConfig.ExpandFolder(chroot, name, Accounts.ProfileDir(Acl.SidOfAccount(name))); exists = path != null && Directory.Exists(path); });
                    if (path == null) sb.Append(" Its folder is " + chroot + ", with a profile folder it does not have yet.");
                    else if (exists) sb.Append(" It sees " + path + " as / and cannot leave it.");
                    else { sb.Append(" Its folder " + path + " does not exist, so its SFTP logins fail: Apply creates it."); color = Red; }
                }
                else if (only) sb.Append(" It is not confined to a folder: it reaches the disks as its Windows permissions allow.");
                text = sb.ToString();
            }
            _sfResult.Text = text; _sfResult.ForeColor = color;
        }

        // ---------------- Partners (SFTP partner accounts) ----------------
        private TabPage _pgPartners; private ListView _lvPartners; private Label _ptState, _ptResult; private Button _ptSetup; private Button[] _ptButtons;
        private bool _ptLoaded; private PartnerSetupState _ptSetupState = new PartnerSetupState(); private List<PartnerAccount> _partners = new List<PartnerAccount>();

        private TabPage BuildPartners()
        {
            var page = new TabPage("Partners");
            var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 5, Padding = new Padding(8) };
            for (int i = 0; i < 5; i++) root.RowStyles.Add(i == 1 ? new RowStyle(SizeType.Percent, 100) : new RowStyle(SizeType.AutoSize));
            var head = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoSize = true, Dock = DockStyle.Top };
            var title = Flow(); title.Padding = new Padding(0);
            title.Controls.Add(Lbl("SFTP partners", true));
            _ptSetup = Btn("Set up partner accounts...", async (s, e) => await SafeAsync(SetUpPartners), 200);
            title.Controls.Add(_ptSetup);
            head.Controls.Add(title);
            _ptState = new Label { AutoSize = true, MaximumSize = new Size(Ui.Px(980), 0), Margin = new Padding(8, 0, 4, 6), ForeColor = Theme.Muted, Text = "..." };
            head.Controls.Add(_ptState);
            root.Controls.Add(head, 0, 0);
            _lvPartners = Lv("Account|110", "Contact|110", "Company|140", "Access|105", "Login|140", "Status|75", "Last day|85", "Last logon|115", "This month|110");
            _lvPartners.AccessibleName = "SFTP partners";
            _lvPartners.ItemActivate += async (s, e) => await SafeAsync(EditPartner);
            _lvPartners.KeyDown += async (s, e) => { if (e.KeyCode == System.Windows.Forms.Keys.Delete) { e.Handled = true; await SafeAsync(DeletePartner); } };
            _lvPartners.SelectedIndexChanged += (s, e) => UpdatePartnerButtons();
            root.Controls.Add(_lvPartners, 0, 1);
            var bar = Flow();
            _ptButtons = new[]
            {
                Btn("New partner...", async (s, e) => await SafeAsync(NewPartner), 130),
                Btn("Edit...", async (s, e) => await SafeAsync(EditPartner), 90),
                Btn("Reset password...", async (s, e) => await SafeAsync(ResetPartnerPassword), 150),
                Btn("Disable", async (s, e) => await SafeAsync(TogglePartner), 100),
                Btn("Unlock", async (s, e) => await SafeAsync(UnlockPartner), 90),
                Btn("Keys...", async (s, e) => await SafeAsync(PartnerKeys), 90),
                Btn("Delete...", async (s, e) => await SafeAsync(DeletePartner), 100),
                Btn("Open folder", (s, e) => Safe(OpenPartnerFolder), 120),
                Btn("Transfers...", (s, e) => Safe(ShowTransfers), 110),
                Btn("Refresh", async (s, e) => await SafeAsync(LoadPartners), 100),
            };
            foreach (var b in _ptButtons) bar.Controls.Add(b);
            root.Controls.Add(bar, 0, 2);
            _ptResult = new Label { AutoSize = true, MaximumSize = new Size(Ui.Px(980), 0), Margin = new Padding(8, 2, 4, 4), ForeColor = Theme.Muted };
            root.Controls.Add(_ptResult, 0, 3);
            root.Controls.Add(new Label
            {
                AutoSize = true, ForeColor = Theme.Muted, MaximumSize = new Size(Ui.Px(980), 0), Margin = new Padding(8, 4, 4, 4),
                Text = "Partners are local accounts of people outside the company who exchange files over SFTP and do nothing else: no shell, commands, terminal or forwarding, each confined to a folder of its own that it sees as /. " +
                       "Adding, changing or removing a partner does not change sshd_config or restart sshd. Passwords are generated, shown once and not stored; the last day decides until when an account can log in. Disabling or deleting a partner ends its open sessions."
            }, 0, 4);
            page.Controls.Add(root);
            return page;
        }

        private string PartnerRoot { get { return _ptSetupState.Root ?? PartnerSetup.DefaultRoot; } }
        private PartnerAccount SelectedPartner() { return _lvPartners.SelectedItems.Count > 0 ? (PartnerAccount)_lvPartners.SelectedItems[0].Tag : null; }

        private Dictionary<string, TransferTotals> _ptMonth = new Dictionary<string, TransferTotals>(StringComparer.OrdinalIgnoreCase);

        private async Task LoadPartners()
        {
            var g = PartnerGroups.Default; var cfg = _cfg;
            PartnerSetupState st = null; List<PartnerAccount> list = null; List<TransferTotals> month = null;
            await BgAsync("Reading the partner accounts...", () =>
            {
                st = PartnerSetup.Check(cfg, g); list = Partners.List(g, true);
                var now = DateTime.Now;
                month = Transfers.Totals(Transfers.Read(new DateTime(now.Year, now.Month, 1), now, CancellationToken.None));
            });
            _ptSetupState = st; _partners = list; _ptLoaded = true;
            _ptMonth = month.ToDictionary(t => t.User, StringComparer.OrdinalIgnoreCase);
            FillPartners();
        }

        /// <summary>What a partner moved this month, from the transfer history ("12 up, 3 down"), or empty.</summary>
        private string MonthText(string name) { TransferTotals t; return _ptMonth.TryGetValue(name, out t) && (t.Uploads + t.Downloads) > 0 ? t.Short : ""; }

        private void ShowTransfers()
        {
            var companies = _partners.ToDictionary(p => p.Name, p => p.Company, StringComparer.OrdinalIgnoreCase);
            var selected = SelectedPartner();
            Func<Task<bool>> enlarge = null;
            if (Transfers.LogSize() < Transfers.WantedLogBytes)
                enlarge = async () => await BgAsync("Enlarging the OpenSSH event log...", () => Transfers.EnlargeLog());
            using (var w = new TransfersWindow(async (f, t, cancellation) => await BgAsync("Reading the transfers...", () => Transfers.Read(f, t, cancellation)), enlarge, companies, selected == null ? null : selected.Name))
                w.ShowDialog(this);
        }

        private void FillPartners(string select = null)
        {
            select = select ?? (SelectedPartner() == null ? null : SelectedPartner().Name);
            _lvPartners.BeginUpdate(); _lvPartners.Items.Clear();
            foreach (var p in _partners)
            {
                var last = LocalAccounts.LastDay(p.Expires);
                var item = new ListViewItem(new[] { p.Name, p.FullName, p.Company, p.Access, p.Login, p.Status, last == null ? "" : last.Value.ToString("yyyy-MM-dd"),
                    p.LastLogon == null ? "never" : p.LastLogon.Value.ToString("yyyy-MM-dd HH:mm"), MonthText(p.Name) }) { Tag = p };
                if (!p.Active) item.ForeColor = p.Disabled ? Theme.Muted : Orange;
                else if (p.KeyOnly && p.KeyCount == 0) item.ForeColor = Orange;
                _lvPartners.Items.Add(item);
                if (string.Equals(p.Name, select, StringComparison.OrdinalIgnoreCase)) item.Selected = true;
            }
            _lvPartners.EndUpdate();
            var st = _ptSetupState; var lines = new List<string>();
            if (st.HostError != null) lines.Add(st.HostError);
            else if (!st.Complete)
            {
                lines.Add("Not set up yet: " + (st.MissingGroups.Count > 0 ? "the partner groups do not exist" : "sshd_config lacks " + st.Missing[0] + (st.Missing.Count > 1 ? ", and " + (st.Missing.Count - 1) + " more" : "")) +
                          ". \"Set up partner accounts\" adds what is missing, once.");
            }
            else
            {
                int active = _partners.Count(p => p.Active), off = _partners.Count - active;
                lines.Add(_partners.Count + " partner(s)" + (_partners.Count > 0 ? ": " + active + " active" + (off > 0 ? ", " + off + " disabled, expired or locked out" : "") : "") +
                          ". Folders under " + PartnerRoot + "; file transfers are logged in the OpenSSH event log.");
                var noKey = _partners.Where(p => p.KeyOnly && p.KeyCount == 0).Select(p => p.Name).ToList();
                if (noKey.Count > 0) lines.Add("Key only, without a key yet (they cannot log in): " + string.Join(", ", noKey) + ".");
            }
            if (st.Problems.Count > 0) lines.Add("Note: " + string.Join("; ", st.Problems) + ".");
            _ptState.Text = string.Join("\n", lines);
            _ptState.ForeColor = st.HostError != null || !st.Complete || st.Problems.Count > 0 || lines.Count > 1 ? Orange : Theme.Muted;
            _ptSetup.Visible = st.HostError == null && (!st.Complete || st.RootFixable); // the setup also corrects the partners' folder
            UpdatePartnerButtons();
        }

        private void UpdatePartnerButtons()
        {
            var p = SelectedPartner(); bool ready = _ptSetupState.Complete && _ptSetupState.HostError == null;
            _ptButtons[0].Enabled = ready;
            for (int i = 1; i <= 7; i++) _ptButtons[i].Enabled = p != null;
            _ptButtons[3].Text = p != null && p.Disabled ? "Enable" : "Disable";
            _ptButtons[4].Enabled = p != null && p.LockedOut;
        }

        private async Task SetUpPartners()
        {
            var g = PartnerGroups.Default; var cfg = _cfg;
            var st = await BgAsync("Checking what partner accounts need...", () => PartnerSetup.Check(cfg, g));
            if (st.HostError != null) throw new ConfigException(st.HostError);
            string root = null; SshdConfig cand = null;
            using (var d = new PartnerSetupDialog(st, g, async dlg =>
            {
                var r = dlg.Root; var c = _cfg.Copy();
                PartnerSetup.Apply(c, g, r);
                // Whoever can make folders in the root can make the folder of a future partner first, and keep control of it.
                bool canHarden = false;
                var problem = await BgAsync("Checking the permissions of " + r + "...", () => PartnerSetup.RootProblem(r, out canHarden));
                if (problem != null)
                {
                    if (string.Equals(Path.GetPathRoot(r), r, StringComparison.OrdinalIgnoreCase))
                        throw new ConfigException(r + " lets other accounts in: " + problem + ".\n\nIt is the root of a drive, whose permissions are not changed here. Choose a folder in it, for example " + Path.Combine(r, "SFTP") + ".");
                    if (!canHarden)
                        throw new ConfigException(r + " lets other accounts in: " + problem + ".\n\nChoose a folder that only administrators can change, or a new folder (the setup makes it for administrators only).");
                    if (Program.Unattended || MessageBox.Show(dlg, r + " lets other accounts in: " + problem + ".\n\nWhoever can make folders in it can make the folder of a future partner first, and keep control of it.\n\n" +
                            "Make " + r + " a folder for administrators only? It is then owned by Administrators, and only SYSTEM and Administrators have access to it (partners keep their own folders in it); other accounts that use it lose their access.\n\nNo: choose another folder.",
                            Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes)
                        throw new OperationCanceledException();
                    await BgAsync("Making " + r + " a folder for administrators only...", () => PartnerSetup.HardenRoot(r));
                }
                root = r; cand = c;
            }))
                if (d.ShowDialog(this) != DialogResult.OK) return;
            List<string> made = null; bool changed = cand.Text != _cfg.Text;
            var running = await PartnerSetup.Run(changed,
                () => BgAsync("Creating the partner groups and folders...", () =>
                {
                    made = PartnerSetup.CreateGroups(g);
                    if (!Directory.Exists(g.KeysDir)) Acl.CreatePrivateFolder(g.KeysDir);
                    if (!Directory.Exists(root)) SftpConfig.CreateNewFolder(root); // fails when someone made it since the check
                    bool canHarden; var problem = PartnerSetup.RootProblem(root, out canHarden);
                    if (problem != null) throw new ConfigException(root + " lets other accounts in: " + problem + ". Nothing was changed in sshd_config.");
                    try { Transfers.EnlargeLog(); } catch (Exception ex) { Log.Error("Enlarging the OpenSSH event log", ex, false); }
                }),
                () => SaveConfig(cand, "Set up SFTP partner accounts: rules for the groups " + string.Join(", ", g.All.Select(PartnerGroups.Sshd)) + ", folders under " + root + ", file transfers logged.", "Save and restart"),
                async b => { await UseConfig(cand); return await RestartWithRollback(b); }); // b is null for a first sshd_config, which is restarted with too
            _ptLoaded = false; await LoadPartners();
            _ptResult.Text = running
                ? "Partner accounts are set up" + (made.Count > 0 ? " (groups " + string.Join(", ", made) + " created)" : "") + ". New partner... adds one; sshd is not restarted for that."
                : "sshd did not keep the new settings: the previous sshd_config is back. The partner groups exist; set up again once the problem is solved.";
            _ptResult.ForeColor = running ? Green : Red;
            Status(running ? "Partner accounts set up" : "Partner setup not applied");
        }

        private static string ServerName() { try { return System.Net.Dns.GetHostEntry("").HostName; } catch { return Environment.MachineName; } }

        private async Task ShowPartnerPassword(string name, string password, string what)
        {
            int port = _cfg == null ? 22 : _cfg.EffectivePort;
            var server = await BgAsync("Looking up this computer's name...", () => ServerName());
            using (var d = new PasswordShownDialog(name, password, server, port, what)) d.ShowDialog(this);
        }

        private async Task NewPartner()
        {
            var g = PartnerGroups.Default; var root = PartnerRoot; string password = null, name = null, notifyError = null; bool keyOnly = false;
            using (var d = new PartnerDialog(null, root, "", async dlg =>
            {
                var n = dlg.AccountName; var fn = dlg.FullName; var co = dlg.Company; var ro = dlg.ReadOnlyAccess; var ko = dlg.KeyOnly; var last = dlg.LastDay; var notify = dlg.Notify;
                Func<bool, string> create = reuse => Partners.CreateKeepingPassword(() => Partners.Create(g, root, n, fn, co, ro, ko, last, reuse), () => SetPartnerNotify(n, notify), out notifyError);
                PartnerFolderExistsException exists = null;
                try { password = await BgAsync("Creating the partner " + n + "...", () => create(false)); }
                catch (PartnerFolderExistsException ex) { if (Program.Unattended) throw; exists = ex; }
                if (exists != null)
                {
                    if (MessageBox.Show(dlg, "The folder " + exists.Folder + " exists already: " + exists.Details + ".\n\n" +
                            "Give it to the new partner " + n + "? Its permissions and those of everything in it are reset: owner Administrators, access for SYSTEM, Administrators and " + n + " only. " +
                            "Every file in it becomes visible to " + n + (ro ? "." : ", who can also change and delete them.") + "\n\nNo: nothing is created; choose another name, or move the folder away first.",
                            Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes)
                        throw new OperationCanceledException();
                    password = await BgAsync("Creating the partner " + n + " with the existing folder...", () => create(true));
                }
                name = n; keyOnly = ko;
            }))
                if (d.ShowDialog(this) != DialogResult.OK) return;
            await LoadPartners(); FillPartners(name);
            _ptResult.Text = "Created the partner " + name + ", with the folder " + Partners.FolderOf(root, name) + "." + (notifyError == null ? "" : " Its upload notifications were not saved: " + notifyError);
            _ptResult.ForeColor = notifyError == null ? Green : Orange;
            Status("Partner created: " + name);
            if (keyOnly)
            {
                password = null;
                MessageBox.Show(this, name + " logs in with a public key only. Add the partner's public key (its .pub file) now.", Program.AppName, MessageBoxButtons.OK, MessageBoxIcon.Information);
                await PartnerKeys();
            }
            else await ShowPartnerPassword(name, password, "The partner " + name + " can log in now, with this password, to its folder only.");
        }

        private async Task EditPartner()
        {
            var p = SelectedPartner(); if (p == null) return;
            var g = PartnerGroups.Default; var root = PartnerRoot;
            string current; AlertSettings.Load().PartnerNotify.TryGetValue(p.Name, out current);
            using (var d = new PartnerDialog(p, root, current, async dlg =>
            {
                var fn = dlg.FullName; var co = dlg.Company; var ro = dlg.ReadOnlyAccess; var ko = dlg.KeyOnly; var last = dlg.LastDay; var notify = dlg.Notify;
                await BgAsync("Saving " + p.Name + "...", () => { Partners.Update(g, root, p, fn, co, ro, ko, last); SetPartnerNotify(p.Name, notify); });
            }))
                if (d.ShowDialog(this) != DialogResult.OK) return;
            await LoadPartners();
            _ptResult.Text = "Saved " + p.Name + ". The changes apply from its next login."; _ptResult.ForeColor = Green;
            Status("Partner saved: " + p.Name);
        }

        /// <summary>Who is told when a partner's files arrive (the alert settings); empty or null: the admins.</summary>
        private static void SetPartnerNotify(string name, string notify)
        {
            var s = AlertSettings.Load();
            string old; s.PartnerNotify.TryGetValue(name, out old);
            if ((old ?? "") == (notify ?? "")) return;
            if (string.IsNullOrEmpty(notify)) s.PartnerNotify.Remove(name); else s.PartnerNotify[name] = notify;
            s.Save();
        }

        private async Task ResetPartnerPassword()
        {
            var p = SelectedPartner(); if (p == null) return;
            if (MessageBox.Show(this, "Give " + p.Name + " a new password? The current one stops working at once." + (p.KeyOnly ? "\n\n" + p.Name + " logs in with a key only, so the password is refused anyway." : ""),
                    Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Question, MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;
            var password = await BgAsync("Setting a new password...", () => Partners.ResetPassword(p.Name));
            await LoadPartners();
            await ShowPartnerPassword(p.Name, password, "The new password of " + p.Name + ". The previous one no longer works.");
            Status("New password for " + p.Name);
        }

        private async Task TogglePartner()
        {
            var p = SelectedPartner(); if (p == null) return;
            bool disable = !p.Disabled; int port = _cfg.EffectivePort; int ended = 0; string unended = null;
            if (disable && MessageBox.Show(this, "Disable " + p.Name + "? It can no longer log in, and its open sessions end now. Its folder, keys and settings stay.", Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Question, MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;
            await BgAsync((disable ? "Disabling " : "Enabling ") + p.Name + "...", () => { Partners.SetDisabled(p.Name, disable); if (disable) ended = Partners.Disconnect(p.Name, port, out unended); });
            await LoadPartners();
            _ptResult.Text = (disable ? "Disabled " + p.Name + (ended > 0 ? "; " + ended + " open session(s) ended" : "") : "Enabled " + p.Name) + "." + (unended != null ? " Not done: " + unended + "." : "");
            _ptResult.ForeColor = unended == null ? Green : Orange;
            Status(_ptResult.Text);
        }

        private async Task UnlockPartner()
        {
            var p = SelectedPartner(); if (p == null || !p.LockedOut) return;
            await BgAsync("Unlocking " + p.Name + "...", () => Partners.Unlock(p.Name));
            await LoadPartners();
            _ptResult.Text = "Unlocked " + p.Name + ": Windows had locked it after too many wrong passwords (the lockout policy)."; _ptResult.ForeColor = Green;
        }

        private async Task PartnerKeys()
        {
            var p = SelectedPartner(); if (p == null) return;
            var g = PartnerGroups.Default;
            var file = await BgAsync("Opening the partner's keys...", () => Partners.EnsureKeysFile(g, p.Name));
            using (var d = new PartnerKeysDialog(p, file)) d.ShowDialog(this);
            await LoadPartners();
        }

        private async Task DeletePartner()
        {
            var p = SelectedPartner(); if (p == null) return;
            var g = PartnerGroups.Default; var root = PartnerRoot; var folder = Partners.FolderOf(root, p.Name); int port = _cfg.EffectivePort;
            var size = await BgAsync("Looking at the partner's folder...", () =>
            {
                if (!Directory.Exists(folder)) return null;
                try { var files = new DirectoryInfo(folder).GetFiles("*", SearchOption.AllDirectories); return files.Length + " file(s), " + Ui.Bytes(files.Sum(f => f.Length)); }
                catch (Exception ex) { return "not readable: " + ex.Message; }
            });
            string problems = null, note = null; bool deleted = false; int ended = 0;
            using (var d = new PartnerDeleteDialog(p, folder, size, async dlg =>
            {
                var withFiles = dlg.DeleteFiles;
                await BgAsync("Deleting " + p.Name + "...", () =>
                {
                    // Disabled first, as Disable does: a login that starts while the sessions end is refused, and an account
                    // that cannot be deleted stays disabled.
                    try { Partners.SetDisabled(p.Name, true); } catch (Exception ex) { Log.Error("Disabling " + p.Name + " before deleting it", ex, false); }
                    string unended; ended = Partners.Disconnect(p.Name, port, out unended);
                    problems = Partners.Delete(g, root, p, withFiles, out note);
                    if (unended != null) problems = (problems == null ? "" : problems + "; ") + unended;
                    try { SetPartnerNotify(p.Name, null); } catch (Exception ex) { Log.Error("Removing the recipients of " + p.Name, ex, false); }
                });
                deleted = true;
            }))
                d.ShowDialog(this);
            if (!deleted) return;
            await LoadPartners();
            _ptResult.Text = "Deleted " + p.Name + (ended > 0 ? "; " + ended + " open session(s) ended" : "") + (note != null ? "; " + note : "") + "." + (problems != null ? " Not done: " + problems + "." : "");
            _ptResult.ForeColor = problems == null ? Green : Orange;
            Status("Partner deleted: " + p.Name);
        }

        private void OpenPartnerFolder()
        {
            var p = SelectedPartner(); if (p == null) return;
            var folder = Partners.FolderOf(PartnerRoot, p.Name);
            if (!Directory.Exists(folder)) throw new ConfigException("The folder " + folder + " does not exist.");
            Proc.OpenExternal("explorer.exe", "\"" + folder + "\"");
        }

        // ---------------- Alerts (alerts, automatic blocking, the transfer archive) ----------------
        private TabPage _pgAlerts; private CheckBox _alOn, _alTls, _alSshd, _alFailures, _alUploads, _alDisk, _alReport, _alBlock; private RadioButton _alTeams, _alText;
        private TextBox _alHost, _alUser, _alPassword, _alFrom, _alAdmins, _alHook, _alAllow; private NumericUpDown _alPort, _alBurst, _alDiskPct, _alThreshold, _alWindow;
        private Label _alState, _alResult, _alPending; private bool _alLoaded;
        private Dictionary<Control, string> _alShown;

        private Dictionary<Control, string> AlertInputs()
        {
            return Descendants(_pgAlerts).Where(c => c is CheckBox || c is RadioButton || c is NumericUpDown || (c is TextBox && !(c.Parent is UpDownBase)))
                .ToDictionary(c => c, c => c is CheckBox ? ((CheckBox)c).Checked.ToString() : c is RadioButton ? ((RadioButton)c).Checked.ToString() : c is NumericUpDown ? ((NumericUpDown)c).Value.ToString(System.Globalization.CultureInfo.InvariantCulture) : c.Text);
        }

        private bool AlertsEdited()
        {
            return _alLoaded && _alShown != null && AlertInputs().Any(p => !_alShown.ContainsKey(p.Key) || _alShown[p.Key] != p.Value);
        }

        private TabPage BuildAlerts()
        {
            var page = new TabPage("Alerts");
            var root = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoScroll = true, Padding = new Padding(8) };
            _alOn = new CheckBox { Text = "Run alerts, automatic blocking and the transfer archive in the background (scheduled tasks as SYSTEM: every minute, and each night)", AutoSize = true, Margin = new Padding(4, 4, 4, 2), Font = BoldFont() };
            root.Controls.Add(_alOn);
            _alState = new Label { AutoSize = true, MaximumSize = new Size(Ui.Px(980), 0), Margin = new Padding(22, 0, 4, 8), ForeColor = Theme.Muted };
            root.Controls.Add(_alState);
            _alHealth = new Label { AutoSize = true, MaximumSize = new Size(Ui.Px(930), 0), Margin = new Padding(22, 0, 4, 8), AccessibleName = "Background agent health" };
            root.Controls.Add(_alHealth);
            root.Controls.Add(Btn("Refresh health", async (s, e) => await SafeAsync(RefreshAgentHealth), 145));
            Func<string, Control> caption = t => new Label { Text = t, AutoSize = true, Margin = new Padding(4, 8, 4, 2), Font = BoldFont() };
            Func<string, int, bool, TextBox> tb = (name, width, secret) => new TextBox { Width = Ui.Px(width), AccessibleName = name, UseSystemPasswordChar = secret, Margin = new Padding(4, 3, 4, 3) };
            Func<string, Label> lbl = t => new Label { Text = t, AutoSize = true, Margin = new Padding(4, 7, 4, 3) };
            Func<Control[], FlowLayoutPanel> row = cs => { var f = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = new Padding(18, 0, 0, 0) }; f.Controls.AddRange(cs); return f; };
            Func<string, int, int, int, NumericUpDown> num = (name, min, max, width) => new NumericUpDown { Minimum = min, Maximum = max, Width = Ui.Px(width), AccessibleName = name, Margin = new Padding(4, 3, 4, 3) };

            root.Controls.Add(caption("E-mail"));
            _alHost = tb("Mail server", 260, false); _alPort = num("Mail server port", 1, 65535, 70); _alTls = new CheckBox { Text = "STARTTLS", AutoSize = true, Margin = new Padding(8, 6, 4, 3), Checked = true };
            root.Controls.Add(row(new Control[] { lbl("Mail server:"), _alHost, lbl("Port:"), _alPort, _alTls }));
            _alUser = tb("Mail server user name", 220, false); _alPassword = tb("Mail server password", 180, true);
            root.Controls.Add(row(new Control[] { lbl("Log in as (optional):"), _alUser, lbl("Password:"), _alPassword }));
            _alFrom = tb("Sender address", 260, false); _alAdmins = tb("Admins' addresses", 420, false);
            root.Controls.Add(row(new Control[] { lbl("From:"), _alFrom, lbl("To the admins:"), _alAdmins }));
            root.Controls.Add(row(new Control[] { Btn("Send a test e-mail", async (s, e) => await SafeAsync(async () => await TestAlert(true)), 150),
                new Label { AutoSize = true, ForeColor = Theme.Muted, MaximumSize = new Size(Ui.Px(760), 0), Margin = new Padding(8, 8, 4, 3), Text = "Port 587 with STARTTLS and a login (Gmail: an app password), or port 25 without a login to a relay or a Microsoft 365 connector that accepts this server's address." } }));

            root.Controls.Add(caption("Webhook (optional)"));
            _alHook = tb("Webhook address", 560, true);
            _alTeams = new RadioButton { Text = "Microsoft Teams (Workflows)", AutoSize = true, Checked = true, Margin = new Padding(8, 6, 4, 3) };
            _alText = new RadioButton { Text = "Text: {\"text\": ...} (Slack, Mattermost, others)", AutoSize = true, Margin = new Padding(8, 6, 4, 3) };
            root.Controls.Add(row(new Control[] { lbl("Address (https://...):"), _alHook }));
            var formats = row(new Control[] { lbl("Format:"), _alTeams, _alText, Btn("Send a test", async (s, e) => await SafeAsync(async () => await TestAlert(false)), 110) });
            root.Controls.Add(formats);

            root.Controls.Add(caption("Alert when"));
            _alSshd = new CheckBox { Text = "sshd stops, and when it runs again", AutoSize = true, Margin = new Padding(22, 3, 4, 2) };
            root.Controls.Add(_alSshd);
            _alFailures = new CheckBox { Text = "failed logins pile up: at least", AutoSize = true, Margin = new Padding(4, 6, 4, 2) }; _alBurst = num("Failed logins for an alert", 10, 100000, 70);
            root.Controls.Add(row(new Control[] { _alFailures, _alBurst, lbl("in the time below, from all addresses together (and when an address is blocked)") }));
            _alUploads = new CheckBox { Text = "a partner's files arrive: to the people set for the partner (Partners tab, Edit), else to the admins; one message per partner per 5 minutes", AutoSize = true, Margin = new Padding(22, 3, 4, 2), MaximumSize = new Size(Ui.Px(960), 0) };
            root.Controls.Add(_alUploads);
            _alDisk = new CheckBox { Text = "free space on the drive of the partners' folders is below", AutoSize = true, Margin = new Padding(4, 6, 4, 2) }; _alDiskPct = num("Free space percentage", 1, 50, 55);
            root.Controls.Add(row(new Control[] { _alDisk, _alDiskPct, lbl("% (checked every hour, one message a day)") }));
            _alReport = new CheckBox { Text = "the monthly transfer report: on the 1st, to the admins, with the list of transfers as a CSV file", AutoSize = true, Margin = new Padding(22, 3, 4, 2) };
            root.Controls.Add(_alReport);

            root.Controls.Add(caption("Automatic blocking"));
            _alBlock = new CheckBox { Text = "Block an address after", AutoSize = true, Margin = new Padding(4, 6, 4, 2) }; _alThreshold = num("Failed logins before a block", 3, 1000, 60); _alWindow = num("Minutes counted", 1, 1440, 60);
            root.Controls.Add(row(new Control[] { _alBlock, _alThreshold, lbl("failed logins within"), _alWindow, lbl("minutes: for 1 hour, then 24 hours, then 7 days within a week") }));
            _alAllow = tb("Never block these addresses", 560, false);
            root.Controls.Add(row(new Control[] { lbl("Never block (addresses or networks, e.g. 203.0.113.0/24):"), _alAllow }));
            root.Controls.Add(new Label
            {
                AutoSize = true, ForeColor = Theme.Muted, MaximumSize = new Size(Ui.Px(960), 0), Margin = new Padding(22, 4, 4, 4),
                Text = "Addresses with a logged-in SSH session and this computer are never blocked. A login with an account name that does not exist counts twice (sshd logs it twice). Blocked addresses are in the firewall rule of the Logs tab, which lists and unblocks them."
            });
            var bar = Flow();
            bar.Controls.Add(Btn("Save", async (s, e) => await SafeAsync(SaveAlerts), 100));
            bar.Controls.Add(Btn("Undo changes", async (s, e) => await SafeAsync(LoadAlerts), 130));
            bar.Controls.Add(Btn("Open the agent log", (s, e) => Safe(() => { if (!File.Exists(Agent.LogPath)) throw new ConfigException("There is no agent log yet: " + Agent.LogPath); Proc.OpenExternal("notepad.exe", "\"" + Agent.LogPath + "\""); }), 160));
            bar.Controls.Add(Btn("Retry failed deliveries", async (s, e) => await SafeAsync(RetryNotifications), 175));
            _alResult = new Label { AutoSize = true, Margin = new Padding(12, 10, 4, 4), MaximumSize = new Size(Ui.Px(700), 0) };
            bar.Controls.Add(_alResult);
            _alPending = new Label { AutoSize = true, Text = "All alert settings saved", AccessibleName = "Alert settings save state", Margin = new Padding(8, 10, 4, 4) };
            bar.Controls.Add(_alPending);
            var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2 };
            layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100)); layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            layout.Controls.Add(root, 0, 0); layout.Controls.Add(bar, 0, 1); page.Controls.Add(layout);
            FitRows(root);
            foreach (var control in Descendants(page))
            {
                if (control is CheckBox) ((CheckBox)control).CheckedChanged += (s, e) => UpdatePending();
                else if (control is RadioButton) ((RadioButton)control).CheckedChanged += (s, e) => UpdatePending();
                else if (control is NumericUpDown) ((NumericUpDown)control).ValueChanged += (s, e) => UpdatePending();
                else if (control is TextBox && !(control.Parent is UpDownBase)) control.TextChanged += (s, e) => UpdatePending();
            }
            return page;
        }

        private async Task LoadAlerts()
        {
            AlertSettings s = null; bool installed = false; AgentHealth health = null;
            await BgAsync("Reading the alert settings...", () =>
            {
                s = AlertSettings.Load(); installed = Agent.TasksInstalled();
                health = AgentHealth.Load();
            });
            _alOn.Checked = installed;
            _alHost.Text = s.SmtpHost; SetClamped(_alPort, s.SmtpPort); _alTls.Checked = s.SmtpTls; _alUser.Text = s.SmtpUser; _alPassword.Text = s.SmtpPassword;
            _alFrom.Text = s.From; _alAdmins.Text = s.AdminTo; _alHook.Text = s.Webhook; _alTeams.Checked = s.WebhookTeams; _alText.Checked = !s.WebhookTeams;
            _alSshd.Checked = s.OnSshdStopped; _alFailures.Checked = s.OnFailedLogins; SetClamped(_alBurst, s.BurstThreshold); _alUploads.Checked = s.OnUploads;
            _alDisk.Checked = s.OnDiskLow; SetClamped(_alDiskPct, s.DiskLowPercent); _alReport.Checked = s.MonthlyReport;
            _alBlock.Checked = s.AutoBlock; SetClamped(_alThreshold, s.BlockThreshold); SetClamped(_alWindow, s.BlockWindowMinutes); _alAllow.Text = s.AllowList;
            _alState.Text = installed ? "On: the tasks " + Agent.WatchTask + " and " + Agent.DailyTask + " run the manager as SYSTEM."
                                      : "Off: nothing runs while this window is closed. Saving with the box ticked sets up the scheduled tasks.";
            _alState.ForeColor = installed ? Theme.Muted : Orange;
            ShowAgentHealth(health);
            _alLoaded = true;
            _alShown = AlertInputs();
            UpdatePending();
        }

        /// <summary>A stored value (a hand-edited file or registry value) within the range of its field: out of range, Value throws.</summary>
        private static void SetClamped(NumericUpDown n, decimal v) { n.Value = Math.Max(n.Minimum, Math.Min(n.Maximum, v)); }

        /// <summary>The settings as they are on the tab (partner recipients from the file: they are set on the Partners tab).</summary>
        private AlertSettings AlertsFromTab()
        {
            var s = AlertSettings.Load();
            s.SmtpHost = _alHost.Text.Trim(); s.SmtpPort = (int)_alPort.Value; s.SmtpTls = _alTls.Checked; s.SmtpUser = _alUser.Text.Trim(); s.SmtpPassword = _alPassword.Text;
            s.From = _alFrom.Text.Trim(); s.AdminTo = _alAdmins.Text.Trim(); s.Webhook = _alHook.Text.Trim(); s.WebhookTeams = _alTeams.Checked;
            s.OnSshdStopped = _alSshd.Checked; s.OnFailedLogins = _alFailures.Checked; s.BurstThreshold = (int)_alBurst.Value; s.OnUploads = _alUploads.Checked;
            s.OnDiskLow = _alDisk.Checked; s.DiskLowPercent = (int)_alDiskPct.Value; s.MonthlyReport = _alReport.Checked;
            s.AutoBlock = _alBlock.Checked; s.BlockThreshold = (int)_alThreshold.Value; s.BlockWindowMinutes = (int)_alWindow.Value; s.AllowList = _alAllow.Text.Trim();
            return s;
        }

        private async Task SaveAlerts()
        {
            // The fields of a tab that could not be read hold no settings: saving them would overwrite the file.
            if (!_alLoaded) throw new ConfigException("The alert settings could not be read, so nothing was saved. Press F5 and save again.");
            var s = AlertsFromTab();
            var problem = s.Problem();
            if (problem != null) throw new ConfigException(problem);
            bool on = _alOn.Checked;
            if (on && !s.MailConfigured && !s.WebhookConfigured && !s.AutoBlock)
                throw new ConfigException("Nothing would run: set up e-mail or a webhook, or automatic blocking, or untick the box at the top.");
            await BgAsync("Saving the alert settings...", () =>
            {
                s.Save();
                if (on) Agent.InstallTasks(); else if (Agent.TasksInstalled()) Agent.RemoveTasks();
            });
            await LoadAlerts();
            _alResult.Text = on ? "Saved; the background tasks run with these settings from their next run (within a minute)." : "Saved; nothing runs in the background.";
            _alResult.ForeColor = Green;
            Status("Alert settings saved");
        }

        private async Task TestAlert(bool mail)
        {
            var s = AlertsFromTab();
            var problem = s.Problem(); if (problem != null) throw new ConfigException(problem);
            if (mail && !s.MailConfigured) throw new ConfigException("Enter the mail server, the sender address and the admins' addresses first.");
            if (!mail && !s.WebhookConfigured) throw new ConfigException("Enter the webhook address first.");
            var subject = "Test message from " + Program.AppName + " on " + Environment.MachineName;
            var text = "This is a test. Alerts of the SSH server on " + Environment.MachineName + " reach you this way.";
            await BgAsync(mail ? "Sending a test e-mail..." : "Sending a test to the webhook...", () =>
            {
                if (mail) Agent.SendMail(s, subject, text, null, AlertSettings.Addresses(s.AdminTo), null, null); else Agent.SendHook(s, subject, text);
            });
            _alResult.Text = mail ? "Test e-mail sent to " + s.AdminTo + "." : "Test sent to the webhook."; _alResult.ForeColor = Green;
        }

        // ---------------- Raw editor ----------------
        private TabPage BuildRawEditor()
        {
            var page = new TabPage("sshd_config (text)");
            var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 3 };
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize)); root.RowStyles.Add(new RowStyle(SizeType.Percent, 100)); root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            // MaxLength 0 lifts the 32767-character typing limit of a multiline TextBox (sshd_config files can be larger).
            _rawEditor = new TextBox { Multiline = true, ScrollBars = ScrollBars.Both, WordWrap = false, Dock = DockStyle.Fill, Font = new Font("Consolas", Ui.Pt(10f)), AcceptsTab = true, AcceptsReturn = true, MaxLength = 0, HideSelection = false };
            // Find bar (Ctrl+F, F3 next, Shift+F3 previous, Esc closes it).
            _findBar = Flow(); _findBar.Visible = false; _findBar.WrapContents = false;
            _findBar.Controls.Add(Lbl("Find:"));
            _findText = new TextBox { Width = Ui.Px(260), Margin = new Padding(4, 6, 4, 4), AccessibleName = "Text to find in sshd_config" };
            _findText.KeyDown += (s, e) =>
            {
                if (e.KeyCode == System.Windows.Forms.Keys.Enter) { e.SuppressKeyPress = true; FindNext(!e.Shift); }
                else if (e.KeyCode == System.Windows.Forms.Keys.Escape) { e.SuppressKeyPress = true; _findBar.Visible = false; _rawEditor.Focus(); }
            };
            _findBar.Controls.Add(_findText);
            _findBar.Controls.Add(Btn("Next", (s, e) => FindNext(true), 80));
            _findBar.Controls.Add(Btn("Previous", (s, e) => FindNext(false), 90));
            _findResult = new Label { AutoSize = true, Margin = new Padding(8, 10, 4, 4), ForeColor = Theme.Muted };
            _findBar.Controls.Add(_findResult);
            _findBar.Controls.Add(Btn("Close", (s, e) => { _findBar.Visible = false; _rawEditor.Focus(); }, 80));
            root.Controls.Add(_findBar, 0, 0);
            root.Controls.Add(_rawEditor, 0, 1);
            var bar = Flow();
            bar.Controls.Add(Btn("Validate", async (s, e) => await SafeAsync(async () =>
            {
                var c = FromEditor(); var tmp = WriteCandidate(c);
                try { var r = await BgAsync("Running sshd -t...", () => Ssh.TestConfig(tmp)); MessageBox.Show(this, r.Ok ? "No problems found." : r.Output.Replace(tmp, "sshd_config"), Program.AppName, MessageBoxButtons.OK, r.Ok ? MessageBoxIcon.Information : MessageBoxIcon.Warning); }
                finally { try { File.Delete(tmp); } catch { } }
            }), 110));
            // The editor text becomes the working configuration only after sshd accepted it; a rejected text must not
            // replace the configuration the Settings tab works on.
            bar.Controls.Add(Btn("Save", async (s, e) => await SafeAsync(async () => await SaveRaw()), 110));
            bar.Controls.Add(Btn("Save and restart sshd", async (s, e) => await SafeAsync(async () => { var b = await SaveRaw(); await RestartWithRollback(b); }), 180));
            bar.Controls.Add(Btn("Reload", async (s, e) => await SafeAsync(async () => await ReloadFromFile(false, true)), 100));
            bar.Controls.Add(Btn("Find...", (s, e) => ShowFind(), 90));
            bar.Controls.Add(Btn("Open in Notepad", (s, e) => Proc.OpenExternal("notepad.exe", "\"" + Ssh.ConfigPath + "\""), 140));
            _tips.SetToolTip(bar.Controls[1], "Ctrl+S"); _tips.SetToolTip(bar.Controls[4], "Ctrl+F; F3 finds the next match, Shift+F3 the previous one");
            _rawPending = new Label { AutoSize = true, Margin = new Padding(12, 10, 4, 4), ForeColor = Orange, MaximumSize = new Size(Ui.Px(560), 0) };
            bar.Controls.Add(_rawPending);
            _rawEditor.AccessibleName = "sshd_config text";
            _rawEditor.TextChanged += (s, e) => UpdatePending();
            root.Controls.Add(bar, 0, 2);
            page.Controls.Add(root);
            return page;
        }

        private FlowLayoutPanel _findBar; private TextBox _findText; private Label _findResult;

        private void ShowFind()
        {
            _findBar.Visible = true;
            if (_rawEditor.SelectionLength > 0 && _rawEditor.SelectedText.IndexOf('\n') < 0) _findText.Text = _rawEditor.SelectedText;
            _findText.Focus(); _findText.SelectAll();
        }

        /// <summary>Selects the next (or previous) match of the find text in the editor, wrapping around the end; case is ignored.</summary>
        private void FindNext(bool forward)
        {
            var what = _findText.Text;
            if (what.Length == 0) { ShowFind(); return; }
            var text = _rawEditor.Text;
            int from = forward ? _rawEditor.SelectionStart + Math.Max(_rawEditor.SelectionLength, 0) : _rawEditor.SelectionStart - 1;
            int i = FindIn(text, what, from, forward);
            if (i < 0) { _findResult.Text = "not found"; _findResult.ForeColor = Red; return; }
            int total = 0; for (int k = text.IndexOf(what, StringComparison.OrdinalIgnoreCase); k >= 0; k = text.IndexOf(what, k + 1, StringComparison.OrdinalIgnoreCase)) total++;
            int line = _rawEditor.GetLineFromCharIndex(i) + 1;
            _findResult.Text = total + " match(es); line " + line; _findResult.ForeColor = Theme.Muted;
            _rawEditor.Select(i, what.Length); _rawEditor.ScrollToCaret();
        }

        /// <summary>The index of the next match at or after from (or before it, backwards), wrapping around; -1 when there is none.</summary>
        internal static int FindIn(string text, string what, int from, bool forward)
        {
            if (string.IsNullOrEmpty(what) || string.IsNullOrEmpty(text)) return -1;
            if (forward)
            {
                from = Math.Max(0, Math.Min(from, text.Length));
                int i = text.IndexOf(what, from, StringComparison.OrdinalIgnoreCase);
                return i >= 0 ? i : text.IndexOf(what, StringComparison.OrdinalIgnoreCase);
            }
            int j = from < 0 ? -1 : text.LastIndexOf(what, Math.Min(from, text.Length - 1), StringComparison.OrdinalIgnoreCase);
            return j >= 0 ? j : text.LastIndexOf(what, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>Save on the text tab: the editor text, checked and saved like every other save. Returns the backup.</summary>
        private async Task<string> SaveRaw()
        {
            var c = FromEditor();
            var b = await SaveConfig(c, "Save the text of the sshd_config (text) tab.");
            await UseConfig(c, true, false);
            Status("Saved (backup " + (b == null ? "none" : Path.GetFileName(b)) + "). Restart sshd to apply.");
            return b;
        }

        /// <summary>Shows sshd_config on the text tab. keepEdits: text changed and not saved stays, with a note that the file changed.</summary>
        private void LoadRaw(bool keepEdits = false)
        {
            var text = _cfg.Text.Replace("\r\n", "\n").Replace("\n", "\r\n");
            if (keepEdits && RawEdited())
            {
                if (text != _rawShown) _rawPending.Text = "sshd_config was changed on another tab while you edited this text. Save writes this text over it; Reload shows the file.";
                _rawShown = text;
            }
            else { _rawShown = text; _rawEditor.Text = text; _rawPending.Text = ""; }
            UpdatePending();
        }
        private SshdConfig FromEditor()
        {
            var c = new SshdConfig { Path = Ssh.ConfigPath, NewLine = _cfg.NewLine, LoadedHash = _cfg.LoadedHash };
            c.Lines = _rawEditor.Text.Replace("\r\n", "\n").Split('\n').ToList();
            while (c.Lines.Count > 0 && c.Lines[c.Lines.Count - 1].Trim().Length == 0) c.Lines.RemoveAt(c.Lines.Count - 1);
            return c;
        }

        // ---------------- Keys ----------------
        private TabPage BuildKeys()
        {
            var page = new TabPage("Keys");
            var split = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal };
            bool splitInit = false;
            split.SizeChanged += (s, e) =>
            {
                // Min sizes and the 50/50 split can only be applied once the container has its real height.
                if (splitInit || split.Height < Ui.Px(400)) return;
                splitInit = true;
                try { split.SplitterDistance = split.Height / 2; split.Panel1MinSize = Ui.Px(160); split.Panel2MinSize = Ui.Px(160); } catch (Exception ex) { Log.Error("Keys layout", ex, false); }
            };

            var adminBox = new GroupBox { Text = "Administrators: %ProgramData%\\ssh\\administrators_authorized_keys (members of the Administrators group)", Dock = DockStyle.Fill, Padding = new Padding(6) };
            var adminRoot = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2 };
            adminRoot.RowStyles.Add(new RowStyle(SizeType.Percent, 100)); adminRoot.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            _lvAdminKeys = Lv("Type|230", "Comment|200", "SHA256 fingerprint|420", "Options|150"); _lvAdminKeys.AccessibleName = "Authorized keys of administrators"; // Type fits ssh-mldsa44-ed25519@openssh.com and sk- types
            _lvAdminKeys.KeyDown += async (s, e) => { if (e.KeyCode == System.Windows.Forms.Keys.Delete) { e.Handled = true; await SafeAsync(async () => await RemoveKey(true)); } };
            adminRoot.Controls.Add(_lvAdminKeys, 0, 0);
            var abar = Flow();
            abar.Controls.Add(Btn("Add from file...", async (s, e) => await SafeAsync(async () => await AddKeyFromFile(true)), 130));
            abar.Controls.Add(Btn("Paste key...", async (s, e) => await SafeAsync(async () => await AddKeyFromText(true)), 110));
            abar.Controls.Add(Btn("Remove selected", async (s, e) => await SafeAsync(async () => await RemoveKey(true)), 140));
            abar.Controls.Add(Btn("Fix permissions", async (s, e) => await SafeAsync(async () => { await BgAsync("Fixing authorized-key permissions...", () => { if (File.Exists(Ssh.AdminKeysPath)) Acl.Restrict(Ssh.AdminKeysPath, null); }); Status("ACL set: SYSTEM and Administrators only"); await LoadKeys(); }), 130));
            abar.Controls.Add(Btn("Open in Notepad", (s, e) => Proc.OpenExternal("notepad.exe", "\"" + Ssh.AdminKeysPath + "\""), 130));
            adminRoot.Controls.Add(abar, 0, 1);
            adminBox.Controls.Add(adminRoot);
            split.Panel1.Controls.Add(adminBox);

            var userBox = new GroupBox { Text = "Standard users: <profile>\\.ssh\\authorized_keys", Dock = DockStyle.Fill, Padding = new Padding(6) };
            var userRoot = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 3 };
            userRoot.RowStyles.Add(new RowStyle(SizeType.AutoSize)); userRoot.RowStyles.Add(new RowStyle(SizeType.Percent, 100)); userRoot.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            var top = Flow();
            top.Controls.Add(Lbl("User profile:"));
            _cmbUsers = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = Ui.Px(380), Margin = new Padding(4) };
            _cmbUsers.SelectedIndexChanged += async (s, e) => await SafeAsync(LoadUserKeys); _cmbUsers.AccessibleName = "User profile";
            top.Controls.Add(_cmbUsers);
            userRoot.Controls.Add(top, 0, 0);
            _lvUserKeys = Lv("Type|230", "Comment|200", "SHA256 fingerprint|420", "Options|150"); _lvUserKeys.AccessibleName = "Authorized keys of the selected user";
            _lvUserKeys.KeyDown += async (s, e) => { if (e.KeyCode == System.Windows.Forms.Keys.Delete) { e.Handled = true; await SafeAsync(async () => await RemoveKey(false)); } };
            userRoot.Controls.Add(_lvUserKeys, 0, 1);
            var ubar = Flow();
            ubar.Controls.Add(Btn("Add from file...", async (s, e) => await SafeAsync(async () => await AddKeyFromFile(false)), 130));
            ubar.Controls.Add(Btn("Paste key...", async (s, e) => await SafeAsync(async () => await AddKeyFromText(false)), 110));
            ubar.Controls.Add(Btn("Remove selected", async (s, e) => await SafeAsync(async () => await RemoveKey(false)), 140));
            ubar.Controls.Add(Btn("Fix permissions", async (s, e) => await SafeAsync(async () => { var p = CurrentUserKeysPath(); var sid = CurrentUserSid(); await BgAsync("Fixing authorized-key permissions...", () => { if (File.Exists(p)) Keys.RestrictKeyFile(p, sid); }); Status("ACL set for " + p); await LoadUserKeys(); }), 130));
            userRoot.Controls.Add(ubar, 0, 2);
            userBox.Controls.Add(userRoot);
            split.Panel2.Controls.Add(userBox);
            page.Controls.Add(split);
            return page;
        }

        private async Task LoadKeys()
        {
            await FillKeyList(_lvAdminKeys, Ssh.AdminKeysPath);
            var sel = _cmbUsers.SelectedItem as string;
            _cmbUsers.Items.Clear(); foreach (var p in Keys.UserProfiles()) _cmbUsers.Items.Add(p);
            if (_cmbUsers.Items.Count > 0) { int i = sel == null ? -1 : _cmbUsers.Items.IndexOf(sel); _cmbUsers.SelectedIndex = i < 0 ? 0 : i; }
        }
        private async Task LoadUserKeys() { if (_cmbUsers.SelectedItem != null) await FillKeyList(_lvUserKeys, CurrentUserKeysPath()); }
        private string CurrentUserKeysPath() { return Keys.UserKeysPath((string)_cmbUsers.SelectedItem); }
        private SecurityIdentifier CurrentUserSid() { return ProfileSid((string)_cmbUsers.SelectedItem); }
        private static SecurityIdentifier ProfileSid(string profile)
        {
            // The profile folder name is not always the account name (renamed accounts, "name.DOMAIN" folders);
            // the ProfileList registry key maps the folder to the SID that sshd will impersonate.
            var sid = Keys.SidOfProfile(profile);
            if (sid == null) throw new Exception("Cannot determine the account that owns " + profile + ". The authorized_keys file would not be readable by that user, so nothing was written.");
            return sid;
        }
        private async Task FillKeyList(ListView lv, string path)
        {
            var keys = await BgAsync("Reading " + Path.GetFileName(path) + "...", () => Keys.Read(path)); // ssh-keygen -l for keys not seen before
            lv.BeginUpdate(); lv.Items.Clear();
            foreach (var k in keys) lv.Items.Add(new ListViewItem(new[] { k.Type, k.Comment, k.Fingerprint, k.Options }) { Tag = k.Line });
            lv.EndUpdate();
        }
        private async Task AddKeyFromFile(bool admin)
        {
            using (var dlg = new OpenFileDialog { Title = "Choose a public key file", Filter = "Public keys (*.pub)|*.pub|All files|*.*" })
            {
                if (dlg.ShowDialog(this) != DialogResult.OK) return;
                await AddKeyLines(admin, File.ReadAllLines(dlg.FileName));
            }
        }
        private async Task AddKeyFromText(bool admin)
        {
            using (var dlg = new TextDialog("Paste one or more public keys (one per line)")) { if (dlg.ShowDialog(this) == DialogResult.OK) await AddKeyLines(admin, dlg.Value.Split('\n')); }
        }
        private async Task AddKeyLines(bool admin, IEnumerable<string> newLines)
        {
            var path = admin ? Ssh.AdminKeysPath : CurrentUserKeysPath();
            var profile = admin ? null : (string)_cmbUsers.SelectedItem; var lines = newLines.ToList();
            // keeps comments; skips key material already present
            var r = await BgAsync("Adding the keys...", () => Keys.AddLines(path, lines, admin ? null : ProfileSid(profile)));
            if (admin) await FillKeyList(_lvAdminKeys, path); else await LoadUserKeys();
            Status(r[0] + " key(s) added to " + path + (r[1] > 0 ? ", " + r[1] + " already present" : ""));
        }
        private async Task RemoveKey(bool admin)
        {
            var lv = admin ? _lvAdminKeys : _lvUserKeys;
            if (lv.SelectedItems.Count == 0) { Status("Select a key first"); return; }
            var line = (string)lv.SelectedItems[0].Tag;
            if (MessageBox.Show(this, "Remove this key?\n\n" + line, Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Question, MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;
            var path = admin ? Ssh.AdminKeysPath : CurrentUserKeysPath();
            var profile = admin ? null : (string)_cmbUsers.SelectedItem;
            int removed = await BgAsync("Removing the key...", () => Keys.RemoveKey(path, line, admin ? null : ProfileSid(profile)));
            if (admin) await FillKeyList(_lvAdminKeys, path); else await LoadUserKeys();
            Status(removed > 0 ? "Key removed" : "Key not found in " + path);
        }

        // ---------------- Key generator ----------------
        private ComboBox _kgType; private TextBox _kgPath, _kgComment, _kgPass1, _kgPass2, _kgPublic; private CheckBox _kgNoPass, _kgAuthorize;
        private Label _kgResult; private string _kgDefaultShown;
        /// <summary>The key the tab shows (generated, loaded or converted here); the buttons of the second row act on it.</summary>
        private KeyFileInfo _kgKey; private bool? _kgAllowed; private readonly List<Button> _kgKeyButtons = new List<Button>();

        private TabPage BuildKeyGen()
        {
            var page = new TabPage("Key generator");
            var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 6, Padding = new Padding(8) };
            for (int i = 0; i < 6; i++) root.RowStyles.Add(i == 4 ? new RowStyle(SizeType.Percent, 100) : new RowStyle(SizeType.AutoSize));

            var grid = new TableLayoutPanel { AutoSize = true, ColumnCount = 3, Dock = DockStyle.Top };
            grid.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize)); grid.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize)); grid.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            Action<string, Control, Control> row = (label, c, extra) => { if (label.Length > 0) c.AccessibleName = label.TrimEnd(':'); grid.Controls.Add(Lbl(label)); grid.Controls.Add(c); if (extra != null) grid.Controls.Add(extra); else grid.Controls.Add(new Label { AutoSize = true }); };

            _kgType = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = Ui.Px(600), Margin = new Padding(4) };
            foreach (var t in KeyGen.Types) _kgType.Items.Add(t);
            _kgPath = new TextBox { Width = Ui.Px(600), Margin = new Padding(4) };
            _kgType.SelectedIndexChanged += (s, e) => Safe(() =>
            {
                // Follow the type with the default file name, unless the user typed a path of their own.
                var t = (KeyTypeChoice)_kgType.SelectedItem;
                if (_kgPath.Text.Trim().Length == 0 || string.Equals(_kgPath.Text.Trim(), _kgDefaultShown, StringComparison.OrdinalIgnoreCase)) _kgPath.Text = KeyGen.DefaultPath(t);
                _kgDefaultShown = KeyGen.DefaultPath(t);
            });
            _kgType.SelectedIndex = 0;
            row("Key type:", _kgType, null);
            row("Private key file:", _kgPath, Btn("Browse...", (s, e) => Safe(BrowseKeyPath), 100));
            _kgComment = new TextBox { Width = Ui.Px(600), Margin = new Padding(4), Text = KeyGen.LoginName().Replace('\\', '_') + "@" + Environment.MachineName };
            row("Comment:", _kgComment, null);
            _kgPass1 = new TextBox { Width = Ui.Px(300), Margin = new Padding(4), UseSystemPasswordChar = true };
            _kgPass2 = new TextBox { Width = Ui.Px(300), Margin = new Padding(4), UseSystemPasswordChar = true };
            row("Passphrase:", _kgPass1, null);
            row("Confirm passphrase:", _kgPass2, null);
            _kgNoPass = new CheckBox { Text = "No passphrase: only for keys used by unattended scripts (anyone who copies the file can use the key)", AutoSize = true, Margin = new Padding(4) };
            _kgNoPass.CheckedChanged += (s, e) => { _kgPass1.Enabled = _kgPass2.Enabled = !_kgNoPass.Checked; };
            row("", _kgNoPass, null);
            _kgAuthorize = new CheckBox { Text = "Allow this key to log in to this server as " + KeyGen.LoginName(), AutoSize = true, Margin = new Padding(4) };
            row("", _kgAuthorize, null);
            root.Controls.Add(grid, 0, 0);

            var bar = Flow();
            bar.Controls.Add(Btn("Generate key pair", async (s, e) => await SafeAsync(GenerateKey), 170));
            bar.Controls.Add(Btn("Load key...", async (s, e) => await SafeAsync(LoadKey), 120));
            bar.Controls.Add(Btn("Setup wizard...", async (s, e) => await SafeAsync(RunWizard), 130));
            root.Controls.Add(bar, 0, 1);

            _kgResult = new Label { AutoSize = true, Margin = new Padding(6, 6, 6, 2), MaximumSize = new Size(Ui.Px(980), 0), ForeColor = Theme.Muted, Text = "Generate a key pair, or load a key you have (OpenSSH, PuTTY .ppk or PEM) to change its passphrase, export it or let it log in here." };
            root.Controls.Add(_kgResult, 0, 2);
            var keyBar = Flow();
            Action<Button> keyButton = b => { b.Enabled = false; _kgKeyButtons.Add(b); keyBar.Controls.Add(b); };
            keyButton(Btn("Change passphrase...", async (s, e) => await SafeAsync(ChangeKeyPassphrase), 160));
            keyButton(Btn("Export...", (s, e) => Safe(() => ExportKey(null)), 100));
            keyButton(Btn("Allow it to log in", async (s, e) => await SafeAsync(AuthorizeCurrentKey), 150));
            keyBar.Controls.Add(Btn("Test login with this key", async (s, e) => await SafeAsync(TestKeyLogin), 190));
            keyBar.Controls.Add(Btn("Copy public key", (s, e) => Safe(() => { if (_kgPublic.Text.Length > 0) { Clipboard.SetText(_kgPublic.Text); Status("Public key copied"); } }), 140));
            keyBar.Controls.Add(Btn("Open folder", (s, e) => Safe(() => { var p = _kgKey != null ? _kgKey.Path : _kgPath.Text.Trim(); if (File.Exists(p)) Proc.OpenExternal("explorer.exe", "/select,\"" + p + "\""); else if (Directory.Exists(Path.GetDirectoryName(p))) Proc.OpenExternal("explorer.exe", "\"" + Path.GetDirectoryName(p) + "\""); }), 120));
            root.Controls.Add(keyBar, 0, 3);
            _kgPublic = new TextBox { Multiline = true, ReadOnly = true, WordWrap = true, ScrollBars = ScrollBars.Vertical, Dock = DockStyle.Fill, Font = new Font("Consolas", Ui.Pt(9.5f)) };
            _kgPublic.AccessibleName = "Public key"; root.Controls.Add(_kgPublic, 0, 4);
            root.Controls.Add(new Label
            {
                AutoSize = true, ForeColor = Theme.Muted, Margin = new Padding(6), MaximumSize = new Size(Ui.Px(980), 0),
                Text = "The private key stays on this computer and only you, SYSTEM and Administrators can read it; ssh refuses a key that others can read. " +
                       "Passphrases go to ssh-keygen through SSH_ASKPASS and never appear on a command line. Give other servers the public key " +
                       "(the .pub file or the text above), never the private key. For PuTTY, WinSCP and FileZilla, Export saves the key as a .ppk file; Load key converts a .ppk file to the OpenSSH format."
            }, 0, 5);
            page.Controls.Add(root);
            return page;
        }

        /// <summary>Shows a key on the tab: a headline (what just happened), what the key is, and whether it may log in here.</summary>
        private void ShowKey(KeyFileInfo k, string headline, bool? allowed, Color color)
        {
            _kgKey = k; _kgAllowed = allowed;
            _kgPublic.Text = k.PublicLine;
            foreach (var b in _kgKeyButtons) b.Enabled = true;
            var lines = new List<string>();
            if (!string.IsNullOrEmpty(headline)) lines.Add(headline);
            lines.Add("Key: " + k.Path);
            lines.Add(k.Description + ", " + k.Format + " format, " + (k.Encrypted ? "protected by a passphrase" : "NO passphrase") + ". Fingerprint " + k.Fingerprint + (k.Comment.Length > 0 ? ", comment \"" + k.Comment + "\"" : "") + ".");
            if (allowed != null) lines.Add("This server: " + (allowed.Value ? "the key may log in as " + KeyGen.LoginName() + "." : "the key may not log in as " + KeyGen.LoginName() + " (\"Allow it to log in\" adds it)."));
            _kgResult.Text = string.Join("\n", lines); _kgResult.ForeColor = color;
        }

        private KeyFileInfo CurrentKey()
        {
            if (_kgKey == null || !File.Exists(_kgKey.Path)) throw new ConfigException("Generate a key pair or load a key first.");
            return _kgKey;
        }

        /// <summary>Whether the key may log in as the account running this program; null when that cannot be read.</summary>
        private static bool? AuthorizedState(string publicLine)
        {
            try { return KeyGen.IsAuthorizedForMe(publicLine); }
            catch (Exception ex) { Log.Error("Reading the authorized keys", ex, false); return null; }
        }

        /// <summary>Asks for a key's passphrase, after showing why when problem is given; null when cancelled.</summary>
        private static string AskPassphrase(IWin32Window owner, string keyName, string problem)
        {
            if (problem != null) MessageBox.Show(owner, problem, Program.AppName, MessageBoxButtons.OK, MessageBoxIcon.Warning);
            using (var d = new PasswordDialog("Passphrase for " + keyName)) return d.ShowDialog(owner) == DialogResult.OK ? d.Value : null;
        }

        /// <summary>Load key: an OpenSSH or PEM key is shown; a PuTTY key is converted to an OpenSSH key first.</summary>
        private async Task LoadKey()
        {
            string path;
            using (var dlg = new OpenFileDialog { Title = "Load a private key", Filter = "Key files (id_*, *.ppk, *.pem, *.key)|id_*;*.ppk;*.pem;*.key|All files (*.*)|*.*" })
            {
                try { dlg.InitialDirectory = Directory.Exists(KeyGen.SshDir) ? KeyGen.SshDir : Environment.GetFolderPath(Environment.SpecialFolder.UserProfile); } catch { }
                if (dlg.ShowDialog(this) != DialogResult.OK) return;
                path = dlg.FileName;
            }
            KeyFileInfo info = null; string pass = null;
            while (info == null)
            {
                try { var p = pass; info = await BgAsync("Reading " + Path.GetFileName(path) + "...", () => KeyGen.Inspect(path, p)); }
                catch (WrongPassphraseException ex) { pass = AskPassphrase(this, Path.GetFileName(path), pass == null ? null : ex.Message); if (pass == null) return; }
            }
            if (info.IsPutty) { await ImportPuttyKey(info); return; }
            var allowed = await BgAsync("Checking whether the key may log in here...", () => AuthorizedState(info.PublicLine));
            ShowKey(info, "Loaded " + info.FileName + ".", allowed, Theme.Text);
            Status("Key loaded: " + info.Path);
        }

        /// <summary>Converts a PuTTY key to a new OpenSSH key file (the .ppk file stays) and shows it.</summary>
        private async Task ImportPuttyKey(KeyFileInfo info)
        {
            if (!KeyFormats.PuttyCanUse(info.Type)) throw new ConfigException(info.FileName + " holds a key of type " + info.Description + ", which cannot be converted.");
            if (MessageBox.Show(this, info.FileName + " is a PuTTY key (" + info.Description + ", " + info.Format + ").\n\nssh, scp, sftp and this program use keys in the OpenSSH format. Save a copy in that format? The .ppk file stays as it is, for PuTTY, WinSCP and FileZilla." +
                    (info.Encrypted ? "\n\nThe copy is protected by the same passphrase." : ""), Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
            string target;
            using (var dlg = new SaveFileDialog { Title = "Save the OpenSSH key as", Filter = "Private key (no extension)|*.*", OverwritePrompt = true, AddExtension = false })
            {
                var dir = Directory.Exists(KeyGen.SshDir) ? KeyGen.SshDir : Path.GetDirectoryName(info.Path);
                dlg.InitialDirectory = dir; dlg.FileName = Path.GetFileName(NewKeyDialog.FreeName(Path.Combine(dir, Path.GetFileNameWithoutExtension(info.Path))));
                if (dlg.ShowDialog(this) != DialogResult.OK) return;
                target = dlg.FileName;
            }
            string pass = null; KeyGenResult res = null; var now = DateTime.Now;
            if (info.Encrypted && (pass = AskPassphrase(this, info.FileName, null)) == null) return;
            while (res == null)
            {
                try { var p = pass; res = await BgAsync("Converting " + info.FileName + "...", () => KeyGen.ImportPuttyKey(info.Path, p, target, p, now)); }
                catch (WrongPassphraseException ex) { pass = AskPassphrase(this, info.FileName, ex.Message); if (pass == null) return; }
            }
            var allowed = await BgAsync("Checking whether the key may log in here...", () => AuthorizedState(res.PublicKey));
            ShowKey(KeyInfoOf(res), "Converted " + info.FileName + " to " + res.PrivatePath + " and " + Path.GetFileName(res.PublicPath) + (res.Encrypted ? ", protected by the passphrase of the PuTTY key" : ", without a passphrase like the PuTTY key") +
                ". Checked with ssh-keygen: the new file gives the same key." + WrittenNote(res.Written, true, res.Encrypted), allowed, res.Written.Unprotected ? Orange : Green);
            Status("PuTTY key converted: " + res.PrivatePath);
        }

        private async Task ChangeKeyPassphrase()
        {
            var key = CurrentKey();
            string what = null;
            using (var d = new PassphraseChangeDialog(key, async dlg =>
            {
                var oldPass = dlg.OldPassphrase; var newPass = dlg.NewPassphrase; // read here: the work runs on another thread
                await BgAsync("Changing the passphrase of " + key.FileName + "...", () => KeyGen.ChangePassphrase(key.Path, oldPass, newPass));
                what = string.IsNullOrEmpty(newPass) ? "Passphrase removed from " : key.Encrypted ? "Passphrase changed for " : "Passphrase set for ";
            }))
                if (d.ShowDialog(this) != DialogResult.OK) return;
            var info = await BgAsync("Reading the key...", () => KeyGen.Inspect(key.Path));
            ShowKey(info, what + info.FileName + ". Checked with ssh-keygen: it is the same key, and it opens with the new passphrase" + (info.Encrypted ? " and not without it." : "."), _kgAllowed, Green);
            Status(what + info.Path);
        }

        /// <summary>Export: the key in another format; true when a file was written. owner is the setup wizard when it offers the export of a key it made.</summary>
        private bool ExportKey(IWin32Window owner)
        {
            var key = CurrentKey();
            KeyWriteResult written = null; var format = KeyExportFormat.PuttyV3; bool encrypted = false;
            using (var d = new KeyExportDialog(key, async dlg =>
            {
                var f = dlg.Format; var t = Path.GetFullPath(dlg.Target); var cur = dlg.CurrentPassphrase; var np = dlg.NewPassphrase; var now = DateTime.Now;
                written = await BgAsync("Exporting " + key.FileName + "...", () => KeyGen.Export(key, f, t, cur, np, now));
                format = f; encrypted = !string.IsNullOrEmpty(np);
            }))
                if (d.ShowDialog(owner ?? this) != DialogResult.OK) return false;
            bool isPrivate = format == KeyExportFormat.OpenSshPrivate || format == KeyExportFormat.PuttyV3 || format == KeyExportFormat.PuttyV2;
            string how;
            if (format == KeyExportFormat.PuttyV3 || format == KeyExportFormat.PuttyV2)
                how = "PuTTY: Connection > SSH > Auth > Credentials, \"Private key file\". WinSCP: Advanced > SSH > Authentication. FileZilla: Site Manager, logon type \"Key file\".";
            else if (format == KeyExportFormat.OpenSshPrivate)
                how = "On the other computer, put it in the .ssh folder of your profile, or give it to ssh with -i. ssh refuses a private key that other accounts can read.";
            else how = "Add it to the authorized_keys file of the account on the server that should accept the key.";
            var msg = "Exported " + written.Path + (format == KeyExportFormat.OpenSshPrivate ? " and " + Path.GetFileName(written.Path) + ".pub" : "") +
                      (isPrivate ? " (checked before it was written: the same key, " + (encrypted ? "opened with its passphrase" : "with NO passphrase") + ")" : "") + "." +
                      WrittenNote(written, isPrivate, encrypted) + "\n" + how;
            bool warn = isPrivate && written.Unprotected;
            ShowKey(key, msg, _kgAllowed, warn ? Orange : Green);
            Status("Exported: " + written.Path);
            if (owner != null) MessageBox.Show(owner, msg, Program.AppName, MessageBoxButtons.OK, warn ? MessageBoxIcon.Warning : MessageBoxIcon.Information);
            return true;
        }

        /// <summary>What to know about files just written: the backups of files that were there, and a drive that keeps no permissions.</summary>
        private static string WrittenNote(KeyWriteResult w, bool privateKey, bool encrypted)
        {
            var s = "";
            if (w.MovedAside.Count > 0) s += " What was there is kept as " + string.Join(", ", w.MovedAside.Select(Path.GetFileName)) + ".";
            if (privateKey && w.Unprotected)
                s += "\nThis drive keeps no file permissions (FAT or exFAT, as on most USB sticks): anyone who has it can read the file" +
                     (encrypted ? ", which only its passphrase protects." : " and use the key, which has NO passphrase.") + " Delete it from the drive once it is copied.";
            return s;
        }

        /// <summary>The tab's view of a key made or converted here, from what was just written (no second read of the file).</summary>
        private static KeyFileInfo KeyInfoOf(KeyGenResult res)
        {
            var e = Keys.Parse(res.PublicKey);
            return new KeyFileInfo
            {
                Path = res.PrivatePath, Format = "OpenSSH", Type = e.Type, Description = KeyFormats.Describe(Convert.FromBase64String(Keys.Blob(res.PublicKey))),
                Fingerprint = res.Fingerprint, Comment = e.Comment ?? "", PublicLine = res.PublicKey, Encrypted = res.Encrypted,
            };
        }

        /// <summary>Allow it to log in: adds the key to the authorized_keys file sshd reads for the account running this program.</summary>
        private async Task AuthorizeCurrentKey()
        {
            var key = CurrentKey();
            bool already = false; // sshd -T works out the file: in the background, it can take seconds
            var where = await BgAsync("Allowing the key to log in...", () => KeyGen.AuthorizeForCurrentUser(key.PublicLine, out already));
            await LoadKeys();
            var text = (already ? "The key was already allowed to log in as " : "The key may now log in as ") + KeyGen.LoginName() + ": it is in " + where + ". \"Test login with this key\" tries it.";
            var type = KeyGen.Types.FirstOrDefault(t => t.Experimental && t.PublicType == key.Type);
            if (type != null && !await EnsureServerAccepts(type)) text += "\nThis server does not accept " + type.PublicType + " yet, so the key cannot log in until PubkeyAcceptedAlgorithms includes it.";
            ShowKey(key, text, true, Green);
            Status(already ? "Key already allowed to log in" : "Key allowed to log in: " + where);
        }

        /// <summary>
        /// The setup wizard's "Create a key for me": a new key pair (the types clients use without extra settings), allowed to
        /// log in as the account running this program, shown on the Key generator tab and offered for export, since the
        /// computer you connect from needs the private key. Returns the note the wizard shows: null when no key was made, empty when it was exported.
        /// </summary>
        private async Task<string> CreateMyKey(IWin32Window owner)
        {
            KeyGenResult res = null;
            using (var d = new NewKeyDialog(async dlg =>
            {
                var t = dlg.KeyType; var p = dlg.PrivatePath; var c = dlg.Comment; var pass = dlg.Passphrase; var now = DateTime.Now;
                res = await BgAsync("Generating " + t.Label + " key...", () => KeyGen.GenerateReplacing(t, p, c, pass, now));
            }))
                if (d.ShowDialog(owner) != DialogResult.OK) return null;
            Log.Info("Key pair created by the setup wizard: " + res.PrivatePath + " " + res.Fingerprint);
            // The key exists from here on: a step that fails is reported with it, it does not hide the key.
            string where = null, problem = null;
            try { bool already; where = await BgAsync("Allowing the key to log in...", () => KeyGen.AuthorizeForCurrentUser(res.PublicKey, out already)); await LoadKeys(); }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex) { problem = ex.Message; Log.Error("Allowing the new key to log in", ex, false); }
            var text = "Created " + res.PrivatePath + " and " + Path.GetFileName(res.PublicPath) + (res.Encrypted ? ", protected by its passphrase" : ", with NO passphrase") + "." +
                       (where != null ? " The key may log in as " + KeyGen.LoginName() + " (" + where + ")." : "\nIt could not be allowed to log in: " + problem + " \"Allow it to log in\" on the Key generator tab tries again.");
            ShowKey(KeyInfoOf(res), text, where != null ? (bool?)true : null, where != null ? Green : Orange);
            Status("Key pair created" + (where != null ? " and allowed to log in: " : ": ") + res.PrivatePath);
            bool exported = false;
            if (MessageBox.Show(owner, text + "\n\nFingerprint " + res.Fingerprint + "\n\nTo log in from another computer, that computer needs the private key. Export a copy now (.ppk for PuTTY, WinSCP and FileZilla, or the OpenSSH format)?",
                    Program.AppName, MessageBoxButtons.YesNo, where != null ? MessageBoxIcon.Information : MessageBoxIcon.Warning) == DialogResult.Yes)
                Safe(() => exported = ExportKey(owner));
            return exported ? "" : "The new key is on this computer only. Before you choose key-only login on the next page, copy its private key to the computer you connect from (Export on the Key generator tab).";
        }

        private void BrowseKeyPath()
        {
            var current = _kgPath.Text.Trim();
            using (var dlg = new SaveFileDialog { Title = "Private key file", OverwritePrompt = false, CheckPathExists = true, AddExtension = false, Filter = "Private key (no extension)|*.*" })
            {
                try { dlg.InitialDirectory = Directory.Exists(Path.GetDirectoryName(current)) ? Path.GetDirectoryName(current) : KeyGen.SshDir; dlg.FileName = Path.GetFileName(current); } catch { }
                if (dlg.ShowDialog(this) == DialogResult.OK) _kgPath.Text = dlg.FileName;
            }
        }

        private async Task GenerateKey()
        {
            var type = (KeyTypeChoice)_kgType.SelectedItem;
            KeyGen.Validate(type, _kgPath.Text, _kgComment.Text.Trim(), _kgPass1.Text, _kgPass2.Text, _kgNoPass.Checked);
            var path = Path.GetFullPath(_kgPath.Text.Trim());
            var now = DateTime.Now;
            if (File.Exists(path) || File.Exists(path + ".pub"))
            {
                // Never overwrite a key: the old pair is kept, with its permissions, under a dated name.
                var stamp = now.ToString("yyyyMMdd-HHmmss");
                if (MessageBox.Show(this, "A key already exists at\n" + path + "\n\nReplace it? The existing files are kept as\n" + Path.GetFileName(path) + ".bak-" + stamp + " and " + Path.GetFileName(path) + ".pub.bak-" + stamp,
                    Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;
            }
            string pass = _kgNoPass.Checked ? null : _kgPass1.Text;
            KeyGenResult res = null;
            var comment = _kgComment.Text.Trim(); // read here: the work below runs on another thread
            try { await BgAsync("Generating " + type.Label + " key...", () => res = KeyGen.GenerateReplacing(type, path, comment, pass, now)); }
            finally { _kgPass1.Text = ""; _kgPass2.Text = ""; pass = null; }
            _kgPublic.Text = res.PublicKey;
            var text = "Created " + res.PrivatePath + " (private key" + (res.Encrypted ? ", protected by the passphrase" : ", NO passphrase") + ") and " + Path.GetFileName(res.PublicPath) +
                       ". Verified: the private key reproduces the public key" + (res.Encrypted ? ", does not open without the passphrase" : "") + ", and only you, SYSTEM and Administrators can read it.";
            if (_kgAuthorize.Checked)
            {
                bool already = false; var where = await BgAsync("Allowing the key to log in...", () => KeyGen.AuthorizeForCurrentUser(res.PublicKey, out already));
                text += "\nAuthorized for " + KeyGen.LoginName() + " in " + where + (already ? " (it was already there)." : ".") + " Use \"Test login with this key\" to try it.";
                await LoadKeys();
                if (type.Experimental && !await EnsureServerAccepts(type))
                    text += "\nThis server does not accept " + type.PublicType + " yet, so the key cannot log in until PubkeyAcceptedAlgorithms includes it.";
            }
            if (type.Experimental)
                text += "\nExperimental key type: clients need OpenSSH 10.5 or later and the line \"PubkeyAcceptedAlgorithms +" + type.PublicType + "\" in their ssh config.";
            var info = KeyInfoOf(res);
            bool? allowed = _kgAuthorize.Checked ? (bool?)null : await BgAsync("Checking whether the key may log in here...", () => AuthorizedState(res.PublicKey));
            ShowKey(info, text, allowed, Green);
            if (_kgAuthorize.Checked) _kgAllowed = true; // said in the text already
            Log.Info("Key pair created: " + res.PrivatePath + " " + res.Fingerprint);
            Status("Key pair created: " + res.PrivatePath);
        }

        /// <summary>
        /// For an experimental key type: asks before adding it to PubkeyAcceptedAlgorithms (validated save with backup,
        /// restart with automatic rollback). Returns true when the server accepts the algorithm afterwards.
        /// </summary>
        private async Task<bool> EnsureServerAccepts(KeyTypeChoice t)
        {
            if (await BgAsync("Checking accepted key algorithms...", () => KeyGen.ServerAccepts(t.PublicType))) return true;
            var value = KeyGen.WithAlgorithm(_cfg.Get("PubkeyAcceptedAlgorithms"), t.PublicType);
            if (value == null)
            {
                MessageBox.Show(this, "PubkeyAcceptedAlgorithms in sshd_config removes algorithms (\"-...\"), so " + t.PublicType + " cannot be added automatically. Edit it on the sshd_config tab.", Program.AppName, MessageBoxButtons.OK, MessageBoxIcon.Information);
                return false;
            }
            if (MessageBox.Show(this, t.PublicType + " is an experimental key type that sshd does not accept by default.\n\nEnable it on this server? This sets\n    PubkeyAcceptedAlgorithms " + value +
                "\nin sshd_config (checked with sshd -t, previous file kept as a backup) and restarts sshd. Connected sessions stay connected.",
                Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Question, MessageBoxDefaultButton.Button2) != DialogResult.Yes) return false;
            var cand = _cfg.Copy();
            cand.Set("PubkeyAcceptedAlgorithms", value);
            var backup = await SaveConfig(cand, "Accept the experimental key type " + t.PublicType + ".", "Save and restart");
            await UseConfig(cand);
            await RestartWithRollback(backup);
            return await BgAsync("Checking accepted key algorithms...", () => KeyGen.ServerAccepts(t.PublicType));
        }

        private async Task TestKeyLogin()
        {
            var p = _kgKey != null ? _kgKey.Path : _kgPath.Text.Trim();
            if (p.Length == 0 || !File.Exists(p)) throw new ConfigException("No private key at\n" + p + "\n\nGenerate one first, or load a key.");
            var path = Path.GetFullPath(p);
            string pass = null;
            if (KeyGen.IsEncrypted(path))
            {
                using (var dlg = new PasswordDialog("Passphrase for " + Path.GetFileName(path))) { if (dlg.ShowDialog(this) != DialogResult.OK) return; pass = dlg.Value; }
            }
            RunResult r = null;
            int port = _cfg == null ? 22 : _cfg.EffectivePort;
            try { await BgAsync("Logging in to this server with " + Path.GetFileName(path) + "...", () => r = KeyGen.TestLogin(path, pass, port)); }
            finally { pass = null; }
            if (KeyGen.LoginOk(r))
            {
                var ok = "Login test passed: this server accepted " + Path.GetFileName(path) + " for " + KeyGen.LoginName() + " on port " + port + " (public key only, host key checked).";
                if (_kgKey != null && _kgKey.Path == path) ShowKey(_kgKey, ok, true, Green); else { _kgResult.Text = ok; _kgResult.ForeColor = Green; }
                Status("Login test passed");
            }
            else
            {
                var detail = r == null ? "" : r.Output.Trim();
                var failed = "Login test failed for " + Path.GetFileName(path) + ". " + (detail.Length > 400 ? detail.Substring(0, 400) + "..." : detail) +
                             "\nIf the key may not log in here yet, \"Allow it to log in\" adds it.";
                if (_kgKey != null && _kgKey.Path == path) ShowKey(_kgKey, failed, _kgAllowed, Red); else { _kgResult.Text = failed; _kgResult.ForeColor = Red; }
                Status("Login test failed");
            }
        }

        // ---------------- Firewall ----------------
        private string _fwShown;
        private string FirewallInputs() { return _fwEnabled.Checked + "|" + _fwDomain.Checked + "|" + _fwPrivate.Checked + "|" + _fwPublic.Checked + "|" + _fwPort.Value; }
        private bool FirewallEdited() { return _fwShown != null && _fwShown != FirewallInputs(); }
        private void CaptureFirewall() { _fwShown = FirewallInputs(); UpdatePending(); }

        private TabPage BuildFirewall()
        {
            var page = new TabPage("Firewall");
            var flow = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown, WrapContents = false, Padding = new Padding(12) };
            _fwState = new Label { AutoSize = true, Font = new Font(Font, FontStyle.Bold), Margin = new Padding(4, 4, 4, 12) };
            flow.Controls.Add(_fwState);
            _fwEnabled = new CheckBox { Text = "Inbound rule enabled", AutoSize = true, Margin = new Padding(4) }; flow.Controls.Add(_fwEnabled);
            flow.Controls.Add(Lbl("Profiles the rule applies to:", true));
            _fwDomain = new CheckBox { Text = "Domain  (domain-joined servers)", AutoSize = true, Margin = new Padding(24, 2, 4, 2) };
            _fwPrivate = new CheckBox { Text = "Private  (home / work networks)", AutoSize = true, Margin = new Padding(24, 2, 4, 2) };
            _fwPublic = new CheckBox { Text = "Public  (untrusted networks)", AutoSize = true, Margin = new Padding(24, 2, 4, 2) };
            flow.Controls.Add(_fwDomain); flow.Controls.Add(_fwPrivate); flow.Controls.Add(_fwPublic);
            var portRow = Flow(); portRow.Controls.Add(Lbl("TCP port:"));
            _fwPort = new NumericUpDown { Minimum = 1, Maximum = 65535, Value = 22, Width = Ui.Px(90), Margin = new Padding(4, 6, 4, 4) }; _fwPort.AccessibleName = "TCP port"; portRow.Controls.Add(_fwPort);
            flow.Controls.Add(portRow);
            var bar = Flow();
            bar.Controls.Add(Btn("Apply", async (s, e) => await SafeAsync(ApplyFirewall), 110));
            _tips.SetToolTip(bar.Controls[0], "Ctrl+S");
            bar.Controls.Add(Btn("Use sshd port", (s, e) => Safe(() =>
            {
                var ports = ExpectedPorts(_cfg ?? new SshdConfig());
                _fwPort.Value = ports[0];
                if (ports.Count > 1) Status("sshd_config gives the ports " + string.Join(", ", ports) + ": the field shows the first; Apply asks before the rule stops allowing one of them");
            }), 120));
            bar.Controls.Add(Btn("Remove rule", async (s, e) => await SafeAsync(async () => { if (MessageBox.Show(this, "Remove the inbound firewall rule for sshd? Remote clients will no longer reach the server.", Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) == DialogResult.Yes) { await BgAsync("Removing the firewall rule...", Firewall.Remove); await LoadFirewallRule(true); } }), 120));
            bar.Controls.Add(Btn("Windows Firewall console", (s, e) => Proc.OpenExternal("wf.msc"), 190));
            flow.Controls.Add(bar);
            flow.Controls.Add(new Label { AutoSize = true, ForeColor = Theme.Muted, Margin = new Padding(4, 12, 4, 4), MaximumSize = new Size(Ui.Px(800), 0), Text = "The rule is scoped to sshd.exe. Domain-joined Windows Servers use the Domain profile; laptops on untrusted networks use Public. Restrict remote addresses in the Windows Firewall console if the server must only be reachable from specific networks." });
            page.Controls.Add(flow);
            foreach (var box in new[] { _fwEnabled, _fwDomain, _fwPrivate, _fwPublic }) box.CheckedChanged += (s, e) => UpdatePending();
            _fwPort.ValueChanged += (s, e) => UpdatePending();
            return page;
        }

        private async Task ApplyFirewall()
        {
            int chosen = (int)_fwPort.Value;
            string ports = chosen.ToString();
            // A rule with several ports (edited in the Windows Firewall console) keeps its list unless the user decides otherwise.
            if (!string.IsNullOrEmpty(_fwLoadedPorts) && !Firewall.IsSinglePort(_fwLoadedPorts))
            {
                if (Firewall.Covers(_fwLoadedPorts, chosen)) ports = _fwLoadedPorts;
                else
                {
                    var answer = MessageBox.Show(this, "The rule allows ports " + _fwLoadedPorts + ".\n\nYes: add port " + chosen + " to them.\nNo: allow only port " + chosen + ".", Program.AppName, MessageBoxButtons.YesNoCancel, MessageBoxIcon.Question);
                    if (answer == DialogResult.Cancel) return;
                    ports = answer == DialogResult.Yes ? _fwLoadedPorts + "," + chosen : chosen.ToString();
                }
            }
            int profiles = (_fwDomain.Checked ? 1 : 0) | (_fwPrivate.Checked ? 2 : 0) | (_fwPublic.Checked ? 4 : 0);
            // Taking a port sshd uses away from the rule, or switching the rule off, cuts off remote clients: ask first. The
            // ports are sshd's (sshd -T, with Include files and ListenAddress ports, and the running listeners), else the file's.
            var state = await BgAsync("Resolving the server endpoints...", ServerState.Read);
            var uncovered = FirewallUncovered(state.Verified ? state.Ports : ExpectedPorts(_cfg ?? new SshdConfig()).ToArray(), ports);
            if (!Program.Unattended && (!_fwEnabled.Checked || uncovered.Count > 0) &&
                MessageBox.Show(this, (!_fwEnabled.Checked ? "The rule will be switched off: other computers can then no longer connect over SSH." : "The rule will not allow port " + string.Join(", ", uncovered) + ", which sshd uses: other computers can then no longer connect there over SSH.") + "\n\nApply anyway?", Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;
            bool enabled = _fwEnabled.Checked;
            await BgAsync("Updating the firewall rule...", () => Firewall.Apply(enabled, profiles, ports));
            await LoadFirewallRule(true); Status("Firewall rule updated");
        }

        /// <summary>The ports sshd uses that a LocalPorts value would not allow.</summary>
        internal static List<int> FirewallUncovered(IEnumerable<int> sshdPorts, string ports) { return sshdPorts.Distinct().Where(p => !Firewall.Covers(ports, p)).ToList(); }

        /// <summary>After the rule was changed by another tab, the wizard or a recovery: changes on this tab not applied yet stay.</summary>
        private Task LoadFirewall() { return LoadFirewallRule(false); }

        /// <summary>
        /// Shows the rule. Unless discard, a box or the port changed on the tab and not applied yet keeps its value over the
        /// rule's, and the rest shows the rule; the ports a multi-port Apply keeps are the rule's as read now either way.
        /// </summary>
        private async Task LoadFirewallRule(bool discard)
        {
            // A failed query is an error, not "no rule": Apply would create a second rule or rewrite the ports.
            var fw = await BgAsync("Reading the firewall rule...", () => Firewall.Find());
            string[] was = null, typed = null;
            if (!discard && FirewallEdited()) { was = _fwShown.Split('|'); typed = FirewallInputs().Split('|'); }
            _fwLoadedPorts = fw == null ? null : fw.Ports;
            // A multi-port rule (or none) shows sshd's port in the field; Apply keeps the whole list (see the Apply button).
            int p, sshdPort = _cfg == null ? 22 : ExpectedPorts(_cfg)[0];
            if (fw == null)
            {
                _fwState.Text = "No inbound rule for sshd found. Choose profiles and click Apply to create one."; _fwState.ForeColor = Red;
                _fwEnabled.Checked = true; _fwDomain.Checked = _fwPrivate.Checked = _fwPublic.Checked = true; _fwPort.Value = sshdPort;
            }
            else
            {
                _fwState.Text = "Rule \"" + fw.Name + "\": " + (fw.Enabled ? "enabled" : "disabled") + ", profiles " + fw.ProfilesText + ", port " + fw.Ports + ", program " + fw.Program;
                _fwState.ForeColor = fw.Enabled ? Green : Red;
                _fwEnabled.Checked = fw.Enabled;
                bool all = (fw.Profiles & 0x7fffffff) == 0x7fffffff;
                _fwDomain.Checked = all || (fw.Profiles & 1) != 0; _fwPrivate.Checked = all || (fw.Profiles & 2) != 0; _fwPublic.Checked = all || (fw.Profiles & 4) != 0;
                _fwPort.Value = int.TryParse(fw.Ports, out p) && p >= 1 && p <= 65535 ? p : sshdPort;
            }
            CaptureFirewall();
            if (typed == null) return;
            var boxes = new[] { _fwEnabled, _fwDomain, _fwPrivate, _fwPublic };
            for (int i = 0; i < boxes.Length; i++) if (typed[i] != was[i]) boxes[i].Checked = bool.Parse(typed[i]);
            if (typed[4] != was[4]) _fwPort.Value = decimal.Parse(typed[4]);
            UpdatePending();
            Status("The firewall rule changed; the changes on the Firewall tab not applied yet are kept");
        }

        // ---------------- Logs ----------------
        private TabPage BuildLogs()
        {
            var page = new TabPage("Logs");
            var split = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal };
            bool splitInit = false;
            split.SizeChanged += (s, e) => { if (splitInit || split.Height < Ui.Px(300)) return; splitInit = true; try { split.SplitterDistance = split.Height * 62 / 100; } catch { } };
            var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2 };
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize)); root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            var bar = Flow();
            bar.Controls.Add(Lbl("Event log " + EventLogs.LogName + "   filter:"));
            _txtFilter = new TextBox { Width = Ui.Px(200), Margin = new Padding(4, 6, 4, 4) }; _txtFilter.KeyDown += async (s, e) => { if (e.KeyCode == System.Windows.Forms.Keys.Enter) { e.SuppressKeyPress = true; await SafeAsync(LoadLogs); } };
            _txtFilter.AccessibleName = "Event filter"; bar.Controls.Add(_txtFilter);
            _cmbPeriod = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = Ui.Px(130), Margin = new Padding(4, 6, 4, 4), AccessibleName = "Period" };
            _cmbPeriod.Items.AddRange(new object[] { "Last hour", "Last 24 hours", "Last 7 days", "Last 30 days", "All" }); _cmbPeriod.SelectedIndex = 1;
            _cmbPeriod.SelectedIndexChanged += async (s, e) => { if (_lvEvents.Items.Count > 0) await SafeAsync(LoadLogs); };
            bar.Controls.Add(_cmbPeriod);
            bar.Controls.Add(Lbl("max:"));
            _numEvents = new NumericUpDown { Minimum = 50, Maximum = 20000, Value = 500, Increment = 50, Width = Ui.Px(80), Margin = new Padding(4, 6, 4, 4) }; _numEvents.AccessibleName = "Maximum number of events"; bar.Controls.Add(_numEvents);
            bar.Controls.Add(Btn("Refresh", async (s, e) => await SafeAsync(LoadLogs), 100));
            bar.Controls.Add(Btn("Failed logins only", async (s, e) => await SafeAsync(async () => { _txtFilter.Text = "Failed"; await LoadLogs(); }), 150));
            bar.Controls.Add(Btn("Accepted logins only", async (s, e) => await SafeAsync(async () => { _txtFilter.Text = "Accepted"; await LoadLogs(); }), 160));
            var sftpEvents = Btn("SFTP transfers", async (s, e) => await SafeAsync(async () => { _txtFilter.Text = "sftp-server"; await LoadLogs(); }), 130);
            _tips.SetToolTip(sftpEvents, "Events of sftp-server: each file opened and closed with the bytes read and written, renamed or removed, by account (with Log file transfers on the SFTP tab).");
            bar.Controls.Add(sftpEvents);
            bar.Controls.Add(Btn("Failed logins by address...", async (s, e) => await SafeAsync(ShowFailedByAddress), 200));
            bar.Controls.Add(Btn("Copy selected", (s, e) => Safe(() => { var rows = _lvEvents.SelectedItems.Cast<ListViewItem>().Select(i => string.Join("\t", i.SubItems.Cast<ListViewItem.ListViewSubItem>().Select(x => x.Text))).ToList(); if (rows.Count > 0) Clipboard.SetText(string.Join("\r\n", rows)); }), 120));
            bar.Controls.Add(Btn("Export...", (s, e) => Safe(() => { var f = Export.SaveList(this, "OpenSSH events", "openssh-events", "Events of " + EventLogs.LogName + " on " + Environment.MachineName + ", " + _cmbPeriod.Text.ToLowerInvariant() + (_txtFilter.Text.Trim().Length > 0 ? ", filter \"" + _txtFilter.Text.Trim() + "\"" : "") + ".", _lvEvents, r => r.Count > 2 && r[2].StartsWith("Err", StringComparison.OrdinalIgnoreCase) ? "error" : null); if (f != null) Status("Exported to " + f); }), 100));
            _tips.SetToolTip(bar.Controls[bar.Controls.Count - 3], "Addresses with failed or abandoned logins in the events shown, and a firewall block list for them.");
            root.Controls.Add(bar, 0, 0);
            _lvEvents = Lv("Time|140", "ID|50", "Level|80", "Message|760"); _lvEvents.AccessibleName = "Events";
            _lvEvents.MultiSelect = true;
            _lvEvents.ItemActivate += (s, e) => { if (_lvEvents.SelectedItems.Count > 0) using (var d = new TextDialog("Event " + _lvEvents.SelectedItems[0].SubItems[1].Text + ", " + _lvEvents.SelectedItems[0].SubItems[0].Text, _lvEvents.SelectedItems[0].SubItems[3].Text)) d.ShowDialog(this); };
            root.Controls.Add(_lvEvents, 0, 1);
            split.Panel1.Controls.Add(root);
            var fileBox = new GroupBox { Text = "File log (%ProgramData%\\ssh\\logs, used when SyslogFacility is LOCAL0-7)", Dock = DockStyle.Fill, Padding = new Padding(6) };
            _txtFileLog = new TextBox { Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Both, WordWrap = false, Dock = DockStyle.Fill, Font = new Font("Consolas", Ui.Pt(9.5f)) };
            _txtFileLog.AccessibleName = "File log"; fileBox.Controls.Add(_txtFileLog);
            split.Panel2.Controls.Add(fileBox);
            page.Controls.Add(split);
            return page;
        }

        private ComboBox _cmbPeriod;
        private List<LogEvent> _events = new List<LogEvent>();

        /// <summary>The period chosen on the Logs tab, or null for all events.</summary>
        private TimeSpan? LogPeriod()
        {
            switch (_cmbPeriod.SelectedIndex)
            {
                case 0: return TimeSpan.FromHours(1);
                case 1: return TimeSpan.FromDays(1);
                case 2: return TimeSpan.FromDays(7);
                case 3: return TimeSpan.FromDays(30);
                default: return null;
            }
        }

        private async Task LoadLogs()
        {
            int max = (int)_numEvents.Value; var filter = _txtFilter.Text.Trim(); var period = LogPeriod();
            string fileText = null;
            var events = await BgCancellableAsync("Reading events (Cancel stops and shows what was read)...", token =>
            {
                var l = EventLogs.Read(max, filter, period, token);
                var f = EventLogs.FileLogPath();
                fileText = f == null ? "No file log present. Set 'Log destination' to LOCAL0 on the Settings tab to log to a file." : ("== " + f + "\r\n" + EventLogs.TailFile(f, 300).Replace("\r\n", "\n").Replace("\n", "\r\n"));
                return l;
            });
            _events = events;
            _lvEvents.BeginUpdate(); _lvEvents.Items.Clear();
            foreach (var ev in events)
            {
                var it = new ListViewItem(new[] { ev.Time.ToString("yyyy-MM-dd HH:mm:ss"), ev.Id.ToString(), ev.Level, ev.Message });
                if (ev.Level.StartsWith("Err", StringComparison.OrdinalIgnoreCase)) it.ForeColor = Red;
                else if (ev.Level.StartsWith("Warn", StringComparison.OrdinalIgnoreCase) || ev.Message.IndexOf("Failed", StringComparison.OrdinalIgnoreCase) >= 0) it.ForeColor = Orange;
                _lvEvents.Items.Add(it);
            }
            _lvEvents.EndUpdate();
            _txtFileLog.Text = fileText ?? "";
            Status(_lvEvents.Items.Count + " event(s)" + (_lvEvents.Items.Count >= max ? " (the maximum; raise it or choose a shorter period to see more)" : ""));
        }

        /// <summary>The addresses with failed logins among the events read, and the block list in the firewall.</summary>
        private async Task ShowFailedByAddress()
        {
            if (_events.Count == 0) await LoadLogs();
            var sources = EventLogs.FailedByAddress(_events);
            var state = await BgAsync("Verifying server endpoints...", ServerState.Read);
            if (!state.Verified) throw new ConfigException("Blocking is unavailable until all SSH endpoints can be inspected. " + state.Error);
            HashSet<string> peers = null; string error = null;
            if (!await BgAsync("Checking logged-in peers...", () => Sessions.TryLoggedInAddresses(state.Ports, out peers, out error)))
                throw new ConfigException("Blocking is unavailable because logged-in peers could not be verified. " + error);
            using (var d = new FailedLoginsDialog(sources, _cmbPeriod.Text.ToLowerInvariant(), state.FirewallPorts, peers.ToList()))
                d.ShowDialog(this);
        }

        // ---------------- Hardening ----------------
        private TabPage BuildHardening()
        {
            var page = new TabPage("Hardening");
            var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2 };
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize)); root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            var bar = Flow();
            bar.Controls.Add(Btn("Run checks", async (s, e) => await SafeAsync(RunChecks), 110));
            bar.Controls.Add(Btn("Fix selected...", async (s, e) => await SafeAsync(FixSelectedChecks), 130));
            bar.Controls.Add(Btn("Apply recommended settings", async (s, e) => await SafeAsync(ApplyRecommended), 210));
            bar.Controls.Add(Btn("Export report...", async (s, e) => await SafeAsync(async () => { var version = await BgAsync("Reading the server version...", Ssh.ServerVersion); var f = Export.SaveList(this, "OpenSSH hardening report", "openssh-hardening", "Hardening checks of " + Environment.MachineName + " (" + version + "), " + DateTime.Now.ToString("yyyy-MM-dd HH:mm") + ", by " + Program.AppName + " " + Program.AppVersion + ".", _lvChecks, r => r.Count > 1 ? (r[1] == "OK" ? "ok" : r[1] == "WARN" ? "warn" : null) : null); if (f != null) Status("Exported to " + f); }), 140));
            _tips.SetToolTip(bar.Controls[1], "Fixes the selected warnings (double-click or Enter on one also works). Settings in sshd_config are shown before they are saved; login methods, login restrictions and SFTP open their tab instead.");
            bar.Controls.Add(new Label { AutoSize = true, Margin = new Padding(12, 10, 4, 4), ForeColor = Theme.Muted, MaximumSize = new Size(Ui.Px(700), 0), Text = "Recommended: ClientAliveInterval 300, MaxAuthTries 4, LoginGraceTime 60, RequiredRSASize 2048, LogLevel VERBOSE, keyboard-interactive off, PerSourcePenalties on. Windows authentication and login restrictions are never changed automatically (see the Authentication and Settings tabs)." });
            root.Controls.Add(bar, 0, 0);
            _lvChecks = Lv("Check|220", "Status|70", "Detail|700"); _lvChecks.AccessibleName = "Hardening checks";
            _lvChecks.MultiSelect = true;
            _lvChecks.ItemActivate += async (s, e) => await SafeAsync(FixSelectedChecks);
            root.Controls.Add(_lvChecks, 0, 1);
            page.Controls.Add(root);
            return page;
        }

        private async Task RunChecks()
        {
            var cfg = _cfg;
            var checks = await BgAsync("Running checks...", () => Hardening.Run(cfg));
            _lvChecks.BeginUpdate(); _lvChecks.Items.Clear();
            foreach (var c in checks)
            {
                var it = new ListViewItem(new[] { c.Name, c.Status, c.Detail }) { Tag = c };
                it.ForeColor = c.Status == "OK" ? Green : c.Status == "WARN" ? Orange : Theme.Text;
                _lvChecks.Items.Add(it);
            }
            _lvChecks.EndUpdate();
            Status("Checks complete: " + _lvChecks.Items.Cast<ListViewItem>().Count(i => i.SubItems[1].Text == "WARN") + " warning(s)");
        }

        /// <summary>The sshd_config change that fixes a check, or null when the check is not fixed by a setting.</summary>
        internal static Action<SshdConfig> ConfigFix(string check)
        {
            switch (check)
            {
                case "Keyboard-interactive": return c => { c.Set("KbdInteractiveAuthentication", "no"); c.Set("ChallengeResponseAuthentication", ""); };
                case "Empty passwords": return c => c.Set("PermitEmptyPasswords", "no");
                case "MaxAuthTries": return c => c.Set("MaxAuthTries", "4");
                case "Per-source penalties": return c => { if ((c.Get("PerSourcePenalties") ?? "").Equals("no", StringComparison.OrdinalIgnoreCase)) c.Set("PerSourcePenalties", ""); else c.Set("PerSourcePenalties", "authfail:5 noauth:1 crash:90 max:600"); };
                case "MaxStartups throttling": return c => c.Set("MaxStartups", "10:30:100");
                case "Idle session timeout": return c => { c.Set("ClientAliveInterval", "300"); c.Set("ClientAliveCountMax", "3"); };
                case "Login grace time": return c => c.Set("LoginGraceTime", "60");
                case "Minimum RSA key size": return c => c.Set("RequiredRSASize", "2048");
                case "Log level": return c => c.Set("LogLevel", "VERBOSE");
                // The defaults of OpenSSH 10.5 are the modern sets: an explicit list is what brings the old algorithms back.
                case "Key exchange": return c => c.Set("KexAlgorithms", "");
                case "Host key algorithms": return c => c.Set("HostKeyAlgorithms", "");
                case "Ciphers": return c => c.Set("Ciphers", "");
            }
            return null;
        }

        /// <summary>
        /// The checks whose fix leaves sshd_config as it is: sshd takes the value from an included file (the fixes edit
        /// sshd_config only), so saving and restarting would change nothing.
        /// </summary>
        internal static List<string> IneffectiveFixes(SshdConfig cfg, IEnumerable<string> checks)
        {
            return checks.Where(name => { var c = cfg.Copy(); ConfigFix(name)(c); return c.Text == cfg.Text; }).ToList();
        }

        /// <summary>
        /// Fixes the selected warnings: settings in one save (shown first) and one restart; other fixes one by one, each
        /// asked. Checks fixed on another tab open that tab at the end (the first one; the others are named).
        /// </summary>
        private async Task FixSelectedChecks()
        {
            var selected = _lvChecks.SelectedItems.Cast<ListViewItem>().Select(i => i.Tag as CheckResult).Where(c => c != null && c.Status == "WARN").ToList();
            if (selected.Count == 0) { Status("Select one or more checks with WARN first"); return; }
            var cfgFixes = selected.Where(c => ConfigFix(c.Name) != null).Select(c => c.Name).ToList();
            var elsewhere = new List<Tuple<TabPage, string, string>>(); bool acted = false;
            Action<TabPage, string, string> later = (page, tab, hint) => { if (!elsewhere.Any(t => t.Item1 == page)) elsewhere.Add(Tuple.Create(page, tab, hint)); };
            foreach (var c in selected.Where(x => ConfigFix(x.Name) == null))
            {
                if (c.Name == "Password authentication") { later(_pgAuth, "Authentication", "Login methods are changed on the Authentication tab"); continue; }
                if (c.Name == "SFTP" || c.Name == "SFTP-only accounts") { later(_pgSftp, "SFTP", "SFTP and SFTP-only accounts are set on the SFTP tab; Apply creates missing folders"); continue; }
                if (c.Name == "Login restriction") { later(_pgSettings, "Settings", "Enter the groups allowed to log in (AllowGroups), for example administrators \"openssh users\""); continue; }
                if (c.Name == "Firewall rule") { later(_pgFirewall, "Firewall", "Tick \"Inbound rule enabled\" and click Apply"); continue; }
                if (c.Name == "sshd service")
                {
                    if (MessageBox.Show(this, "Set the sshd service to start automatically and start it now?", Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) continue;
                    _expectedStateChange = DateTime.UtcNow;
                    await BgAsync("Starting sshd...", () => { Services.SetStartMode("sshd", "auto"); Services.Start("sshd"); });
                    acted = true; continue;
                }
                if (c.Name == "Host keys") { await GenerateHostKeys(); acted = true; continue; }
                if (c.Name == "administrators_authorized_keys ACL")
                {
                    await BgAsync("Fixing permissions...", () => { Acl.Restrict(Ssh.AdminKeysPath, null); Acl.EnsureOwner(Ssh.AdminKeysPath, null); });
                    await LoadKeys(); acted = true; continue;
                }
                if (c.Name == "Public network exposure")
                {
                    var fw = await BgAsync("Reading the firewall rule...", Firewall.Get); if (fw == null) continue;
                    int profiles = fw.Profiles & 3; if ((fw.Profiles & 0x7fffffff) == 0x7fffffff) profiles = 3; if (profiles == 0) profiles = 3;
                    if (MessageBox.Show(this, "Limit the sshd firewall rule to the " + FirewallRule.ProfileText(profiles) + " profile(s)? Computers on a public network (a café, a hotel) can then no longer connect.", Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) continue;
                    await BgAsync("Updating the firewall profiles...", () => Firewall.Apply(fw.Enabled, profiles, fw.Ports)); await LoadFirewall(); acted = true; continue;
                }
                MessageBox.Show(this, c.Name + ": " + c.Detail + "\n\nThis cannot be fixed from here. Repair the package (msiexec /fa <package>.msi) or correct the permissions by hand.", Program.AppName, MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            var ineffective = IneffectiveFixes(_cfg, cfgFixes);
            cfgFixes = cfgFixes.Except(ineffective).ToList();
            if (cfgFixes.Count > 0)
            {
                var cand = _cfg.Copy();
                foreach (var name in cfgFixes) ConfigFix(name)(cand);
                var b = await SaveConfig(cand, "Fix: " + string.Join(", ", cfgFixes) + ".", "Save and restart");
                await UseConfig(cand);
                await RestartWithRollback(b);
                acted = true;
            }
            if (ineffective.Count > 0)
            {
                var inc = _cfg.Includes();
                var text = string.Join(", ", ineffective) + ": not changed. sshd takes " + (ineffective.Count > 1 ? "these values" : "this value") + " from an included file" + (inc.Count > 0 ? " (Include " + string.Join("; ", inc) + ")" : "") +
                           ", and the fix would leave sshd_config as it is, so nothing was saved or restarted.\n\nEdit that file, or set the value on the Settings tab: it is written before the first Include, and sshd takes the first value it reads.";
                Log.Info("Hardening fix without effect on sshd_config: " + string.Join(", ", ineffective));
                if (!Program.Unattended) MessageBox.Show(this, text, Program.AppName, MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            if (acted) await RunChecks();
            if (elsewhere.Count > 0)
            {
                _tabs.SelectedTab = elsewhere[0].Item1;
                if (elsewhere[0].Item1 == _pgSettings) _fields["AllowGroups"].Focus();
                Status(elsewhere[0].Item3 + (elsewhere.Count > 1 ? ". Also on the " + string.Join(" and ", elsewhere.Skip(1).Select(t => t.Item2)) + " tab" + (elsewhere.Count > 2 ? "s" : "") : ""));
            }
            else if (ineffective.Count > 0 && cfgFixes.Count == 0 && !acted) Status("Not changed: sshd takes " + string.Join(", ", ineffective) + " from an included file");
        }

        private async Task ApplyRecommended()
        {
            if (MessageBox.Show(this, "Write these settings to sshd_config?\n\n  ClientAliveInterval 300\n  ClientAliveCountMax 3\n  MaxAuthTries 4\n  LoginGraceTime 60\n  RequiredRSASize 2048\n  LogLevel VERBOSE\n  KbdInteractiveAuthentication no (it has no Windows back end)\n  PerSourcePenalties (sshd default, enabled)\n\nA backup is created and the file is validated first. sshd is restarted afterwards.", Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
            var c = _cfg.Copy();
            c.Set("ClientAliveInterval", "300"); c.Set("ClientAliveCountMax", "3"); c.Set("MaxAuthTries", "4"); c.Set("LogLevel", "VERBOSE");
            c.Set("LoginGraceTime", "60"); c.Set("RequiredRSASize", "2048");
            c.Set("KbdInteractiveAuthentication", "no"); c.Set("ChallengeResponseAuthentication", "");
            if ((c.Get("PerSourcePenalties") ?? "").Equals("no", StringComparison.OrdinalIgnoreCase)) c.Set("PerSourcePenalties", "");
            var b = await SaveConfig(c, "Apply the recommended settings.", "Save and restart"); await UseConfig(c);
            await RestartWithRollback(b); await RunChecks();
        }

        // ---------------- Notification area icon, notifications ----------------
        private NotifyIcon _tray; private ContextMenuStrip _trayMenu; private string _lastSshdStatus;
        private EventLogWatcher _failureWatcher;
        private readonly Queue<DateTime> _failures = new Queue<DateTime>();
        private DateTime _lastFailureNotice = DateTime.MinValue;

        /// <summary>The icon in the notification area: the service state in its tooltip, a menu, and notifications.</summary>
        private void InitTray()
        {
            if (Program.Unattended || !Prefs.TrayIcon || _tray != null) return;
            _trayMenu = new ContextMenuStrip();
            _trayMenu.Items.Add("Open " + Program.AppName, null, (s, e) => ShowFromTray());
            _trayMenu.Items.Add(new ToolStripSeparator());
            _trayMenu.Items.Add("Start sshd", null, async (s, e) => { ShowFromTray(); await ServiceAction("start"); });
            _trayMenu.Items.Add("Restart sshd", null, async (s, e) => { ShowFromTray(); await ServiceAction("restart"); });
            _trayMenu.Items.Add("Stop sshd", null, async (s, e) => { ShowFromTray(); await ServiceAction("stop"); });
            _trayMenu.Items.Add(new ToolStripSeparator());
            _trayMenu.Items.Add("Sessions", null, (s, e) => { ShowFromTray(); _tabs.SelectedTab = _pgSessions; });
            _trayMenu.Items.Add("Logs", null, (s, e) => { ShowFromTray(); _tabs.SelectedTab = _pgLogs; });
            _trayMenu.Items.Add("Setup wizard...", null, async (s, e) => { ShowFromTray(); await SafeAsync(RunWizard); });
            _trayMenu.Items.Add(new ToolStripSeparator());
            _trayMenu.Items.Add("Exit", null, (s, e) => { ShowFromTray(); Close(); });
            // While an operation runs or a dialog is open, the menu only opens the window: its actions would start a second
            // operation inside the first one.
            _trayMenu.Opening += (s, e) =>
            {
                bool idle = _busyDepth == 0 && !Application.OpenForms.Cast<Form>().Any(f => f.Modal);
                for (int i = 1; i < _trayMenu.Items.Count; i++) _trayMenu.Items[i].Enabled = idle;
            };
            _tray = new NotifyIcon { Icon = Ui.AppIcon ?? SystemIcons.Application, Text = Program.AppName, ContextMenuStrip = _trayMenu, Visible = true };
            _tray.DoubleClick += (s, e) => ShowFromTray();
            _tray.BalloonTipClicked += (s, e) => ShowFromTray();
            if (!_minimizeHooked)
            {
                _minimizeHooked = true;
                Resize += (s, e) => { if (WindowState == FormWindowState.Minimized && Prefs.MinimizeToTray && _tray != null) { Hide(); Notify(Program.AppName, "Still running here; double-click the icon to open the window.", ToolTipIcon.Info, false); } };
            }
            StartFailureWatcher();
        }

        private bool _minimizeHooked;

        private void ShowFromTray()
        {
            if (!Visible) Show();
            if (WindowState == FormWindowState.Minimized) WindowState = FormWindowState.Normal;
            Activate();
        }

        private DateTime _lastInfoNotice = DateTime.MinValue;
        private void Notify(string title, string text, ToolTipIcon icon, bool important = true)
        {
            if (_tray == null) return;
            if (!important && DateTime.UtcNow - _lastInfoNotice < TimeSpan.FromHours(1)) return; // "still running" only now and then
            if (!important) _lastInfoNotice = DateTime.UtcNow;
            _tray.ShowBalloonTip(10000, title, text, icon);
            Log.Info("Notification: " + title + ": " + text);
        }

        /// <summary>Called with every dashboard refresh: the tooltip, and a notification when sshd stopped without this window stopping it.</summary>
        private void TrayState(ServiceState sshd, int sessions)
        {
            if (_tray == null) return;
            var t = "sshd: " + sshd.Status + (sshd.Status == "Running" ? ", " + sessions + " connection(s)" : "");
            _tray.Text = t.Length > 63 ? t.Substring(0, 63) : t;
            if (_lastSshdStatus == "Running" && sshd.Status != "Running" && DateTime.UtcNow - _expectedStateChange > TimeSpan.FromMinutes(2))
                Notify("sshd is not running", "The SSH server is " + sshd.Status.ToLowerInvariant() + ". New connections are refused. Open the manager to start it, and see the Logs tab for the reason.", ToolTipIcon.Error);
            else if (_lastSshdStatus != null && _lastSshdStatus != "Running" && sshd.Status == "Running" && DateTime.UtcNow - _expectedStateChange > TimeSpan.FromMinutes(2))
                Notify("sshd is running again", "The SSH server was started.", ToolTipIcon.Info);
            _lastSshdStatus = sshd.Status;
        }

        /// <summary>Counts failed logins as sshd logs them and notifies when a threshold is crossed (Prefs.FailedLoginThreshold).</summary>
        private void StartFailureWatcher()
        {
            if (Prefs.FailedLoginThreshold <= 0) return;
            try
            {
                _failureWatcher = new EventLogWatcher(new EventLogQuery(EventLogs.LogName, PathType.LogName, "*"));
                _failureWatcher.EventRecordWritten += (s, e) =>
                {
                    if (e.EventRecord == null) return;
                    string msg;
                    using (e.EventRecord)
                    {
                        try { msg = e.EventRecord.FormatDescription(); } catch { msg = null; }
                        if (string.IsNullOrEmpty(msg)) { try { msg = EventLogs.FallbackText(e.EventRecord.Properties.Select(v => v.Value)); } catch { msg = null; } }
                    }
                    string user; var addr = EventLogs.FailedLoginAddress(msg, out user);
                    if (addr == null) return;
                    try { BeginInvoke((Action)(() => CountFailure(addr))); } catch (InvalidOperationException) { }
                };
                _failureWatcher.Enabled = true;
            }
            catch (Exception ex) { Log.Error("Watching the event log for failed logins", ex, false); _failureWatcher = null; }
        }

        private void CountFailure(string address)
        {
            var now = DateTime.UtcNow; var window = TimeSpan.FromMinutes(Prefs.FailedLoginMinutes);
            _failures.Enqueue(now);
            while (_failures.Count > 0 && now - _failures.Peek() > window) _failures.Dequeue();
            if (_failures.Count >= Prefs.FailedLoginThreshold && now - _lastFailureNotice > window)
            {
                _lastFailureNotice = now;
                Notify("Failed SSH logins", _failures.Count + " failed logins in the last " + Prefs.FailedLoginMinutes + " minute(s), the latest from " + address + ". The Logs tab shows them by address and can block addresses.", ToolTipIcon.Warning);
            }
        }

        private void StopWatchers()
        {
            try { if (_failureWatcher != null) { _failureWatcher.Enabled = false; _failureWatcher.Dispose(); _failureWatcher = null; } } catch { }
            try { if (_tray != null) { _tray.Visible = false; _tray.Dispose(); _tray = null; } } catch { }
            try { if (_trayMenu != null) { _trayMenu.Dispose(); _trayMenu = null; } } catch { }
        }

        // ---------------- Setup wizard ----------------
        /// <summary>Offers the setup wizard once, on the first start of the manager on this account.</summary>
        private async Task OfferWizard()
        {
            if (Program.Unattended) return;
            // --wizard (the Start menu shortcut), or started by the package after installing: straight into the wizard.
            if (Program.StartWizard)
            {
                Prefs.WizardOffered = true;
                Log.Info("Setup wizard opened " + (Program.StartedByInstaller ? "after the installation" : "with --wizard") + ", as " + Environment.UserDomainName + "\\" + Environment.UserName);
                await RunWizard();
                return;
            }
            if (Prefs.WizardOffered) return;
            Prefs.WizardOffered = true;
            if (MessageBox.Show(this, "Set up the SSH server now? A short wizard helps with the port and networks, a key for you, how accounts log in, and the recommended settings.\n\nYou can start it any time with \"Setup wizard...\" on the Dashboard.", Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes)
                await RunWizard();
        }

        /// <summary>
        /// Usable keys authorized for the account running this program, in every file sshd reads for it (Keys.UsableCount).
        /// Throws when that cannot be worked out, or when sshd reads no file (AuthorizedKeysFile none): no file is guessed.
        /// </summary>
        private static int MyKeyCount()
        {
            var files = Ssh.AuthorizedKeysFilesFor(KeyGen.LoginName(), Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));
            if (files.Count == 0) throw new ConfigException("sshd reads no authorized_keys file (AuthorizedKeysFile none).");
            return Keys.UsableCount(files);
        }

        private bool _wizardRunning;
        private async Task RunWizard()
        {
            // From the notification area menu, the wizard can be asked for while it (or another dialog) is open already.
            if (_wizardRunning || Application.OpenForms.Cast<Form>().Any(f => f != this && f.Modal)) { Status("Close the open dialog first"); return; }
            _wizardRunning = true;
            try
            {
                FirewallRule fw = null; ServerStateSnapshot state = null;
                await BgAsync("Reading the current settings...", () => { fw = Firewall.Find(); state = ServerState.Read(); });
                string err; var allow = _cfg.GetCombinedArgs("AllowGroups", out err);
                WizardPlan plan;
                using (var w = new SetupWizard(_cfg.EffectivePort, fw, allow == null || allow.Count == 0 ? null : SshdArgs.FormatTyped(allow), async () => await BgAsync("Reading your keys...", () => MyKeyCount()), QuickAddMyKey, CreateMyKey))
                {
                    w.UseServerState(state);
                    w.ChangesConfig = p => { try { return WizardCandidate(p).Text != _cfg.Text; } catch { return true; } };
                    if (w.ShowDialog(this) != DialogResult.OK) return;
                    plan = w.Plan;
                }
                await ApplyWizard(plan, fw, state);
            }
            finally { _wizardRunning = false; }
        }

        /// <summary>sshd_config as the wizard's plan writes it.</summary>
        private SshdConfig WizardCandidate(WizardPlan plan)
        {
            var cand = _cfg.Copy();
            if (plan.Port != _cfg.EffectivePort) cand.SetFirst("Port", plan.Port.ToString());
            if (plan.Login != WizardLogin.Keep)
            {
                var st = AuthConfig.Read(cand);
                if (plan.Login == WizardLogin.EveryoneKeyOnly)
                    AuthConfig.Apply(cand, new AuthMethods { Password = false, PublicKey = true, Kerberos = st.Global.Kerberos }, st.RulesProblem == null ? st.Rules : null);
                else
                {
                    if (st.RulesProblem != null) throw new ConfigException("The rules section of sshd_config was changed by hand (" + st.RulesProblem + "), so the wizard cannot add the rule for administrators. Correct it on the sshd_config (text) tab, or add the rule on the Authentication tab.");
                    string e;
                    var admins = Accounts.Canonical(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null).Translate(typeof(NTAccount)).Value, true, out e) ?? "administrators";
                    var rules = st.Rules.Where(r => !(r.IsGroup && r.Name == admins)).ToList();
                    rules.Insert(0, new AuthRule { IsGroup = true, Name = admins, Methods = new AuthMethods { Password = false, PublicKey = true } });
                    AuthConfig.Apply(cand, st.Global, rules);
                }
            }
            if (plan.Recommended)
            {
                cand.Set("ClientAliveInterval", "300"); cand.Set("ClientAliveCountMax", "3"); cand.Set("MaxAuthTries", "4"); cand.Set("LogLevel", "VERBOSE");
                cand.Set("LoginGraceTime", "60"); cand.Set("RequiredRSASize", "2048");
                cand.Set("KbdInteractiveAuthentication", "no"); cand.Set("ChallengeResponseAuthentication", "");
                if ((cand.Get("PerSourcePenalties") ?? "").Equals("no", StringComparison.OrdinalIgnoreCase)) cand.Set("PerSourcePenalties", "");
            }
            if (plan.AllowGroups != null) { string e; cand.Set("AllowGroups", plan.AllowGroups.Length == 0 ? "" : SshdArgs.Join(SshdArgs.ParseTyped(plan.AllowGroups, out e))); }
            return cand;
        }

        /// <summary>
        /// Applies the wizard's plan: one save of sshd_config (with the preview and your-access check), the firewall rule, one
        /// restart with the keep-or-restore question. shown: what sshd reported when the wizard opened (its summary).
        /// </summary>
        private async Task ApplyWizard(WizardPlan plan, FirewallRule fw, ServerStateSnapshot shown)
        {
            var cand = WizardCandidate(plan);
            bool portChanged = plan.Port != _cfg.EffectivePort;
            var fwProfiles = fw == null ? 0 : ((fw.Profiles & 0x7fffffff) == 0x7fffffff ? 7 : fw.Profiles & 7);
            var rulePorts = fw == null ? null : fw.Ports;
            string backup = null;
            bool configurationChanged = cand.Text != _cfg.Text;
            var changes = plan.Summary(_cfg.EffectivePort, fwProfiles, fw != null, fw != null && fw.Enabled, rulePorts, shown, configurationChanged);
            if (configurationChanged)
            {
                if (plan.Login != WizardLogin.Keep)
                {
                    // Key-only login with no key sshd can use locks you out of new SSH logins: asked as on the Authentication tab.
                    var lockout = await BgAsync("Checking that you can still log in with the new settings...", () =>
                    {
                        var tmp = WriteCandidate(cand);
                        try { return AuthConfig.LockoutWarning(tmp, cand.EffectivePort); } finally { try { File.Delete(tmp); } catch { } }
                    });
                    if (lockout != null && !Program.Unattended &&
                        MessageBox.Show(this, "Warning: " + lockout + "\n\nApply the setup wizard's settings anyway?", Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes)
                        throw new OperationCanceledException();
                }
                backup = await SaveConfig(cand, "Setup wizard: " + string.Join(" ", changes), "Apply");
                await UseConfig(cand);
            }
            // The rule must allow every port sshd uses, as sshd -T resolves them (Include files, ListenAddress ports) with
            // the running listeners, read after the save: the port field shows only the Port line of sshd_config.
            var state = await BgAsync("Resolving the server endpoints...", ServerState.Read);
            var adds = WizardPlan.FirewallAdds(rulePorts, plan.Port, portChanged, state.Verified ? state.Ports : null);
            Action undo = null; Func<Task> apply = null, keep = null; string fwNote = null;
            if (fw == null || fwProfiles != plan.Profiles || fw.Enabled != plan.FirewallEnabled || adds.Count > 0)
            {
                // Ports are only added while you decide, so the server stays reachable, and the rule comes back with the old
                // file. A rule the wizard creates, or one that had one port, keeps the ports sshd then uses once the new
                // settings are kept; without verified ports, nothing is taken away.
                var before = fw;
                var added = string.Join(",", adds);
                var pending = fw == null ? added : adds.Count == 0 ? fw.Ports : fw.Ports + "," + added;
                apply = async () => { await BgAsync("Applying the firewall plan...", () => Firewall.Apply(plan.FirewallEnabled, plan.Profiles, pending)); await LoadFirewall(); };
                undo = () => { if (before == null) Firewall.Remove(); else Firewall.Apply(before.Enabled, before.Profiles, before.Ports); };
                if (WizardPlan.FirewallNarrows(fw != null, rulePorts, configurationChanged, state.Verified, adds.Count))
                    keep = async () =>
                    {
                        // Never throws: a keep that fails leaves the recovery armed, which would then restore the settings just kept.
                        try
                        {
                            var running = await BgAsync("Verifying the running listeners...", ServerState.Read);
                            if (!running.Verified) { fwNote = "; the firewall rule keeps ports " + pending + " because the running listeners could not be verified"; Log.Info("Firewall rule left at " + pending + ": " + running.Error); return; }
                            await BgAsync("Keeping the firewall plan...", () => Firewall.Apply(plan.FirewallEnabled, plan.Profiles, running.FirewallPorts));
                            await LoadFirewall();
                            Log.Info("Firewall rule kept ports " + running.FirewallPorts);
                        }
                        catch (Exception ex) { fwNote = "; the firewall rule keeps ports " + pending + ": " + ex.Message; Log.Error("Keeping the firewall plan", ex, false); }
                    };
            }
            if (configurationChanged) await RestartWithRollback(backup, undo, apply, keep);
            else if (apply != null) await apply();
            await RefreshDashboard();
            Status("Setup wizard applied" + fwNote);
        }

        // ---------------- About ----------------
        private bool _aboutLoaded;
        private Action<string, string> _setAboutVersions;

        private async Task LoadAboutVersions()
        {
            var versions = await BgAsync("Reading OpenSSH versions...", () => new[]
                { _clientOnly ? "Not checked in the client workspace" : Ssh.ServerVersion(), Ssh.ClientBanner() });
            _setAboutVersions(versions[0], versions[1]);
            _aboutLoaded = true;
        }

        private TabPage BuildAbout()
        {
            var page = new TabPage("About");
            var flow = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown, WrapContents = false, Padding = new Padding(12) };
            var header = new FlowLayoutPanel { FlowDirection = FlowDirection.LeftToRight, AutoSize = true, WrapContents = false, Margin = new Padding(0) };
            if (Ui.AppIcon != null)
            {
                // The icon at the size of this display (the .ico has 64, 96 and 128 px images).
                using (var sized = new Icon(Ui.AppIcon, Ui.Px(64), Ui.Px(64)))
                    header.Controls.Add(new PictureBox { Image = sized.ToBitmap(), SizeMode = PictureBoxSizeMode.Zoom, Size = new Size(Ui.Px(64), Ui.Px(64)), Margin = new Padding(4, 4, 12, 4), AccessibleName = "Program icon" });
            }
            var title = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, AutoSize = true, WrapContents = false, Margin = new Padding(0, Ui.Px(8), 0, 0) };
            title.Controls.Add(new Label { Text = Program.AppName, AutoSize = true, Font = new Font(Font.FontFamily, Ui.Pt(14f), FontStyle.Bold), Margin = new Padding(4, 0, 4, 0) });
            title.Controls.Add(new Label { Text = "Version " + Program.AppVersion + "  ·  " + Program.Copyright, AutoSize = true, ForeColor = Theme.Muted, Margin = new Padding(6, 2, 4, 4) });
            header.Controls.Add(title);
            flow.Controls.Add(header);
            flow.Controls.Add(new Label { AutoSize = true, MaximumSize = new Size(Ui.Px(820), 0), Margin = new Padding(4, 8, 4, 8), Text = "The management console of OpenSSH Server PN, the OpenSSH server and client for Windows: service control, configuration editing that is validated, backed up and rolled back on failure, login methods, SFTP with transfer logging and SFTP-only accounts, authorized and host keys, the Windows Firewall rule, the event log and a hardening check. It also manages the official Microsoft packages and the OpenSSH feature of Windows." });
            // The same lines as text, for "Copy details" (what a support request needs).
            var details = new List<Label>();
            Func<string, string, Label> line = (k, v) =>
            {
                var label = new Label { AutoSize = true, Text = k.PadRight(22) + v, Font = new Font("Consolas", Ui.Pt(9.5f)), Margin = new Padding(4, 1, 4, 1) };
                details.Add(label); flow.Controls.Add(label); return label;
            };
            line("Product:", Program.AppName + " " + Program.AppVersion); line("Publisher:", Program.Publisher); line("Licence:", "BSD-style, as OpenSSH (LICENSE.txt in the install folder)");
            line("Install folder:", Ssh.InstallDir); line("Configuration:", Ssh.ConfigPath);
            var serverVersion = line("Server version:", "Loading when opened...");
            var clientVersion = line("Client banner:", "Loading when opened...");
            _setAboutVersions = (server, client) => { serverVersion.Text = "Server version:".PadRight(22) + server; clientVersion.Text = "Client banner:".PadRight(22) + client; };
            line("Manager log:", Log.Path); line("Self-check:", "OpenSSHServerPNManager.exe --check [report.txt]"); line("OS:", Environment.OSVersion.VersionString + (Environment.Is64BitOperatingSystem ? " x64" : " x86")); line(".NET runtime:", Environment.Version.ToString());
            Action<string, string, string> link = (text, url, margin) =>
            {
                var l = new LinkLabel { Text = text + "  " + url, AutoSize = true, Margin = margin == "first" ? new Padding(4, 12, 4, 2) : new Padding(4, 2, 4, 2), AccessibleName = text };
                l.LinkArea = new LinkArea(text.Length + 2, url.Length);
                l.LinkClicked += (s, e) => Proc.OpenExternal(url);
                flow.Controls.Add(l);
            };
            link("Website and documentation:", Program.Website, "first");
            link("Updates:", Program.ReleasesUrl, null);
            link("Support and problem reports:", Program.SupportUrl, null);
            var buttons = Flow(); buttons.Dock = DockStyle.None; buttons.Padding = new Padding(0); buttons.WrapContents = false;
            buttons.Controls.Add(Btn("Open manager log", (s, e) => Proc.OpenExternal("notepad.exe", "\"" + Log.Path + "\""), 150));
            buttons.Controls.Add(Btn("Copy details", (s, e) => Safe(() => { Clipboard.SetText(string.Join(Environment.NewLine, details.Select(label => label.Text)) + Environment.NewLine); Status("Details copied: paste them into a support request"); }), 130));
            _tips.SetToolTip(buttons.Controls[1], "Copies the version, paths and system above, for a problem report.");
            flow.Controls.Add(buttons);

            // Preferences of this account (HKCU\Software\OpenSSH Server PN Manager).
            flow.Controls.Add(Lbl("Preferences", true));
            var themeRow = Flow(); themeRow.Dock = DockStyle.None; themeRow.Padding = new Padding(0);
            themeRow.Controls.Add(Lbl("Appearance:"));
            var theme = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = Ui.Px(200), Margin = new Padding(4, 6, 4, 4), AccessibleName = "Appearance" };
            theme.Items.AddRange(new object[] { "Like Windows", "Light", "Dark" });
            theme.SelectedIndex = Prefs.Theme == "light" ? 1 : Prefs.Theme == "dark" ? 2 : 0;
            theme.SelectedIndexChanged += (s, e) => Safe(() => { Prefs.Theme = theme.SelectedIndex == 1 ? "light" : theme.SelectedIndex == 2 ? "dark" : "system"; ApplyTheme(); });
            themeRow.Controls.Add(theme);
            if (SystemInformation.HighContrast) themeRow.Controls.Add(new Label { AutoSize = true, ForeColor = Theme.Muted, Margin = new Padding(8, 10, 4, 4), Text = "High contrast is on: its colours are used." });
            flow.Controls.Add(themeRow);
            Func<string, bool, Action<bool>, CheckBox> pref = (text, value, set) =>
            {
                var c = new CheckBox { Text = text, AutoSize = true, Checked = value, Margin = new Padding(4, 3, 4, 3), MaximumSize = new Size(Ui.Px(900), 0) };
                c.CheckedChanged += (s, e) => set(c.Checked);
                flow.Controls.Add(c); return c;
            };
            if (!_clientOnly)
            {
            pref("Show the changes to sshd_config before every save", Prefs.PreviewChanges, v => Prefs.PreviewChanges = v);
            pref("After a restart with new settings, ask to keep them; restore the previous settings after " + Prefs.ConfirmSeconds + " s without an answer", Prefs.ConfirmAfterRestart, v => Prefs.ConfirmAfterRestart = v);
            pref("Icon in the notification area, with a notification when sshd stops or logins fail repeatedly", Prefs.TrayIcon, v => { Prefs.TrayIcon = v; if (v) InitTray(); else StopWatchers(); });
            pref("Minimize to the notification area", Prefs.MinimizeToTray, v => Prefs.MinimizeToTray = v);
            var failRow = Flow(); failRow.Dock = DockStyle.None; failRow.Padding = new Padding(0);
            failRow.Controls.Add(Lbl("Notify after"));
            var failN = new NumericUpDown { Minimum = 0, Maximum = 10000, Width = Ui.Px(70), Margin = new Padding(4, 6, 4, 4), AccessibleName = "Failed logins before a notification (0 = never)" };
            SetClamped(failN, Prefs.FailedLoginThreshold);
            failN.ValueChanged += (s, e) => Prefs.FailedLoginThreshold = (int)failN.Value;
            failRow.Controls.Add(failN);
            failRow.Controls.Add(Lbl("failed logins within"));
            var failM = new NumericUpDown { Minimum = 1, Maximum = 1440, Width = Ui.Px(70), Margin = new Padding(4, 6, 4, 4), AccessibleName = "Minutes for counting failed logins" };
            SetClamped(failM, Prefs.FailedLoginMinutes);
            failM.ValueChanged += (s, e) => Prefs.FailedLoginMinutes = (int)failM.Value;
            failRow.Controls.Add(failM);
            failRow.Controls.Add(Lbl("minute(s) (0 = never)"));
            flow.Controls.Add(failRow);
            }
            flow.Controls.Add(new Label { AutoSize = true, ForeColor = Theme.Muted, MaximumSize = new Size(Ui.Px(900), 0), Margin = new Padding(4, 6, 4, 4), Text = "Keyboard: Ctrl+S saves the tab shown, F5 refreshes it, Ctrl+1 to Ctrl+9 open the tabs, Ctrl+F finds in the sshd_config text, Enter opens the selected item of a list, Delete removes it." });
            page.Controls.Add(flow);
            flow.AutoScroll = true;
            FitRows(flow);
            return page;
        }

        /// <summary>Switches the colours of the window to the preference (light, dark, like Windows); high contrast always wins.</summary>
        private void ApplyTheme()
        {
            var previous = Theme.Current;
            Theme.Current = Theme.For(Prefs.Theme);
            Theme.Apply(this, previous);
            // List rows coloured by state take the new colours the next time they are filled.
            if (_lvChecks != null) _lvChecks.Items.Clear();
            Invalidate(true);
        }
    }
}

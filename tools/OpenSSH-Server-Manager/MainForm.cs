// OpenSSH Server Manager for Windows: MainForm

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

        private static Icon _appIcon; private static bool _appIconRead;
        /// <summary>The program icon with all its sizes (app.ico, embedded by build.ps1), or null in a build without it.</summary>
        public static Icon AppIcon
        {
            get
            {
                if (_appIconRead) return _appIcon;
                _appIconRead = true;
                try { using (var s = typeof(Ui).Assembly.GetManifestResourceStream("OpenSSHServerManager.app.ico")) if (s != null) _appIcon = new Icon(s); }
                catch (Exception ex) { Log.Error("Program icon", ex, false); }
                return _appIcon;
            }
        }
    }

    // ------------------------------------------------------------------------------------------
    // Main window
    // ------------------------------------------------------------------------------------------
    internal sealed class MainForm : Form
    {
        private readonly TabControl _tabs = new TabControl();
        private readonly StatusStrip _status = new StatusStrip();
        private readonly ToolStripStatusLabel _statusText = new ToolStripStatusLabel("Ready");
        private readonly ToolStripProgressBar _busy = new ToolStripProgressBar { Style = ProgressBarStyle.Marquee, Visible = false, Width = Ui.Px(90) };
        private readonly ToolTip _tips = new ToolTip { AutoPopDelay = 20000, InitialDelay = 400, ReshowDelay = 200 };
        private readonly System.Windows.Forms.Timer _timer = new System.Windows.Forms.Timer { Interval = 5000 };

        // dashboard
        private Label _lblSshd, _lblAgent, _lblVersion, _lblListen, _lblSessions, _lblFirewall, _lblConfig;
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
        private bool _loadingSettings;
        private TabPage _pgSettings, _pgAuth, _pgRaw;
        private Label _setPending, _rawPending;
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

        private static readonly Color Green = Color.FromArgb(0, 128, 0), Red = Color.FromArgb(192, 0, 0), Orange = Color.FromArgb(200, 110, 0);

        public MainForm()
        {
            Text = Program.AppName + " " + Program.AppVersion + "  -  " + Ssh.InstallDir;
            Font = new Font("Segoe UI", Ui.Pt(9.5f));
            AutoScaleMode = AutoScaleMode.Font;
            StartPosition = FormStartPosition.CenterScreen;
            MinimumSize = new Size(Ui.Px(900), Ui.Px(640));
            Size = new Size(Ui.Px(1040), Ui.Px(720));
            if (Ui.AppIcon != null) Icon = Ui.AppIcon;
            else { try { Icon = Icon.ExtractAssociatedIcon(Ssh.Exe("sshd.exe")); } catch { } }

            _tabs.Dock = DockStyle.Fill;
            _tabs.TabPages.Add(BuildDashboard());
            _tabs.TabPages.Add(BuildSessions());
            _tabs.TabPages.Add(_pgSettings = BuildSettings());
            _tabs.TabPages.Add(_pgAuth = BuildAuthentication());
            _tabs.TabPages.Add(_pgRaw = BuildRawEditor());
            _tabs.TabPages.Add(BuildKeys());
            _tabs.TabPages.Add(BuildKeyGen());
            _tabs.TabPages.Add(BuildFirewall());
            _tabs.TabPages.Add(BuildLogs());
            _tabs.TabPages.Add(BuildHardening());
            _tabs.TabPages.Add(BuildAbout());
            _tabs.SelectedIndexChanged += (s, e) => Safe(() => OnTabSelected());

            _status.Items.Add(_statusText); _status.Items.Add(_busy);
            Controls.Add(_tabs); Controls.Add(_status);

            _timer.Tick += (s, e) =>
            {
                if (_tabs.SelectedTab == null) return;
                // In the background: service, network, firewall and process queries can take seconds, and the
                // window must stay responsive meanwhile.
                if (_tabs.SelectedTab.Text == "Dashboard") RefreshInBackground(CollectDashboard, ShowDashboard);
                else if (_tabs.SelectedTab.Text == "Sessions") RefreshInBackground(CollectSessions, ShowSessions);
            };
            Shown += (s, e) => { Safe(LoadEverything); _timer.Start(); };
            FormClosing += (s, e) =>
            {
                if (!Program.Unattended && e.CloseReason == CloseReason.UserClosing)
                {
                    var unsaved = UnsavedTabs();
                    if (unsaved.Count > 0 && MessageBox.Show(this, "Changes on " + string.Join(" and ", unsaved) + " are not saved.\n\nClose anyway and lose them?", Program.AppName,
                            MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes) { e.Cancel = true; return; }
                }
                _timer.Stop();
            };
        }

        // ---------------- test hooks (used by --screenshot) ----------------
        public int TabCount { get { return _tabs.TabPages.Count; } }
        public string TabName(int i) { return _tabs.TabPages[i].Text; }
        public void SelectTabForTest(int i) { _tabs.SelectedIndex = i; Safe(() => OnTabSelected(), false); }
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

        // ---------------- test hooks (used by --selftest, with Ssh.ConfigDirOverride) ----------------
        public void SetSettingForTest(string key, string value)
        {
            var c = _fields[key];
            if (c is ComboBox) { var cb = (ComboBox)c; cb.SelectedIndex = Math.Max(0, cb.Items.IndexOf(value)); } else ((TextBox)c).Text = value;
        }
        /// <summary>Save on the Settings tab; the error message, or null when it saved.</summary>
        public string SaveSettingsForTest() { try { SaveSettings(false); return null; } catch (ConfigException ex) { return ex.Message; } }
        public void ReloadFromFileForTest() { ReloadFromFile(); }
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
        public void OtherTabSavedForTest() { UseConfig(SshdConfig.Load()); }
        /// <summary>Text boxes, lists and the like without a name for screen readers.</summary>
        public List<string> UnnamedInputsForTest()
        {
            return _tabs.TabPages.Cast<TabPage>().SelectMany(p => Descendants(p).Where(c => (c is TextBoxBase || c is ComboBox || c is NumericUpDown || c is ListView) && !(c.Parent is UpDownBase) && string.IsNullOrEmpty(c.AccessibleName))
                .Select(c => p.Text + ": " + c.GetType().Name)).ToList();
        }
        /// <summary>Time on the window's thread: a refresh done there, and starting one in the background (which is then awaited).</summary>
        public TimeSpan[] BackgroundRefreshForTest()
        {
            var sw = Stopwatch.StartNew(); RefreshDashboard(); var direct = sw.Elapsed;
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
        /// <summary>A value of the configuration every tab works on (what the next save of any tab starts from).</summary>
        public string WorkingValueForTest(string key) { return _cfg.Get(key); }
        /// <summary>sshd_config as Apply on the Authentication tab would write it.</summary>
        public SshdConfig AuthCandidateForTest() { return AuthCandidate(); }

        /// <summary>
        /// Text that does not fit, on every tab: a button narrower than its text, a control wider than its table column
        /// (it runs into the next one), or a control that runs past the right edge of its row.
        /// </summary>
        public List<string> ClippedTextForTest()
        {
            var found = new List<string>();
            for (int i = 0; i < _tabs.TabPages.Count; i++)
            {
                _tabs.SelectedIndex = i; Application.DoEvents();
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
            _tabs.SelectedIndex = 0;
            return found;
        }

        private static IEnumerable<Control> Descendants(Control root)
        {
            foreach (Control c in root.Controls) { yield return c; foreach (var d in Descendants(c)) yield return d; }
        }

        // ---------------- helpers ----------------
        private void Safe(Action a, bool show = true)
        {
            try { a(); }
            catch (ConfigException ex)
            {
                Log.Info("Configuration rejected: " + ex.Message);
                if (!Program.Unattended) MessageBox.Show(this, ex.Message, Program.AppName, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                Status("Not saved: configuration rejected");
            }
            catch (Exception ex) { Log.Error("Operation failed", ex, show); Status("Error: " + ex.Message); }
        }

        private void Busy(string text, Action work)
        {
            // The refresh timer must not run a second operation (e.g. a dashboard refresh while a dialog inside
            // 'work' pumps messages) until this one has finished.
            bool timerWasRunning = _timer.Enabled; _timer.Stop();
            _busy.Visible = true; Status(text); UseWaitCursor = true; Enabled = false;
            try { Application.DoEvents(); work(); }
            finally { Enabled = true; UseWaitCursor = false; _busy.Visible = false; if (timerWasRunning && !IsDisposed) _timer.Start(); }
        }

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
        private static ListView Lv(params string[] cols)
        {
            var lv = new ListView { View = View.Details, FullRowSelect = true, GridLines = true, Dock = DockStyle.Fill, HideSelection = false, MultiSelect = false };
            foreach (var c in cols) { var parts = c.Split('|'); lv.Columns.Add(parts[0], Ui.Px(parts.Length > 1 ? int.Parse(parts[1]) : 150)); }
            return lv;
        }

        private void LoadEverything()
        {
            Busy("Loading...", () =>
            {
                _cfg = SshdConfig.Load();
                RefreshDashboard();
                LoadSettings();
                LoadAuth();
                LoadRaw();
                LoadKeys();
                LoadFirewall();
            });
            Status("Ready. Configuration: " + Ssh.ConfigPath);
        }

        private void OnTabSelected()
        {
            var tab = _tabs.SelectedTab;
            if (tab == null) return;
            switch (tab.Text)
            {
                case "Dashboard": RefreshDashboard(); break;
                case "Sessions": RefreshSessions(); break;
                case "Logs": if (_lvEvents.Items.Count == 0) LoadLogs(); break;
                case "Hardening": if (_lvChecks.Items.Count == 0) RunChecks(); break;
            }
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
            _lblSessions = row("Active sessions"); _lblFirewall = row("Firewall rule"); _lblConfig = row("Configuration");
            root.Controls.Add(grid, 0, 0);

            var actions = Flow();
            _btnStart = Btn("Start", (s, e) => ServiceAction("start"));
            _btnStop = Btn("Stop", (s, e) => ServiceAction("stop"));
            _btnRestart = Btn("Restart", (s, e) => ServiceAction("restart"));
            actions.Controls.Add(_btnStart); actions.Controls.Add(_btnStop); actions.Controls.Add(_btnRestart);
            actions.Controls.Add(Btn("Test configuration", (s, e) => Safe(TestLiveConfig), 150));
            actions.Controls.Add(Btn("Refresh", (s, e) => Safe(RefreshDashboard), 100));
            actions.Controls.Add(Btn("Open config folder", (s, e) => Proc.OpenExternal("explorer.exe", "\"" + Ssh.ConfigDir + "\""), 150));
            actions.Controls.Add(Btn("Event Viewer", (s, e) => Proc.OpenExternal("eventvwr.exe", "/c:\"" + EventLogs.LogName + "\""), 120));
            actions.Controls.Add(Btn("Add my public key", (s, e) => Safe(QuickAddMyKey), 150));
            actions.Controls.Add(Btn("Generate missing host keys", (s, e) => Safe(GenerateHostKeys), 200));
            actions.Controls.Add(Btn("Connect (ssh localhost)", (s, e) => Proc.OpenExternal(Ssh.Exe("ssh.exe"), "-p " + (_cfg == null ? 22 : _cfg.EffectivePort) + " localhost"), 170));
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
        }

        private DashboardData CollectDashboard(SshdConfig cfg)
        {
            var d = new DashboardData { Sshd = Services.Status("sshd"), Agent = Services.Status("ssh-agent"), Version = Ssh.ServerVersion(), Port = cfg.EffectivePort };
            d.Listeners = Net.Listeners(d.Port); d.Sessions = Net.Sessions(d.Port);
            d.Firewall = Firewall.Get();
            d.ConfigExists = File.Exists(Ssh.ConfigPath); d.RestartPending = Services.ChangedSinceStart(d.Sshd, Ssh.ConfigPath);
            d.HostKeys = HostKeys.List();
            return d;
        }

        private void RefreshDashboard()
        {
            if (_cfg == null) _cfg = SshdConfig.Load();
            ShowDashboard(CollectDashboard(_cfg));
        }

        private void ShowDashboard(DashboardData d)
        {
            var sshd = d.Sshd; var agent = d.Agent;
            _lblSshd.Text = sshd.Status + (sshd.Pid > 0 ? "  (PID " + sshd.Pid + ")" : "") + "   start: " + sshd.StartMode;
            _lblSshd.ForeColor = sshd.Status == "Running" ? Green : Red;
            _lblAgent.Text = agent.Status + "   start: " + agent.StartMode; _lblAgent.ForeColor = agent.Status == "Running" ? Green : Orange;
            _lblVersion.Text = d.Version;
            _lblListen.Text = d.Listeners.Count > 0 ? string.Join("   ", d.Listeners) : "nothing listening on port " + d.Port; _lblListen.ForeColor = d.Listeners.Count > 0 ? Green : Red;
            _lblSessions.Text = d.Sessions.Count + (d.Sessions.Count > 0 ? "   from " + string.Join(", ", d.Sessions.Take(6)) + (d.Sessions.Count > 6 ? " ..." : "") : "");
            var fw = d.Firewall;
            _lblFirewall.Text = fw == null ? "missing" : (fw.Enabled ? "enabled" : "DISABLED") + "   profiles: " + fw.ProfilesText + "   port: " + fw.Ports;
            _lblFirewall.ForeColor = fw != null && fw.Enabled ? Green : Red;
            _lblConfig.Text = Ssh.ConfigPath + (!d.ConfigExists ? "  (not created yet; sshd copies sshd_config_default on first start)"
                            : d.RestartPending ? "   saved after sshd started: restart sshd to apply the changes" : "");
            _lblConfig.ForeColor = d.RestartPending ? Orange : ForeColor;
            _btnStart.Enabled = sshd.Exists && sshd.Status != "Running"; _btnStop.Enabled = sshd.Status == "Running"; _btnRestart.Enabled = sshd.Status == "Running";
            // Rebuilt only when the keys changed, so a selected row stays selected.
            var rows = d.HostKeys.Select(k => new[] { k.File, k.Type, k.Bits ?? "", k.Fingerprint ?? "" }).ToList();
            var shown = _lvHostKeys.Items.Cast<ListViewItem>().Select(i => i.SubItems.Cast<ListViewItem.ListViewSubItem>().Select(s => s.Text).ToArray()).ToList();
            if (rows.Count != shown.Count || rows.Where((r, i) => !r.SequenceEqual(shown[i])).Any())
            {
                _lvHostKeys.BeginUpdate(); _lvHostKeys.Items.Clear();
                foreach (var r in rows) _lvHostKeys.Items.Add(new ListViewItem(r));
                _lvHostKeys.EndUpdate();
            }
        }

        private bool _refreshRunning; private DateTime _refreshStarted;
        /// <summary>
        /// Collects on a background thread (STA, for the COM objects of the firewall API) and shows the result on the
        /// window's thread. At most one runs at a time; a timer tick while one runs is skipped. One that has not finished
        /// after a minute is given up, so that a hung query does not stop the refresh for good. Returns false when one
        /// was already running.
        /// </summary>
        private bool RefreshInBackground<T>(Func<SshdConfig, T> collect, Action<T> show)
        {
            if (_refreshRunning && DateTime.UtcNow - _refreshStarted > TimeSpan.FromMinutes(1)) { Log.Info("Background refresh gave up after a minute"); _refreshRunning = false; }
            if (_refreshRunning || _cfg == null || IsDisposed) return false;
            _refreshRunning = true; _refreshStarted = DateTime.UtcNow;
            var cfg = _cfg;
            var worker = new Thread(() =>
            {
                T data = default(T); Exception error = null;
                try { data = collect(cfg); } catch (Exception ex) { error = ex; }
                try
                {
                    BeginInvoke((Action)(() =>
                    {
                        _refreshRunning = false;
                        if (error != null) { Log.Error("Refresh", error, false); return; }
                        if (Enabled) Safe(() => show(data), false); // not while an operation (Busy) runs
                    }));
                }
                catch (InvalidOperationException) { } // the window was closed meanwhile
            }) { IsBackground = true, Name = "refresh" };
            worker.SetApartmentState(ApartmentState.STA);
            worker.Start();
            return true;
        }

        private void ServiceAction(string action)
        {
            Safe(() =>
            {
                if (action == "stop" && MessageBox.Show(this, "Stop the SSH server? New connections are refused until it starts again.\n\nConnected sessions stay connected; end them on the Sessions tab if needed.", Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
                Busy((action == "stop" ? "Stopping" : action == "start" ? "Starting" : "Restarting") + " sshd...", () =>
                {
                    switch (action)
                    {
                        case "start": Services.Start("sshd"); break;
                        case "stop": Services.Stop("sshd"); break;
                        case "restart": Services.Restart("sshd"); break;
                    }
                    Thread.Sleep(800);
                    RefreshDashboard();
                });
                Status("sshd " + action + " completed");
            });
        }

        private void TestLiveConfig()
        {
            var r = Ssh.TestConfig(null);
            MessageBox.Show(this, r.Ok ? "sshd -t reports no problems with\n" + Ssh.ConfigPath : "sshd -t reported:\n\n" + r.Output, Program.AppName, MessageBoxButtons.OK, r.Ok ? MessageBoxIcon.Information : MessageBoxIcon.Warning);
        }

        private void GenerateHostKeys()
        {
            Busy("Generating host keys...", () => { var o = HostKeys.GenerateMissing(); RefreshDashboard(); Status("ssh-keygen -A: " + (o.Length == 0 ? "done" : o)); });
        }

        private void QuickAddMyKey()
        {
            using (var dlg = new OpenFileDialog { Title = "Choose your public key (*.pub)", Filter = "Public keys (*.pub)|*.pub|All files|*.*", InitialDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".ssh") })
            {
                if (dlg.ShowDialog(this) != DialogResult.OK) return;
                var line = File.ReadAllText(dlg.FileName).Trim();
                if (!Keys.LooksLikePublicKey(line) || line.IndexOf("PRIVATE KEY", StringComparison.OrdinalIgnoreCase) >= 0) throw new ConfigException("The file does not contain an OpenSSH public key. Choose the .pub file, never the private key.");
                bool already;
                var target = KeyGen.AuthorizeForCurrentUser(line, out already); // the file sshd reads for this account (sshd -T -C)
                LoadKeys();
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
            bar.Controls.Add(Btn("Refresh", (s, e) => Safe(RefreshSessions), 100));
            bar.Controls.Add(Btn("Disconnect selected", (s, e) => Safe(() => DisconnectSessions(false)), 160));
            bar.Controls.Add(Btn("Disconnect all", (s, e) => Safe(() => DisconnectSessions(true)), 130));
            bar.Controls.Add(new Label { AutoSize = true, Margin = new Padding(12, 10, 4, 4), ForeColor = Color.DimGray, Text = "Each connection runs as an sshd-session.exe process: one owned by SYSTEM before login, then one owned by the user. Refreshes every 5 seconds." });
            root.Controls.Add(bar, 0, 1);
            var split = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal };
            bool splitInit = false;
            split.SizeChanged += (s, e) => { if (splitInit || split.Height < Ui.Px(300)) return; splitInit = true; try { split.SplitterDistance = split.Height * 62 / 100; } catch { } };
            var sessBox = new GroupBox { Text = "Session processes (sshd-session.exe)", Dock = DockStyle.Fill, Padding = new Padding(6) };
            _lvSessions = Lv("PID|80", "User|260", "Started|160", "Duration|100", "Role|200"); _lvSessions.AccessibleName = "Session processes";
            sessBox.Controls.Add(_lvSessions); split.Panel1.Controls.Add(sessBox);
            var connBox = new GroupBox { Text = "Established TCP connections on the server port (peer address, owning process)", Dock = DockStyle.Fill, Padding = new Padding(6) };
            _lvConnections = Lv("Peer|260", "Owning process|260"); _lvConnections.AccessibleName = "Established connections";
            connBox.Controls.Add(_lvConnections); split.Panel2.Controls.Add(connBox);
            root.Controls.Add(split, 0, 2);
            page.Controls.Add(root);
            return page;
        }

        private ListView _lvConnections;

        private sealed class SessionsData { public int Port; public List<SessionInfo> List; public List<string[]> Connections; }

        private SessionsData CollectSessions(SshdConfig cfg)
        {
            int port = cfg.EffectivePort;
            return new SessionsData { Port = port, List = Sessions.List(port), Connections = Sessions.Connections(port) };
        }

        private void RefreshSessions()
        {
            if (_cfg == null) _cfg = SshdConfig.Load();
            ShowSessions(CollectSessions(_cfg));
        }

        private void ShowSessions(SessionsData data)
        {
            var list = data.List;
            var selected = _lvSessions.SelectedItems.Count > 0 ? (int)_lvSessions.SelectedItems[0].Tag : -1;
            _lvSessions.BeginUpdate(); _lvSessions.Items.Clear();
            foreach (var s in list)
            {
                bool system = s.User.IndexOf("SYSTEM", StringComparison.OrdinalIgnoreCase) >= 0;
                var ts = s.Start == DateTime.MinValue ? TimeSpan.Zero : DateTime.Now - s.Start;
                if (ts < TimeSpan.Zero) ts = TimeSpan.Zero;
                var dur = s.Start == DateTime.MinValue ? "" : ((int)ts.TotalHours).ToString("00") + ":" + ts.Minutes.ToString("00") + ":" + ts.Seconds.ToString("00");
                var it = new ListViewItem(new[] { s.Pid == 0 ? "" : s.Pid.ToString(), s.User, s.Start == DateTime.MinValue ? "" : s.Start.ToString("yyyy-MM-dd HH:mm:ss"), dur, s.Pid == 0 ? "" : (system ? "privileged monitor (pre-login or supervisor)" : "user session") }) { Tag = s.Pid };
                if (system) it.ForeColor = Color.Gray;
                if (s.Pid == selected) it.Selected = true;
                _lvSessions.Items.Add(it);
            }
            _lvSessions.EndUpdate();
            var conns = data.Connections;
            _lvConnections.BeginUpdate(); _lvConnections.Items.Clear();
            foreach (var c in conns) _lvConnections.Items.Add(new ListViewItem(c));
            _lvConnections.EndUpdate();
            int users = list.Count(x => x.Pid != 0 && x.User.IndexOf("SYSTEM", StringComparison.OrdinalIgnoreCase) < 0);
            _lblSessionSummary.Text = users + " user session(s), " + list.Count(x => x.Pid != 0) + " sshd-session process(es), " + conns.Count + " established connection(s) on port " + data.Port;
        }

        private void DisconnectSessions(bool all)
        {
            var targets = all ? _lvSessions.Items.Cast<ListViewItem>().ToList() : _lvSessions.SelectedItems.Cast<ListViewItem>().ToList();
            targets = targets.Where(i => (int)i.Tag != 0).ToList();
            if (targets.Count == 0) { Status("Select a session first"); return; }
            var who = string.Join("\n", targets.Select(i => "PID " + i.SubItems[0].Text + "  " + i.SubItems[1].Text + "  " + i.SubItems[4].Text));
            if (MessageBox.Show(this, "Disconnect " + targets.Count + " session(s)?\n\n" + who, Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;
            int ok = 0;
            foreach (var t in targets) { try { Sessions.Disconnect((int)t.Tag); ok++; } catch (Exception ex) { Log.Error("Disconnect PID " + t.Tag, ex, false); } }
            Thread.Sleep(500); RefreshSessions();
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
            var authHint = new Label { AutoSize = true, ForeColor = Color.DimGray, Margin = new Padding(4, 0, 4, 6), Text = "Login methods (Windows authentication, public key, Kerberos; rules per user and group) are set on the Authentication tab." };
            grid.Controls.Add(authHint); grid.SetColumnSpan(authHint, 3);
            foreach (var f in FieldDefs)
            {
                var lbl = Lbl(f.Label); grid.Controls.Add(lbl);
                Control c;
                if (f.Choices != null) { var cb = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = Ui.Px(160) }; cb.Items.AddRange(f.Choices.Select(x => (object)(x == "" ? "(default)" : x)).ToArray()); c = cb; }
                else { c = new TextBox { Width = Ui.Px(f.Wide ? 410 : 200) }; }
                c.Margin = new Padding(4); grid.Controls.Add(c);
                var hint = new Label { AutoSize = true, ForeColor = Color.Gray, Margin = new Padding(4, 8, 4, 4) }; grid.Controls.Add(hint);
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
            var shellHint = new Label { AutoSize = true, ForeColor = Color.Gray, Margin = new Padding(4, 8, 4, 4), Text = "registry HKLM\\SOFTWARE\\OpenSSH\\DefaultShell; empty = cmd.exe" }; grid.Controls.Add(shellHint);
            grid.Controls.Add(Lbl("Shell command option"));
            _txtShellOption = new TextBox { Width = Ui.Px(200), Margin = new Padding(4) }; grid.Controls.Add(_txtShellOption);
            var optHint = new Label { AutoSize = true, ForeColor = Color.Gray, Margin = new Padding(4, 8, 4, 4), Text = "e.g. /c for cmd-like shells, -c for bash; empty = automatic" }; grid.Controls.Add(optHint);
            _tips.SetToolTip(_cmbShell, "Shell started for interactive sessions and remote commands. Applies immediately to new sessions; no restart needed.");
            _txtPwshPath.AccessibleName = "PowerShell subsystem command"; _cmbShell.AccessibleName = "Default shell"; _txtShellOption.AccessibleName = "Shell command option";
            EventHandler other = (s, e) => { if (!_loadingSettings) UpdatePending(); };
            _chkPwshSubsystem.CheckedChanged += other; _txtPwshPath.TextChanged += other; _cmbShell.TextChanged += other; _txtShellOption.TextChanged += other;

            scroll.Controls.Add(grid);
            root.Controls.Add(scroll, 0, 0);

            var bar = Flow();
            bar.Controls.Add(Btn("Save", (s, e) => Safe(() => SaveSettings(false)), 110));
            bar.Controls.Add(Btn("Save and restart sshd", (s, e) => Safe(() => SaveSettings(true)), 180));
            bar.Controls.Add(Btn("Reload from file", (s, e) => Safe(() => ReloadFromFile(true, false)), 140));
            bar.Controls.Add(Btn("Restore a backup...", (s, e) => Safe(RestoreBackup), 150));
            bar.Controls.Add(Btn("Reset to shipped defaults", (s, e) => Safe(ResetToDefault), 190));
            _setPending = new Label { AutoSize = true, Margin = new Padding(12, 10, 4, 4), ForeColor = Orange };
            bar.Controls.Add(_setPending);
            var note = new Label { AutoSize = true, Margin = new Padding(12, 10, 4, 4), ForeColor = Color.DimGray, Text = "Every save is validated with sshd -t first; a timestamped backup is kept next to sshd_config." };
            bar.Controls.Add(note);
            root.Controls.Add(bar, 0, 1);
            page.Controls.Add(root);
            return page;
        }

        /// <summary>Shows sshd_config on the Settings tab. keepEdits: fields changed and not saved keep what was typed.</summary>
        private void LoadSettings(bool keepEdits = false)
        {
            Dictionary<string, string> eff;
            try { eff = Ssh.EffectiveSettings(); } catch { eff = new Dictionary<string, string>(); }
            _loadingSettings = true;
            try { LoadSettingsFields(eff, keepEdits); }
            finally { _loadingSettings = false; }
            foreach (var f in FieldDefs) ShowFieldError(f);
            UpdatePending();
        }

        private void LoadSettingsFields(Dictionary<string, string> eff, bool keepEdits)
        {
            foreach (var f in FieldDefs)
            {
                bool keep = keepEdits && FieldEdited(f);
                var v = _cfg.Get(f.Key) ?? "";
                if (f.List) { string err; var args = SshdArgs.Split(v, out err); v = (args == null ? null : SshdArgs.FormatTyped(args)) ?? v; }
                _shown[f.Key] = v;
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
            if (occurrences > 1) hint += (hint.Length > 0 ? "   " : "") + "(" + occurrences + " entries in the file; this field edits the first, the others are on the text tab)";
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
            _hints[f.Key].ForeColor = err != null ? Red : Color.Gray;
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
            if (RawEdited()) l.Add("the sshd_config (text) tab");
            return l;
        }

        /// <summary>Marks tabs with changes not saved: "*" after the tab name and a note next to the Save buttons.</summary>
        private void UpdatePending()
        {
            if (_pgSettings == null || _setPending == null || _rawPending == null) return; // still building
            bool s = SettingsEdited(), r = RawEdited();
            MarkTab(_pgSettings, "Settings", s); MarkTab(_pgAuth, "Authentication", AuthEdited()); MarkTab(_pgRaw, "sshd_config (text)", r);
            _setPending.Text = s ? "Changes not saved yet" : "";
            if (!r) _rawPending.Text = "";
            else if (_rawPending.Text.Length == 0) _rawPending.Text = "Changes not saved yet";
        }

        private static void MarkTab(TabPage page, string name, bool edited) { var text = edited ? name + " *" : name; if (page.Text != text) page.Text = text; }

        private void SaveSettings(bool restart)
        {
            var shell = _cmbShell.Text.Trim();
            // Validate only a changed shell: an existing registry value must not block saving unrelated settings.
            bool shellChanged = !string.Equals(shell, (DefaultShell.Get() ?? "").Trim(), StringComparison.OrdinalIgnoreCase);
            if (shellChanged && shell.Length > 0 && !File.Exists(shell)) throw new ConfigException("Default shell not found:\n" + shell + "\n\nEnter the full path of an existing program, or leave the field empty for cmd.exe.");
            var cand = _cfg.Copy();
            foreach (var f in FieldDefs)
            {
                var v = FieldValue(f);
                var error = FieldError(f, v); if (error != null) throw new ConfigException(error);
                // Only fields the user changed are written: an untouched field must not normalise the line or comment
                // out further occurrences of a repeatable directive (ListenAddress, Port, AllowUsers ...).
                string shown; if (!_shown.TryGetValue(f.Key, out shown)) shown = _cfg.Get(f.Key) ?? "";
                if (v == shown) continue;
                if (f.List)
                {
                    string err; v = SshdArgs.Join(SshdArgs.ParseTyped(v, out err));
                }
                cand.Set(f.Key, v);
            }
            var pwshCurrent = cand.GetSubsystem("powershell");
            var pwshWanted = PwshWanted();
            if (pwshWanted != pwshCurrent) cand.SetSubsystem("powershell", pwshWanted);
            var backup = cand.SaveValidated();
            DefaultShell.Set(shell, _txtShellOption.Text);
            UseConfig(cand, false, true);
            var port = _cfg.EffectivePort;
            var fw = Firewall.Get();
            if (fw != null && !Firewall.Covers(fw.Ports, port))
            {
                // A single-port rule follows sshd to the new port; a multi-port rule keeps its list and gains the port.
                bool single = Firewall.IsSinglePort(fw.Ports);
                var question = single
                    ? "The firewall rule allows port " + fw.Ports + " but sshd will listen on " + port + ".\n\nUpdate the firewall rule to port " + port + "?"
                    : "The firewall rule allows ports " + fw.Ports + " but not " + port + ", the port sshd will listen on.\n\nAdd port " + port + " to the rule?";
                if (MessageBox.Show(this, question, Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes)
                { Firewall.Apply(fw.Enabled, fw.Profiles, single ? port.ToString() : fw.Ports + "," + port); LoadFirewall(); }
            }
            if (restart) RestartWithRollback(backup);
            else Status("Saved. Restart sshd to apply (default shell applies immediately).");
        }

        /// <summary>Restarts sshd and offers to restore the backup when it does not start. True when sshd runs the new configuration.</summary>
        private bool RestartWithRollback(string backup)
        {
            bool applied = false;
            Busy("Restarting sshd...", () =>
            {
                try { Services.Restart("sshd"); }
                catch (Exception ex)
                {
                    if (backup != null && MessageBox.Show(this, "sshd did not start with the new configuration:\n" + ex.Message + "\n\nRestore the previous configuration and start sshd again?", Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Error) == DialogResult.Yes)
                    {
                        File.Copy(backup, Ssh.ConfigPath, true); UseConfig(SshdConfig.Load());
                        Services.Start("sshd");
                        Status("Previous configuration restored, sshd running");
                        return;
                    }
                    throw;
                }
                applied = true;
                Thread.Sleep(800);
                var l = Net.Listeners(_cfg.EffectivePort);
                Status(l.Count > 0 ? "Saved and restarted; listening on " + string.Join(", ", l) : "Saved and restarted, but nothing is listening yet on port " + _cfg.EffectivePort);
                LoadSettings(true); RefreshDashboard(); // the effective values after the restart
            });
            return applied;
        }

        /// <summary>Reload on the Settings tab (discardRaw false) or on the text tab (discardSettings false): the tab's own edits are discarded.</summary>
        private void ReloadFromFile(bool discardSettings = true, bool discardRaw = false) { UseConfig(SshdConfig.Load(), !discardSettings, !discardRaw); Status("Reloaded"); }

        /// <summary>
        /// Makes c the configuration every tab works on, after it was saved or read from the file, and shows it on every tab.
        /// Edits are made on a copy (SshdConfig.Copy) and adopted only after the save succeeded, so an edit that was not
        /// saved never reaches the next save of another tab. Login-method changes not applied yet are kept when the file
        /// has the same login methods as when they were made; otherwise the tab shows the file. Unsaved edits on the Settings
        /// and text tabs are kept (keep...Edits) unless it is that tab's own save or reload.
        /// </summary>
        private void UseConfig(SshdConfig c, bool keepSettingsEdits = true, bool keepRawEdits = true)
        {
            _cfg = c;
            LoadSettings(keepSettingsEdits); LoadRaw(keepRawEdits);
            var fromFile = AuthConfig.Read(c);
            if (!AuthEdited() || !SameAuth(fromFile, _auState)) { bool lost = AuthEdited(); LoadAuth(); if (lost) Status("sshd_config changed: the login-method changes not applied yet were replaced by the file"); }
            else { _auState = fromFile; FillRules(); UpdateAuthUi(); }
            _lvChecks.Items.Clear(); // run again from the new configuration when the tab is opened
        }

        private static bool SameAuth(AuthState a, AuthState b)
        {
            return a.RulesProblem == b.RulesProblem && a.Global.SameAs(b.Global) && a.Rules.Count == b.Rules.Count && a.Rules.Where((r, i) => !r.SameAs(b.Rules[i])).Count() == 0;
        }

        private void RestoreBackup()
        {
            using (var dlg = new OpenFileDialog { Title = "Choose a backup to restore", InitialDirectory = Ssh.ConfigDir, Filter = "sshd_config backups (sshd_config.bak.*)|sshd_config.bak.*|All files|*.*" })
            {
                if (dlg.ShowDialog(this) != DialogResult.OK) return;
                var cand = SshdConfig.Load(dlg.FileName); cand.Path = Ssh.ConfigPath;
                var backup = cand.SaveValidated();
                UseConfig(SshdConfig.Load());
                if (MessageBox.Show(this, "Backup restored (previous file saved as " + Path.GetFileName(backup) + "). Restart sshd now?", Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes) RestartWithRollback(backup);
            }
        }

        private void ResetToDefault()
        {
            if (!File.Exists(Ssh.DefaultConfigPath)) throw new Exception("sshd_config_default not found in " + Ssh.InstallDir);
            if (MessageBox.Show(this, "Replace sshd_config with the shipped sshd_config_default? Your current file is backed up first.", Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;
            var cand = SshdConfig.Load(Ssh.DefaultConfigPath); cand.Path = Ssh.ConfigPath;
            var backup = cand.SaveValidated();
            UseConfig(SshdConfig.Load());
            Status("Defaults written; backup " + Path.GetFileName(backup));
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
                AutoSize = true, ForeColor = Color.DimGray, MaximumSize = new Size(Ui.Px(980), 0), Margin = new Padding(16, 2, 4, 6),
                Text = "Keyboard-interactive is switched off when you apply: OpenSSH for Windows has no back end for it, so it never logs anyone in, and each client attempt at it counts against MaxAuthTries. Windows passwords use the password method."
            });
            root.Controls.Add(top, 0, 0);

            var head = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoSize = true, Dock = DockStyle.Top };
            head.Controls.Add(Lbl("Rules for specific users and groups", true));
            _auRulesNote = new Label { AutoSize = true, MaximumSize = new Size(Ui.Px(980), 0), Margin = new Padding(16, 0, 4, 4), ForeColor = Color.DimGray };
            head.Controls.Add(_auRulesNote);
            root.Controls.Add(head, 0, 1);

            _lvRules = Lv("Applies to|90", "Name|220", "Login methods|560"); _lvRules.AccessibleName = "Rules for users and groups";
            _lvRules.Margin = new Padding(16, 0, 4, 0);
            _lvRules.DoubleClick += (s, e) => Safe(EditRule);
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
            var btnShow = Btn("Show its login methods", (s, e) => Safe(() => CheckAccount(false)), 190);
            var btnAsk = Btn("Ask the running server", (s, e) => Safe(() => CheckAccount(true)), 190);
            check.Controls.Add(btnShow); check.Controls.Add(btnAsk);
            _tips.SetToolTip(btnShow, "What sshd works out for this account from the settings on this tab, applied or not (sshd -T with the rules and any other Match blocks; run as SYSTEM for other accounts, like the service).");
            _tips.SetToolTip(btnAsk, "Connects to this server with the account name only (no password, no key) and shows the methods the server offers.");
            root.Controls.Add(check, 0, 4);

            _auResult = new Label
            {
                AutoSize = true, MaximumSize = new Size(Ui.Px(980), 0), Margin = new Padding(8, 2, 4, 4), ForeColor = Color.DimGray,
                Text = "Apply checks the settings with sshd -t, keeps the previous sshd_config as a backup, restarts sshd (and restores the backup if sshd does not start), then asks the running server which methods it offers you. Connected sessions stay connected."
            };
            root.Controls.Add(_auResult, 0, 5);

            var bar = Flow();
            bar.Controls.Add(Btn("Apply and restart sshd", (s, e) => Safe(ApplyAuth), 190));
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
            _auRulesNote.ForeColor = _auState.RulesProblem != null || _auState.OtherMatchSettings.Count > 0 ? Orange : Color.DimGray;
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
            _auSummary.ForeColor = m.AnyEnabled ? SystemColors.ControlText : Red;
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

        private void ApplyAuth()
        {
            var global = AuthFromUi();
            var cand = AuthCandidate();
            string warning = null; RunResult t = null;
            var tmp = WriteCandidate(cand);
            try
            {
                Busy("Checking the new settings with sshd...", () =>
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
            var backup = cand.SaveValidated();
            Log.Info("Login methods applied: " + global.Describe() + "; " + (_auState.RulesProblem == null ? _auRules.Count + " rule(s)" : "rules section left as it is"));
            _cfg = SshdConfig.Load(); LoadAuth(); UseConfig(_cfg); // the applied methods are now the file's
            if (RestartWithRollback(backup)) VerifyAuth();
        }

        /// <summary>After Apply: asks the running server which methods it offers the current account, and compares with sshd -T.</summary>
        private void VerifyAuth()
        {
            var me = Accounts.AsciiLower(KeyGen.LoginName());
            int port = _cfg.EffectivePort;
            string e1 = null, e2 = null; AuthMethods expected = null; SortedSet<string> offered = null;
            Busy("Asking the running server which login methods it offers...", () =>
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
        private void CheckAccount(bool live)
        {
            string err = null;
            var typed = _auAccount.Text.Trim();
            var name = Accounts.Canonical(typed.Length == 0 ? KeyGen.LoginName() : typed, false, out err);
            if (name == null) throw new ConfigException(err);
            int port = _cfg.EffectivePort;
            if (live)
            {
                SortedSet<string> offered = null;
                Busy("Asking the running server...", () => offered = AuthConfig.Probe(name, "localhost", port, out err));
                if (offered == null) { SetAuthResult("The running server gave no list of methods for " + name + ": " + err, Red); return; }
                SetAuthResult("The running server offers " + name + ": " + AuthConfig.MethodNames(offered) + "." + (_auPending.Text.Length > 0 ? " Changes on this tab count only after Apply." : ""), SystemColors.ControlText);
                return;
            }
            var tmp = WriteCandidate(AuthCandidate());
            Dictionary<string, string> d = null;
            try { Busy("Asking sshd...", () => d = AuthConfig.EffectiveSettingsFor(name, tmp, port, out err)); }
            finally { try { File.Delete(tmp); } catch { } }
            if (d == null) throw new ConfigException("sshd could not work out the settings for " + name + ":\n\n" + (err ?? "").Replace(tmp, "sshd_config"));
            var m = AuthConfig.MethodsFrom(d);
            var sb = new StringBuilder(name + " logs in with: " + m.Describe() + (_auPending.Text.Length > 0 ? " (the settings on this tab, not applied yet)" : "") + ".");
            if (m.PublicKey)
            {
                string value; d.TryGetValue("authorizedkeysfile", out value);
                var home = Accounts.ProfileDir(Acl.SidOfAccount(name));
                var file = Ssh.ResolveKeysFile(value, name, home);
                if (file == null) sb.Append(home == null ? " The account has not logged on yet, so it has no profile and no authorized_keys file." : " No authorized_keys file is configured.");
                else
                {
                    int n = 0;
                    try { n = Keys.Read(file).Count(k => k.Type != "?"); } catch { }
                    sb.Append(" Keys authorized: " + n + " in " + file + ".");
                }
            }
            var limits = new[] { "allowusers", "allowgroups", "denyusers", "denygroups" }.Where(k => d.ContainsKey(k) && d[k].Length > 0).Select(k => k + " " + d[k]).ToList();
            if (limits.Count > 0) sb.Append(" sshd_config also limits who may log in: " + string.Join("; ", limits) + ".");
            SetAuthResult(sb.ToString(), SystemColors.ControlText);
        }

        // ---------------- Raw editor ----------------
        private TabPage BuildRawEditor()
        {
            var page = new TabPage("sshd_config (text)");
            var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2 };
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 100)); root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            // MaxLength 0 lifts the 32767-character typing limit of a multiline TextBox (sshd_config files can be larger).
            _rawEditor = new TextBox { Multiline = true, ScrollBars = ScrollBars.Both, WordWrap = false, Dock = DockStyle.Fill, Font = new Font("Consolas", Ui.Pt(10f)), AcceptsTab = true, AcceptsReturn = true, MaxLength = 0 };
            root.Controls.Add(_rawEditor, 0, 0);
            var bar = Flow();
            bar.Controls.Add(Btn("Validate", (s, e) => Safe(() => { var c = FromEditor(); var tmp = Path.GetTempFileName(); try { File.WriteAllText(tmp, c.Text, new UTF8Encoding(false)); var r = Ssh.TestConfig(tmp); MessageBox.Show(this, r.Ok ? "No problems found." : r.Output.Replace(tmp, "sshd_config"), Program.AppName, MessageBoxButtons.OK, r.Ok ? MessageBoxIcon.Information : MessageBoxIcon.Warning); } finally { try { File.Delete(tmp); } catch { } } }), 110));
            // The editor text becomes the working configuration only after sshd accepted it; a rejected text must not
            // replace the configuration the Settings tab works on.
            bar.Controls.Add(Btn("Save", (s, e) => Safe(() => { var c = FromEditor(); var b = c.SaveValidated(); UseConfig(c, true, false); Status("Saved (backup " + (b == null ? "none" : Path.GetFileName(b)) + "). Restart sshd to apply."); }), 110));
            bar.Controls.Add(Btn("Save and restart sshd", (s, e) => Safe(() => { var c = FromEditor(); var b = c.SaveValidated(); UseConfig(c, true, false); RestartWithRollback(b); }), 180));
            bar.Controls.Add(Btn("Reload", (s, e) => Safe(() => ReloadFromFile(false, true)), 100));
            bar.Controls.Add(Btn("Open in Notepad", (s, e) => Proc.OpenExternal("notepad.exe", "\"" + Ssh.ConfigPath + "\""), 140));
            _rawPending = new Label { AutoSize = true, Margin = new Padding(12, 10, 4, 4), ForeColor = Orange, MaximumSize = new Size(Ui.Px(560), 0) };
            bar.Controls.Add(_rawPending);
            _rawEditor.AccessibleName = "sshd_config text";
            _rawEditor.TextChanged += (s, e) => UpdatePending();
            root.Controls.Add(bar, 0, 1);
            page.Controls.Add(root);
            return page;
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
            var c = new SshdConfig { Path = Ssh.ConfigPath, NewLine = _cfg.NewLine };
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
            adminRoot.Controls.Add(_lvAdminKeys, 0, 0);
            var abar = Flow();
            abar.Controls.Add(Btn("Add from file...", (s, e) => Safe(() => AddKeyFromFile(true)), 130));
            abar.Controls.Add(Btn("Paste key...", (s, e) => Safe(() => AddKeyFromText(true)), 110));
            abar.Controls.Add(Btn("Remove selected", (s, e) => Safe(() => RemoveKey(true)), 140));
            abar.Controls.Add(Btn("Fix permissions", (s, e) => Safe(() => { if (File.Exists(Ssh.AdminKeysPath)) Acl.Restrict(Ssh.AdminKeysPath, null); Status("ACL set: SYSTEM and Administrators only"); LoadKeys(); }), 130));
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
            _cmbUsers.SelectedIndexChanged += (s, e) => Safe(LoadUserKeys); _cmbUsers.AccessibleName = "User profile";
            top.Controls.Add(_cmbUsers);
            userRoot.Controls.Add(top, 0, 0);
            _lvUserKeys = Lv("Type|230", "Comment|200", "SHA256 fingerprint|420", "Options|150"); _lvUserKeys.AccessibleName = "Authorized keys of the selected user";
            userRoot.Controls.Add(_lvUserKeys, 0, 1);
            var ubar = Flow();
            ubar.Controls.Add(Btn("Add from file...", (s, e) => Safe(() => AddKeyFromFile(false)), 130));
            ubar.Controls.Add(Btn("Paste key...", (s, e) => Safe(() => AddKeyFromText(false)), 110));
            ubar.Controls.Add(Btn("Remove selected", (s, e) => Safe(() => RemoveKey(false)), 140));
            ubar.Controls.Add(Btn("Fix permissions", (s, e) => Safe(() => { var p = CurrentUserKeysPath(); if (File.Exists(p)) Acl.Restrict(p, CurrentUserSid()); Status("ACL set for " + p); LoadUserKeys(); }), 130));
            userRoot.Controls.Add(ubar, 0, 2);
            userBox.Controls.Add(userRoot);
            split.Panel2.Controls.Add(userBox);
            page.Controls.Add(split);
            return page;
        }

        private void LoadKeys()
        {
            FillKeyList(_lvAdminKeys, Ssh.AdminKeysPath);
            var sel = _cmbUsers.SelectedItem as string;
            _cmbUsers.Items.Clear(); foreach (var p in Keys.UserProfiles()) _cmbUsers.Items.Add(p);
            if (_cmbUsers.Items.Count > 0) { int i = sel == null ? -1 : _cmbUsers.Items.IndexOf(sel); _cmbUsers.SelectedIndex = i < 0 ? 0 : i; }
        }
        private void LoadUserKeys() { if (_cmbUsers.SelectedItem != null) FillKeyList(_lvUserKeys, CurrentUserKeysPath()); }
        private string CurrentUserKeysPath() { return Keys.UserKeysPath((string)_cmbUsers.SelectedItem); }
        private SecurityIdentifier CurrentUserSid()
        {
            // The profile folder name is not always the account name (renamed accounts, "name.DOMAIN" folders);
            // the ProfileList registry key maps the folder to the SID that sshd will impersonate.
            var sid = Keys.SidOfProfile((string)_cmbUsers.SelectedItem);
            if (sid == null) throw new Exception("Cannot determine the account that owns " + _cmbUsers.SelectedItem + ". The authorized_keys file would not be readable by that user, so nothing was written.");
            return sid;
        }
        private static void FillKeyList(ListView lv, string path)
        {
            lv.BeginUpdate(); lv.Items.Clear();
            foreach (var k in Keys.Read(path)) lv.Items.Add(new ListViewItem(new[] { k.Type, k.Comment, k.Fingerprint, k.Options }) { Tag = k.Line });
            lv.EndUpdate();
        }
        private void AddKeyFromFile(bool admin)
        {
            using (var dlg = new OpenFileDialog { Title = "Choose a public key file", Filter = "Public keys (*.pub)|*.pub|All files|*.*" })
            {
                if (dlg.ShowDialog(this) != DialogResult.OK) return;
                AddKeyLines(admin, File.ReadAllLines(dlg.FileName));
            }
        }
        private void AddKeyFromText(bool admin)
        {
            using (var dlg = new TextDialog("Paste one or more public keys (one per line)")) { if (dlg.ShowDialog(this) == DialogResult.OK) AddKeyLines(admin, dlg.Value.Split('\n')); }
        }
        private void AddKeyLines(bool admin, IEnumerable<string> newLines)
        {
            var path = admin ? Ssh.AdminKeysPath : CurrentUserKeysPath();
            var owner = admin ? null : CurrentUserSid();
            var r = Keys.AddLines(path, newLines, owner); // keeps comments; skips key material already present
            if (admin) FillKeyList(_lvAdminKeys, path); else LoadUserKeys();
            Status(r[0] + " key(s) added to " + path + (r[1] > 0 ? ", " + r[1] + " already present" : ""));
        }
        private void RemoveKey(bool admin)
        {
            var lv = admin ? _lvAdminKeys : _lvUserKeys;
            if (lv.SelectedItems.Count == 0) { Status("Select a key first"); return; }
            var line = (string)lv.SelectedItems[0].Tag;
            if (MessageBox.Show(this, "Remove this key?\n\n" + line, Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
            var path = admin ? Ssh.AdminKeysPath : CurrentUserKeysPath();
            int removed = Keys.RemoveKey(path, line, admin ? null : CurrentUserSid());
            if (admin) FillKeyList(_lvAdminKeys, path); else LoadUserKeys();
            Status(removed > 0 ? "Key removed" : "Key not found in " + path);
        }

        // ---------------- Key generator ----------------
        private ComboBox _kgType; private TextBox _kgPath, _kgComment, _kgPass1, _kgPass2, _kgPublic; private CheckBox _kgNoPass, _kgAuthorize;
        private Label _kgResult; private string _kgDefaultShown;

        private TabPage BuildKeyGen()
        {
            var page = new TabPage("Key generator");
            var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 5, Padding = new Padding(8) };
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize)); root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize)); root.RowStyles.Add(new RowStyle(SizeType.Percent, 100)); root.RowStyles.Add(new RowStyle(SizeType.AutoSize));

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
            bar.Controls.Add(Btn("Generate key pair", (s, e) => Safe(GenerateKey), 170));
            bar.Controls.Add(Btn("Test login with this key", (s, e) => Safe(TestKeyLogin), 190));
            bar.Controls.Add(Btn("Copy public key", (s, e) => Safe(() => { if (_kgPublic.Text.Length > 0) { Clipboard.SetText(_kgPublic.Text); Status("Public key copied"); } }), 140));
            bar.Controls.Add(Btn("Open folder", (s, e) => Safe(() => { var p = _kgPath.Text.Trim(); if (File.Exists(p)) Proc.OpenExternal("explorer.exe", "/select,\"" + p + "\""); else if (Directory.Exists(Path.GetDirectoryName(p))) Proc.OpenExternal("explorer.exe", "\"" + Path.GetDirectoryName(p) + "\""); }), 120));
            root.Controls.Add(bar, 0, 1);

            _kgResult = new Label { AutoSize = true, Margin = new Padding(6, 6, 6, 2), MaximumSize = new Size(Ui.Px(980), 0), ForeColor = Color.DimGray, Text = "The public key appears below after generation." };
            root.Controls.Add(_kgResult, 0, 2);
            _kgPublic = new TextBox { Multiline = true, ReadOnly = true, WordWrap = true, ScrollBars = ScrollBars.Vertical, Dock = DockStyle.Fill, Font = new Font("Consolas", Ui.Pt(9.5f)) };
            _kgPublic.AccessibleName = "Public key"; root.Controls.Add(_kgPublic, 0, 3);
            root.Controls.Add(new Label
            {
                AutoSize = true, ForeColor = Color.DimGray, Margin = new Padding(6), MaximumSize = new Size(Ui.Px(980), 0),
                Text = "The private key stays on this computer and only you, SYSTEM and Administrators can read it; ssh refuses a key that others can read. " +
                       "The passphrase goes to ssh-keygen through SSH_ASKPASS and never appears on a command line. Give other servers the public key " +
                       "(the .pub file or the text above), never the private key. PuTTY and WinSCP: import the private key in PuTTYgen (Conversions, Import key)."
            }, 0, 4);
            page.Controls.Add(root);
            return page;
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

        private void GenerateKey()
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
            try { Busy("Generating " + type.Label + " key...", () => res = KeyGen.GenerateReplacing(type, path, _kgComment.Text.Trim(), pass, now)); }
            finally { _kgPass1.Text = ""; _kgPass2.Text = ""; pass = null; }
            _kgPublic.Text = res.PublicKey;
            var text = "Created " + res.PrivatePath + " (private key" + (res.Encrypted ? ", protected by the passphrase" : ", NO passphrase") + ") and " + Path.GetFileName(res.PublicPath) +
                       ".\nFingerprint " + res.Fingerprint + ". Verified: the private key reproduces the public key" + (res.Encrypted ? ", does not open without the passphrase" : "") + ", and only you, SYSTEM and Administrators can read it.";
            if (_kgAuthorize.Checked)
            {
                bool already; var where = KeyGen.AuthorizeForCurrentUser(res.PublicKey, out already);
                text += "\nAuthorized for " + KeyGen.LoginName() + " in " + where + (already ? " (it was already there)." : ".") + " Use \"Test login with this key\" to try it.";
                LoadKeys();
                if (type.Experimental && !EnsureServerAccepts(type))
                    text += "\nThis server does not accept " + type.PublicType + " yet, so the key cannot log in until PubkeyAcceptedAlgorithms includes it.";
            }
            if (type.Experimental)
                text += "\nExperimental key type: clients need OpenSSH 10.5 or later and the line \"PubkeyAcceptedAlgorithms +" + type.PublicType + "\" in their ssh config.";
            _kgResult.Text = text; _kgResult.ForeColor = Green;
            Log.Info("Key pair created: " + res.PrivatePath + " " + res.Fingerprint);
            Status("Key pair created: " + res.PrivatePath);
        }

        /// <summary>
        /// For an experimental key type: asks before adding it to PubkeyAcceptedAlgorithms (validated save with backup,
        /// restart with automatic rollback). Returns true when the server accepts the algorithm afterwards.
        /// </summary>
        private bool EnsureServerAccepts(KeyTypeChoice t)
        {
            if (KeyGen.ServerAccepts(t.PublicType)) return true;
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
            var backup = cand.SaveValidated();
            UseConfig(cand);
            RestartWithRollback(backup);
            return KeyGen.ServerAccepts(t.PublicType);
        }

        private void TestKeyLogin()
        {
            var p = _kgPath.Text.Trim();
            if (p.Length == 0 || !File.Exists(p)) throw new ConfigException("No private key at\n" + p + "\n\nGenerate one first, or enter the path of an existing private key.");
            var path = Path.GetFullPath(p);
            string pass = null;
            if (KeyGen.IsEncrypted(path))
            {
                using (var dlg = new PasswordDialog("Passphrase for " + Path.GetFileName(path))) { if (dlg.ShowDialog(this) != DialogResult.OK) return; pass = dlg.Value; }
            }
            RunResult r = null;
            int port = _cfg == null ? 22 : _cfg.EffectivePort;
            try { Busy("Logging in to this server with " + Path.GetFileName(path) + "...", () => r = KeyGen.TestLogin(path, pass, port)); }
            finally { pass = null; }
            if (KeyGen.LoginOk(r))
            {
                _kgResult.Text = "Login test passed: this server accepted " + Path.GetFileName(path) + " for " + KeyGen.LoginName() + " on port " + port + " (public key only, host key checked)."; _kgResult.ForeColor = Green;
                Status("Login test passed");
            }
            else
            {
                var detail = r == null ? "" : r.Output.Trim();
                _kgResult.Text = "Login test failed for " + Path.GetFileName(path) + ". " + (detail.Length > 400 ? detail.Substring(0, 400) + "..." : detail) +
                                 "\nIf the key is not authorized yet, tick \"Allow this key to log in\" and generate it again, or add the .pub file on the Keys tab."; _kgResult.ForeColor = Red;
                Status("Login test failed");
            }
        }

        // ---------------- Firewall ----------------
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
            bar.Controls.Add(Btn("Apply", (s, e) => Safe(() =>
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
                Firewall.Apply(_fwEnabled.Checked, (_fwDomain.Checked ? 1 : 0) | (_fwPrivate.Checked ? 2 : 0) | (_fwPublic.Checked ? 4 : 0), ports);
                LoadFirewall(); Status("Firewall rule updated");
            }), 110));
            bar.Controls.Add(Btn("Use sshd port", (s, e) => Safe(() => { _fwPort.Value = _cfg.EffectivePort; }), 120));
            bar.Controls.Add(Btn("Remove rule", (s, e) => Safe(() => { if (MessageBox.Show(this, "Remove the inbound firewall rule for sshd? Remote clients will no longer reach the server.", Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Warning) == DialogResult.Yes) { Firewall.Remove(); LoadFirewall(); } }), 120));
            bar.Controls.Add(Btn("Windows Firewall console", (s, e) => Proc.OpenExternal("wf.msc"), 190));
            flow.Controls.Add(bar);
            flow.Controls.Add(new Label { AutoSize = true, ForeColor = Color.DimGray, Margin = new Padding(4, 12, 4, 4), MaximumSize = new Size(Ui.Px(800), 0), Text = "The rule is scoped to sshd.exe. Domain-joined Windows Servers use the Domain profile; laptops on untrusted networks use Public. Restrict remote addresses in the Windows Firewall console if the server must only be reachable from specific networks." });
            page.Controls.Add(flow);
            return page;
        }

        private void LoadFirewall()
        {
            var fw = Firewall.Get();
            _fwLoadedPorts = fw == null ? null : fw.Ports;
            if (fw == null) { _fwState.Text = "No inbound rule for sshd found. Choose profiles and click Apply to create one."; _fwState.ForeColor = Red; _fwEnabled.Checked = true; _fwDomain.Checked = _fwPrivate.Checked = _fwPublic.Checked = true; _fwPort.Value = _cfg == null ? 22 : _cfg.EffectivePort; return; }
            _fwState.Text = "Rule \"" + fw.Name + "\": " + (fw.Enabled ? "enabled" : "disabled") + ", profiles " + fw.ProfilesText + ", port " + fw.Ports + ", program " + fw.Program;
            _fwState.ForeColor = fw.Enabled ? Green : Red;
            _fwEnabled.Checked = fw.Enabled;
            bool all = (fw.Profiles & 0x7fffffff) == 0x7fffffff;
            _fwDomain.Checked = all || (fw.Profiles & 1) != 0; _fwPrivate.Checked = all || (fw.Profiles & 2) != 0; _fwPublic.Checked = all || (fw.Profiles & 4) != 0;
            // A multi-port rule shows sshd's port in the field; Apply keeps the whole list (see the Apply button).
            int p; int sshdPort = _cfg == null ? 22 : _cfg.EffectivePort;
            _fwPort.Value = int.TryParse(fw.Ports, out p) && p >= 1 && p <= 65535 ? p : (sshdPort >= 1 && sshdPort <= 65535 ? sshdPort : 22);
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
            _txtFilter = new TextBox { Width = Ui.Px(240), Margin = new Padding(4, 6, 4, 4) }; _txtFilter.KeyDown += (s, e) => { if (e.KeyCode == System.Windows.Forms.Keys.Enter) { e.SuppressKeyPress = true; Safe(LoadLogs); } };
            _txtFilter.AccessibleName = "Event filter"; bar.Controls.Add(_txtFilter);
            bar.Controls.Add(Lbl("max:"));
            _numEvents = new NumericUpDown { Minimum = 50, Maximum = 5000, Value = 300, Increment = 50, Width = Ui.Px(80), Margin = new Padding(4, 6, 4, 4) }; _numEvents.AccessibleName = "Maximum number of events"; bar.Controls.Add(_numEvents);
            bar.Controls.Add(Btn("Refresh", (s, e) => Safe(LoadLogs), 100));
            bar.Controls.Add(Btn("Failed logins only", (s, e) => Safe(() => { _txtFilter.Text = "Failed"; LoadLogs(); }), 150));
            bar.Controls.Add(Btn("Accepted logins only", (s, e) => Safe(() => { _txtFilter.Text = "Accepted"; LoadLogs(); }), 160));
            bar.Controls.Add(Btn("Copy selected", (s, e) => Safe(() => { if (_lvEvents.SelectedItems.Count > 0) Clipboard.SetText(string.Join("\t", _lvEvents.SelectedItems[0].SubItems.Cast<ListViewItem.ListViewSubItem>().Select(x => x.Text))); }), 120));
            root.Controls.Add(bar, 0, 0);
            _lvEvents = Lv("Time|140", "ID|50", "Level|80", "Message|760"); _lvEvents.AccessibleName = "Events";
            _lvEvents.DoubleClick += (s, e) => { if (_lvEvents.SelectedItems.Count > 0) MessageBox.Show(this, _lvEvents.SelectedItems[0].SubItems[3].Text, "Event " + _lvEvents.SelectedItems[0].SubItems[1].Text); };
            root.Controls.Add(_lvEvents, 0, 1);
            split.Panel1.Controls.Add(root);
            var fileBox = new GroupBox { Text = "File log (%ProgramData%\\ssh\\logs, used when SyslogFacility is LOCAL0-7)", Dock = DockStyle.Fill, Padding = new Padding(6) };
            _txtFileLog = new TextBox { Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Both, WordWrap = false, Dock = DockStyle.Fill, Font = new Font("Consolas", Ui.Pt(9.5f)) };
            _txtFileLog.AccessibleName = "File log"; fileBox.Controls.Add(_txtFileLog);
            split.Panel2.Controls.Add(fileBox);
            page.Controls.Add(split);
            return page;
        }

        private void LoadLogs()
        {
            Busy("Reading events...", () =>
            {
                var events = EventLogs.Read((int)_numEvents.Value, _txtFilter.Text.Trim());
                _lvEvents.BeginUpdate(); _lvEvents.Items.Clear();
                foreach (var ev in events)
                {
                    var it = new ListViewItem(new[] { ev.Time.ToString("yyyy-MM-dd HH:mm:ss"), ev.Id.ToString(), ev.Level, ev.Message });
                    if (ev.Level.StartsWith("Err", StringComparison.OrdinalIgnoreCase)) it.ForeColor = Red;
                    else if (ev.Level.StartsWith("Warn", StringComparison.OrdinalIgnoreCase) || ev.Message.IndexOf("Failed", StringComparison.OrdinalIgnoreCase) >= 0) it.ForeColor = Orange;
                    _lvEvents.Items.Add(it);
                }
                _lvEvents.EndUpdate();
                var f = EventLogs.FileLogPath();
                _txtFileLog.Text = f == null ? "No file log present. Set 'Log destination' to LOCAL0 on the Settings tab to log to a file." : ("== " + f + "\r\n" + EventLogs.TailFile(f, 300).Replace("\r\n", "\n").Replace("\n", "\r\n"));
            });
            Status(_lvEvents.Items.Count + " event(s)");
        }

        // ---------------- Hardening ----------------
        private TabPage BuildHardening()
        {
            var page = new TabPage("Hardening");
            var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2 };
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize)); root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            var bar = Flow();
            bar.Controls.Add(Btn("Run checks", (s, e) => Safe(RunChecks), 110));
            bar.Controls.Add(Btn("Apply recommended settings", (s, e) => Safe(ApplyRecommended), 210));
            bar.Controls.Add(new Label { AutoSize = true, Margin = new Padding(12, 10, 4, 4), ForeColor = Color.DimGray, MaximumSize = new Size(Ui.Px(700), 0), Text = "Recommended: ClientAliveInterval 300, MaxAuthTries 4, LoginGraceTime 60, RequiredRSASize 2048, LogLevel VERBOSE, keyboard-interactive off, PerSourcePenalties on. Windows authentication and login restrictions are never changed automatically (see the Authentication and Settings tabs)." });
            root.Controls.Add(bar, 0, 0);
            _lvChecks = Lv("Check|220", "Status|70", "Detail|700"); _lvChecks.AccessibleName = "Hardening checks";
            root.Controls.Add(_lvChecks, 0, 1);
            page.Controls.Add(root);
            return page;
        }

        private void RunChecks()
        {
            Busy("Running checks...", () =>
            {
                _lvChecks.BeginUpdate(); _lvChecks.Items.Clear();
                foreach (var c in Hardening.Run(_cfg))
                {
                    var it = new ListViewItem(new[] { c.Name, c.Status, c.Detail });
                    it.ForeColor = c.Status == "OK" ? Green : c.Status == "WARN" ? Orange : Color.Black;
                    _lvChecks.Items.Add(it);
                }
                _lvChecks.EndUpdate();
            });
            Status("Checks complete: " + _lvChecks.Items.Cast<ListViewItem>().Count(i => i.SubItems[1].Text == "WARN") + " warning(s)");
        }

        private void ApplyRecommended()
        {
            if (MessageBox.Show(this, "Write these settings to sshd_config?\n\n  ClientAliveInterval 300\n  ClientAliveCountMax 3\n  MaxAuthTries 4\n  LoginGraceTime 60\n  RequiredRSASize 2048\n  LogLevel VERBOSE\n  KbdInteractiveAuthentication no (it has no Windows back end)\n  PerSourcePenalties (sshd default, enabled)\n\nA backup is created and the file is validated first. sshd is restarted afterwards.", Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
            var c = _cfg.Copy();
            c.Set("ClientAliveInterval", "300"); c.Set("ClientAliveCountMax", "3"); c.Set("MaxAuthTries", "4"); c.Set("LogLevel", "VERBOSE");
            c.Set("LoginGraceTime", "60"); c.Set("RequiredRSASize", "2048");
            c.Set("KbdInteractiveAuthentication", "no"); c.Set("ChallengeResponseAuthentication", "");
            if ((c.Get("PerSourcePenalties") ?? "").Equals("no", StringComparison.OrdinalIgnoreCase)) c.Set("PerSourcePenalties", "");
            var b = c.SaveValidated(); UseConfig(c);
            RestartWithRollback(b); RunChecks();
        }

        // ---------------- About ----------------
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
            header.Controls.Add(new Label { Text = Program.AppName + " " + Program.AppVersion, AutoSize = true, Font = new Font(Font.FontFamily, Ui.Pt(14f), FontStyle.Bold), Margin = new Padding(4, Ui.Px(20), 4, 4) });
            flow.Controls.Add(header);
            flow.Controls.Add(new Label { AutoSize = true, MaximumSize = new Size(Ui.Px(820), 0), Margin = new Padding(4, 8, 4, 8), Text = "Management console for the OpenSSH for Windows server: service control, validated configuration editing with backups and rollback, authorized and host keys, default shell, Windows Firewall rule, event log viewer and a hardening check. Works with the MSI packages from this repository and with the official Microsoft packages." });
            Action<string, string> line = (k, v) => flow.Controls.Add(new Label { AutoSize = true, Text = k.PadRight(22) + v, Font = new Font("Consolas", Ui.Pt(9.5f)), Margin = new Padding(4, 1, 4, 1) });
            line("Install folder:", Ssh.InstallDir); line("Configuration:", Ssh.ConfigPath); line("Server version:", Ssh.ServerVersion()); line("Client banner:", Ssh.ClientBanner());
            line("Manager log:", Log.Path); line("Self-check:", "OpenSSHServerManager.exe --check [report.txt]"); line("OS:", Environment.OSVersion.VersionString + (Environment.Is64BitOperatingSystem ? " x64" : " x86")); line(".NET runtime:", Environment.Version.ToString());
            var link = new LinkLabel { Text = "https://github.com/patnawa/openssh_server_pn  (documentation, packages, issues)", AutoSize = true, Margin = new Padding(4, 12, 4, 4) };
            link.LinkClicked += (s, e) => Proc.OpenExternal("https://github.com/patnawa/openssh_server_pn");
            flow.Controls.Add(link);
            var wiki = new LinkLabel { Text = "https://github.com/PowerShell/Win32-OpenSSH/wiki  (upstream wiki)", AutoSize = true, Margin = new Padding(4) };
            wiki.LinkClicked += (s, e) => Proc.OpenExternal("https://github.com/PowerShell/Win32-OpenSSH/wiki");
            flow.Controls.Add(wiki);
            flow.Controls.Add(Btn("Open manager log", (s, e) => Proc.OpenExternal("notepad.exe", "\"" + Log.Path + "\""), 150));
            page.Controls.Add(flow);
            return page;
        }
    }
}

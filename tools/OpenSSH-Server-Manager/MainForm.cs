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
    internal sealed class MainForm : ThemedForm
    {
        private readonly ThemedTabControl _tabs = new ThemedTabControl();
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

        // State colours of the current palette (Theme): light, dark or high contrast.
        private static Color Green { get { return Theme.Good; } }
        private static Color Red { get { return Theme.Bad; } }
        private static Color Orange { get { return Theme.Warn; } }

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
            _tabs.TabPages.Add(_pgDashboard = BuildDashboard());
            _tabs.TabPages.Add(_pgSessions = BuildSessions());
            _tabs.TabPages.Add(_pgSettings = BuildSettings());
            _tabs.TabPages.Add(_pgAuth = BuildAuthentication());
            _tabs.TabPages.Add(_pgRaw = BuildRawEditor());
            _tabs.TabPages.Add(_pgKeys = BuildKeys());
            _tabs.TabPages.Add(_pgKeyGen = BuildKeyGen());
            _tabs.TabPages.Add(_pgClient = BuildClient());
            _tabs.TabPages.Add(_pgFirewall = BuildFirewall());
            _tabs.TabPages.Add(_pgLogs = BuildLogs());
            _tabs.TabPages.Add(_pgHardening = BuildHardening());
            _tabs.TabPages.Add(_pgAbout = BuildAbout());
            _tabs.SelectedIndexChanged += (s, e) => Safe(() => OnTabSelected());
            _tabs.AccessibleName = "Sections";

            _cancelButton.Click += (s, e) => { var c = _cancel; if (c != null) { c.Cancel(); Status("Cancelling..."); } };
            _status.Items.Add(_statusText); _status.Items.Add(_busy); _status.Items.Add(_cancelButton);
            Controls.Add(_tabs); Controls.Add(_status);
            KeyPreview = true;

            _timer.Tick += (s, e) =>
            {
                // In the background: service, network, firewall and process queries can take seconds, and the
                // window must stay responsive meanwhile. The notification area icon needs the service state even
                // while another tab (or no window) is shown.
                if (_tabs.SelectedTab == _pgSessions) RefreshInBackground(CollectSessions, ShowSessions);
                else if (_tabs.SelectedTab == _pgDashboard || _tray != null) RefreshInBackground(CollectDashboard, ShowDashboard);
            };
            Shown += (s, e) => { Safe(LoadEverything); _timer.Start(); Safe(OfferWizard, false); };
            FormClosing += (s, e) =>
            {
                if (_busyDepth > 0 && e.CloseReason == CloseReason.UserClosing) { e.Cancel = true; Status("Wait until the running operation has finished"); return; }
                if (!Program.Unattended && e.CloseReason == CloseReason.UserClosing)
                {
                    var unsaved = UnsavedTabs();
                    if (unsaved.Count > 0 && MessageBox.Show(this, "Changes on " + string.Join(" and ", unsaved) + " are not saved.\n\nClose anyway and lose them?", Program.AppName,
                            MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes) { e.Cancel = true; return; }
                }
                _timer.Stop();
                StopWatchers();
            };
            InitTray();
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
                        if (tab == _pgSettings) Safe(() => SaveSettings(false));
                        else if (tab == _pgRaw) Safe(() => SaveRaw());
                        else if (tab == _pgAuth) Safe(ApplyAuth);
                        else if (tab == _pgFirewall) Safe(ApplyFirewall);
                        else return base.ProcessCmdKey(ref msg, keyData);
                        return true;
                    case System.Windows.Forms.Keys.F5:
                        if (tab == _pgDashboard) Safe(RefreshDashboard);
                        else if (tab == _pgSessions) Safe(RefreshSessions);
                        else if (tab == _pgLogs) Safe(LoadLogs);
                        else if (tab == _pgHardening) Safe(RunChecks);
                        else if (tab == _pgKeys) Safe(LoadKeys);
                        else if (tab == _pgFirewall) Safe(LoadFirewall);
                        else if (tab == _pgClient) Safe(LoadClient);
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
                    int i = digit - System.Windows.Forms.Keys.D1;
                    if (i < _tabs.TabCount) { _tabs.SelectedIndex = i; _tabs.Focus(); return true; }
                }
            }
            return base.ProcessCmdKey(ref msg, keyData);
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
            catch (OperationCanceledException) { Status("Cancelled: nothing was changed"); }
            catch (ConfigException ex)
            {
                Log.Info("Configuration rejected: " + ex.Message);
                if (!Program.Unattended) MessageBox.Show(this, ex.Message, Program.AppName, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                Status("Not saved: configuration rejected");
            }
            catch (Exception ex) { Log.Error("Operation failed", ex, show); Status("Error: " + ex.Message); }
        }

        private int _busyDepth; private bool _timerWasRunning;
        private CancellationTokenSource _cancel;
        private readonly ToolStripButton _cancelButton = new ToolStripButton("Cancel") { Visible = false, AccessibleName = "Cancel the running operation" };

        /// <summary>
        /// Marks the window busy while an operation runs: the tabs take no input, the progress bar moves and the window
        /// can still be moved, repainted and closed-guarded. The refresh timer pauses so that no second operation starts.
        /// </summary>
        private void BeginBusy(string text)
        {
            if (_busyDepth++ == 0)
            {
                _timerWasRunning = _timer.Enabled; _timer.Stop();
                _busy.Visible = true; UseWaitCursor = true; _tabs.Enabled = false;
            }
            Status(text);
        }

        private void EndBusy()
        {
            if (--_busyDepth > 0) return;
            _tabs.Enabled = true; UseWaitCursor = false; _busy.Visible = false; _cancelButton.Visible = false;
            if (_timerWasRunning && !IsDisposed) _timer.Start();
            if (_themePending && !IsDisposed) { _themePending = false; BeginInvoke((Action)(() => Safe(ApplyTheme, false))); }
        }

        /// <summary>Runs work on the window's thread with the window marked busy (work that shows dialogs or fills controls).</summary>
        private void Busy(string text, Action work)
        {
            BeginBusy(text);
            try { Application.DoEvents(); work(); }
            finally { EndBusy(); }
        }

        /// <summary>
        /// Runs work that does not touch the window (services, sshd, ssh-keygen, event log, firewall) on a background thread
        /// and waits for it while the window keeps handling messages, so it never shows "Not Responding". Returns work's
        /// result, or throws its exception. Called from a background thread, it simply runs work.
        /// </summary>
        private T Bg<T>(string text, Func<T> work)
        {
            if (!IsHandleCreated || InvokeRequired) return work();
            T result = default(T); Exception error = null;
            var t = new Thread(() => { try { result = work(); } catch (Exception ex) { error = ex; } }) { IsBackground = true, Name = "operation" };
            t.SetApartmentState(ApartmentState.STA); // COM objects of the firewall and network list APIs
            BeginBusy(text);
            try
            {
                t.Start();
                while (!t.Join(15)) Application.DoEvents();
            }
            finally { EndBusy(); }
            if (error != null) System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(error).Throw();
            return result;
        }

        private void Bg(string text, Action work) { Bg<object>(text, () => { work(); return null; }); }

        /// <summary>Bg with a Cancel button in the status bar; work receives the token and stops when it is cancelled.</summary>
        private T BgCancellable<T>(string text, Func<CancellationToken, T> work)
        {
            using (var cts = new CancellationTokenSource())
            {
                _cancel = cts; _cancelButton.Visible = true;
                try { return Bg(text, () => work(cts.Token)); }
                finally { _cancel = null; _cancelButton.Visible = false; }
            }
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
            lv.ColumnClick += (s, e) => ListSorter.Toggle((ListView)s, e.Column);
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
            // By page, not by caption: captions change ("Settings *") and could be translated.
            var tab = _tabs.SelectedTab;
            if (tab == null) return;
            if (tab == _pgDashboard) RefreshDashboard();
            else if (tab == _pgSessions) RefreshSessions();
            else if (tab == _pgLogs) { if (_lvEvents.Items.Count == 0) LoadLogs(); }
            else if (tab == _pgHardening) { if (_lvChecks.Items.Count == 0) RunChecks(); }
            else if (tab == _pgClient) { if (!_clientLoaded) LoadClient(); }
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
            actions.Controls.Add(Btn("Connect (ssh localhost)", (s, e) => Proc.OpenUnelevated(Ssh.Exe("ssh.exe"), "-p " + (_cfg == null ? 22 : _cfg.EffectivePort) + " localhost"), 170));
            actions.Controls.Add(Btn("Setup wizard...", (s, e) => Safe(RunWizard), 130));
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
            var cfg = _cfg;
            ShowDashboard(Bg("Refreshing the dashboard...", () => CollectDashboard(cfg)));
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
            TrayState(sshd, d.Sessions.Count);
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
                        if (_busyDepth == 0) Safe(() => show(data), false); // not while an operation (Busy) runs
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
                if (action == "restart" && !Program.Unattended && MessageBox.Show(this, "Restart the SSH server? sshd reads sshd_config again; new connections are refused for a moment.\n\nConnected sessions stay connected: each runs in its own sshd-session.exe process.", Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
                _expectedStateChange = DateTime.UtcNow;
                Bg((action == "stop" ? "Stopping" : action == "start" ? "Starting" : "Restarting") + " sshd...", () =>
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
                RefreshDashboard();
                Status("sshd " + action + " completed");
            });
        }

        private void TestLiveConfig()
        {
            var r = Bg("Running sshd -t...", () => Ssh.TestConfig(null));
            MessageBox.Show(this, r.Ok ? "sshd -t reports no problems with\n" + Ssh.ConfigPath : "sshd -t reported:\n\n" + r.Output, Program.AppName, MessageBoxButtons.OK, r.Ok ? MessageBoxIcon.Information : MessageBoxIcon.Warning);
        }

        private void GenerateHostKeys()
        {
            var o = Bg("Generating host keys...", () => HostKeys.GenerateMissing());
            RefreshDashboard(); Status("ssh-keygen -A: " + (o.Length == 0 ? "done" : o));
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
            bar.Controls.Add(new Label { AutoSize = true, Margin = new Padding(12, 10, 4, 4), ForeColor = Theme.Muted, Text = "Each connection runs as an sshd-session.exe process: one owned by SYSTEM before login, then one owned by the user. Refreshes every 5 seconds." });
            root.Controls.Add(bar, 0, 1);
            var split = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal };
            bool splitInit = false;
            split.SizeChanged += (s, e) => { if (splitInit || split.Height < Ui.Px(300)) return; splitInit = true; try { split.SplitterDistance = split.Height * 62 / 100; } catch { } };
            var sessBox = new GroupBox { Text = "Session processes (sshd-session.exe)", Dock = DockStyle.Fill, Padding = new Padding(6) };
            _lvSessions = Lv("PID|80", "User|260", "Started|160", "Duration|100", "Role|200"); _lvSessions.AccessibleName = "Session processes";
            _lvSessions.MultiSelect = true; // "Disconnect selected" ends every selected session
            _lvSessions.KeyDown += (s, e) => { if (e.KeyCode == System.Windows.Forms.Keys.Delete) { e.Handled = true; Safe(() => DisconnectSessions(false)); } };
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
            var cfg = _cfg;
            ShowSessions(Bg("Reading sessions...", () => CollectSessions(cfg)));
        }

        private void ShowSessions(SessionsData data)
        {
            var list = data.List;
            var selected = new HashSet<int>(_lvSessions.SelectedItems.Cast<ListViewItem>().Select(i => (int)i.Tag));
            _lvSessions.BeginUpdate(); _lvSessions.Items.Clear();
            foreach (var s in list)
            {
                bool system = s.User.IndexOf("SYSTEM", StringComparison.OrdinalIgnoreCase) >= 0;
                var ts = s.Start == DateTime.MinValue ? TimeSpan.Zero : DateTime.Now - s.Start;
                if (ts < TimeSpan.Zero) ts = TimeSpan.Zero;
                var dur = s.Start == DateTime.MinValue ? "" : ((int)ts.TotalHours).ToString("00") + ":" + ts.Minutes.ToString("00") + ":" + ts.Seconds.ToString("00");
                var it = new ListViewItem(new[] { s.Pid == 0 ? "" : s.Pid.ToString(), s.User, s.Start == DateTime.MinValue ? "" : s.Start.ToString("yyyy-MM-dd HH:mm:ss"), dur, s.Pid == 0 ? "" : (system ? "privileged monitor (pre-login or supervisor)" : "user session") }) { Tag = s.Pid };
                if (system) it.ForeColor = Theme.Faint;
                if (selected.Contains(s.Pid)) it.Selected = true;
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
            bar.Controls.Add(Btn("Save", (s, e) => Safe(() => SaveSettings(false)), 110));
            bar.Controls.Add(Btn("Save and restart sshd", (s, e) => Safe(() => SaveSettings(true)), 180));
            bar.Controls.Add(Btn("Reload from file", (s, e) => Safe(() => ReloadFromFile(true, false)), 140));
            bar.Controls.Add(Btn("Backups...", (s, e) => Safe(RestoreBackup), 110));
            bar.Controls.Add(Btn("Reset to shipped defaults", (s, e) => Safe(ResetToDefault), 190));
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
        private void LoadSettings(bool keepEdits = false)
        {
            Dictionary<string, string> eff;
            try { eff = Bg("Reading the effective settings (sshd -T)...", () => Ssh.EffectiveSettings()); } catch { eff = new Dictionary<string, string>(); }
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
            var backup = SaveConfig(cand, changed.Count == 0 ? "Save the settings of the Settings tab." : "Save " + string.Join(", ", changed.Select(f => f.Label)) + ".", restart ? "Save and restart" : "Save");
            // The window adopts the saved file first, so that nothing below can leave it with the old file's state.
            UseConfig(cand, false, true);
            // The registry value is written only when it changed (HKLM\SOFTWARE\OpenSSH\DefaultShell applies to new sessions at once).
            bool optionChanged = _txtShellOption.Text.Trim() != (DefaultShell.GetOption() ?? "").Trim();
            if (shellChanged || optionChanged) { try { DefaultShell.Set(shell, _txtShellOption.Text); } catch (Exception ex) { Log.Error("sshd_config was saved, but the default shell could not be set", ex, true); } }
            ReportOverridden(changed);
            var firewallBack = OpenFirewallForPort(_cfg.EffectivePort);
            if (restart)
            {
                if (RestartWithRollback(backup, firewallBack == null ? null : firewallBack.Undo) && firewallBack != null) firewallBack.Keep();
            }
            else Status("Saved. Restart sshd to apply (default shell applies immediately)." + (firewallBack != null ? " The firewall allows the old and the new port until then." : ""));
        }

        /// <summary>A change to the firewall rule that goes with a change of sshd's port: undone with the settings, or finished when they are kept.</summary>
        private sealed class FirewallChange { public Action Undo; public Action Keep; }

        /// <summary>
        /// When the firewall rule does not admit the port sshd will listen on, asks to add it. The rule keeps its old ports
        /// meanwhile, so sshd stays reachable whether the new settings are kept or not. Returns how to undo the change (a
        /// restart that is rolled back) and how to finish it (the new settings are kept: a rule that had a single port then
        /// drops the old one when sshd no longer uses it), or null when nothing changed.
        /// </summary>
        private FirewallChange OpenFirewallForPort(int port)
        {
            if (Program.Unattended) return null;
            var fw = Bg("Reading the firewall rule...", () => Firewall.Get());
            if (fw == null || Firewall.Covers(fw.Ports, port)) return null;
            bool single = Firewall.IsSinglePort(fw.Ports);
            var question = "The firewall rule allows port" + (single ? " " : "s ") + fw.Ports + " but not " + port + ", the port sshd will listen on.\n\nAdd port " + port + " to the rule?" +
                           (single ? " Port " + fw.Ports + " stays open until the new settings are kept after the restart, so you can still connect if they are not." : "");
            if (MessageBox.Show(this, question, Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return null;
            var before = fw;
            Firewall.Apply(fw.Enabled, fw.Profiles, fw.Ports + "," + port); LoadFirewall();
            Log.Info("Firewall rule: port " + port + " added to " + before.Ports);
            return new FirewallChange
            {
                Undo = () => { Firewall.Apply(before.Enabled, before.Profiles, before.Ports); Log.Info("Firewall rule: ports back to " + before.Ports); },
                Keep = () =>
                {
                    if (!single) return;
                    int old; int.TryParse(before.Ports, out old);
                    if (_cfg.GetAll("Port").Any(p => p.Value.Trim() == before.Ports) || _cfg.GetAll("ListenAddress").Any(la => SshdConfig.ListenPort(la.Value) == old)) return;
                    Firewall.Apply(before.Enabled, before.Profiles, port.ToString()); LoadFirewall();
                    Status("New settings kept; the firewall rule now allows port " + port + " only (port " + before.Ports + " closed)");
                    Log.Info("Firewall rule: old port " + before.Ports + " closed, " + port + " kept");
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
        private string SaveConfig(SshdConfig cand, string what, string okText = "Save")
        {
            var access = Bg("Checking that you can still log in with the new settings...", () =>
            {
                var tmp = WriteCandidate(cand);
                try { return AuthConfig.AccessWarning(tmp, cand.EffectivePort); } finally { try { File.Delete(tmp); } catch { } }
            });
            if (access != null && !Program.Unattended &&
                MessageBox.Show(this, "Warning: " + access + "\n\nOpen sessions stay connected, but new logins of your account would fail. Save anyway?", Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes)
                throw new OperationCanceledException();
            if (!ConfirmChanges(cand, what, okText)) throw new OperationCanceledException();
            try { return Bg("Checking with sshd -t and saving...", () => cand.SaveValidated()); }
            catch (ConfigChangedException)
            {
                if (Program.Unattended) throw;
                var answer = MessageBox.Show(this, "sshd_config was changed by another program (or in Notepad) after this window read it.\n\n" +
                    "Yes: save anyway; the file as it is now is kept as a backup.\nNo: save nothing, so you can reload the file and make your change again.",
                    Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2);
                if (answer != DialogResult.Yes) throw new OperationCanceledException();
                return Bg("Saving...", () => cand.SaveValidated(true));
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
            var ports = ExpectedPorts(cfg);
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
                var fw = Firewall.Get();
                var blocked = fw == null ? ports : ports.Where(p => !Firewall.Covers(fw.Ports, p)).ToList();
                if (fw == null) { lines.Add("There is no inbound firewall rule for sshd: other computers cannot connect."); problems = true; }
                else if (!fw.Enabled) { lines.Add("The firewall rule for sshd is disabled: other computers cannot connect."); problems = true; }
                else if (blocked.Count > 0) { lines.Add("The firewall rule allows port " + fw.Ports + " but not " + string.Join(", ", blocked) + ": other computers cannot connect there."); problems = true; }
            }
            catch (Exception ex) { lines.Add("Firewall not checked: " + ex.Message); }
            try
            {
                var access = AuthConfig.AccessWarning(null, ports[0]);
                if (access != null) { lines.Add(access); problems = true; }
                string err; var me = Accounts.AsciiLower(KeyGen.LoginName());
                var offered = AuthConfig.Probe(me, "localhost", ports[0], out err);
                if (offered != null) lines.Add("It offers " + me + " (you): " + AuthConfig.MethodNames(offered) + ".");
            }
            catch (Exception ex) { Log.Error("Checking the login methods after a restart", ex, false); }
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
            SshdConfig.WriteReplacing(Ssh.ConfigPath, File.ReadAllText(backup, Encoding.UTF8));
            Log.Info("Restored " + backup + " to " + Ssh.ConfigPath + (kept != null ? " (the replaced file is kept as " + kept + ")" : ""));
            return kept;
        }

        /// <summary>When sshd was restarted or started by this window (or a stop is expected): no "sshd stopped" notification then.</summary>
        private DateTime _expectedStateChange = DateTime.MinValue;

        /// <summary>
        /// Restarts sshd with the saved configuration. When it does not start, the previous file (backup) goes back and sshd
        /// starts again, without a question. When it starts, the server is checked (listening, answering, firewall, your
        /// access) and, unless switched off, you are asked to keep the new settings; without an answer in time, or with
        /// "Restore", the previous file goes back. True when sshd runs the new configuration.
        /// </summary>
        private bool RestartWithRollback(string backup, Action undo = null)
        {
            _expectedStateChange = DateTime.UtcNow;
            var failure = Bg("Restarting sshd...", () => { try { Services.Restart("sshd"); return (Exception)null; } catch (Exception ex) { return ex; } });
            _expectedStateChange = DateTime.UtcNow;
            if (failure != null)
            {
                if (backup == null || !File.Exists(backup)) { RefreshDashboard(); throw failure; }
                string kept = null; Exception again = null;
                Bg("sshd did not start: restoring the previous configuration...", () =>
                {
                    kept = RestoreFile(backup);
                    if (undo != null) { try { undo(); } catch (Exception ex) { Log.Error("Undoing the change that went with the new settings", ex, false); } }
                    try { Services.Start("sshd"); } catch (Exception ex) { again = ex; }
                });
                _expectedStateChange = DateTime.UtcNow;
                UseConfig(SshdConfig.Load()); RefreshDashboard(); if (undo != null) LoadFirewall();
                Status(again == null ? "sshd did not start with the new configuration; the previous one was restored and sshd runs" : "sshd did not start, not even with the previous configuration");
                if (!Program.Unattended)
                    MessageBox.Show(this, "sshd did not start with the new configuration:\n" + failure.Message + "\n\n" +
                        (again == null ? "The previous sshd_config was restored and sshd started again." : "The previous sshd_config was restored, but sshd did not start either: " + again.Message + "\nSee the Logs tab.") +
                        (kept != null ? "\n\nThe configuration that failed is kept as " + Path.GetFileName(kept) + " (Settings tab, Backups)." : ""),
                        Program.AppName, MessageBoxButtons.OK, MessageBoxIcon.Error);
                return false;
            }
            var cfg = _cfg;
            var check = Bg("Checking the restarted server...", () => CheckServer(cfg));
            LoadSettings(true); RefreshDashboard(); // the effective values after the restart
            Status(check.Summary);
            if (backup == null || !File.Exists(backup) || Program.Unattended || !Prefs.ConfirmAfterRestart) return true;
            DialogResult answer;
            using (var d = new KeepSettingsDialog(check.Text, check.Problems, Prefs.ConfirmSeconds, () => { var c = Bg("Checking...", () => CheckServer(cfg)); return new KeyValuePair<string, bool>(c.Text, c.Problems); }))
                answer = d.ShowDialog(this);
            if (answer == DialogResult.OK) { Status("New settings kept. " + check.Summary); Log.Info("New settings kept after the restart"); return true; }
            Exception startError = null; string replaced = null;
            Bg("Restoring the previous settings...", () =>
            {
                replaced = RestoreFile(backup);
                if (undo != null) { try { undo(); } catch (Exception ex) { Log.Error("Undoing the change that went with the new settings", ex, false); } }
                try { Services.Restart("sshd"); } catch (Exception ex) { startError = ex; }
            });
            _expectedStateChange = DateTime.UtcNow;
            UseConfig(SshdConfig.Load()); RefreshDashboard(); if (undo != null) LoadFirewall();
            Log.Info("The previous settings were restored after the restart (" + (answer == DialogResult.Abort ? "no answer or Restore" : answer.ToString()) + ")");
            Status(startError == null ? "The previous settings were restored and sshd restarted" : "The previous settings were restored, but sshd did not start: " + startError.Message);
            MessageBox.Show(this, (startError == null ? "The previous settings were restored and sshd restarted with them." : "The previous settings were restored, but sshd did not start: " + startError.Message) +
                (replaced != null ? "\n\nThe new settings are kept as " + Path.GetFileName(replaced) + " (Settings tab, Backups), in case you want them back." : ""),
                Program.AppName, MessageBoxButtons.OK, startError == null ? MessageBoxIcon.Information : MessageBoxIcon.Error);
            return false;
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
            string chosen;
            var current = File.Exists(Ssh.ConfigPath) ? File.ReadAllText(Ssh.ConfigPath) : "";
            using (var dlg = new BackupsDialog(Ssh.ConfigPath, current))
            {
                if (dlg.ShowDialog(this) != DialogResult.OK || dlg.Chosen == null) return;
                chosen = dlg.Chosen;
            }
            var cand = SshdConfig.Load(chosen); cand.Path = Ssh.ConfigPath; cand.LoadedHash = _cfg.LoadedHash;
            var backup = SaveConfig(cand, "Restore the backup " + Path.GetFileName(chosen) + ".", "Restore");
            UseConfig(SshdConfig.Load());
            if (MessageBox.Show(this, "Backup restored (previous file saved as " + (backup == null ? "none" : Path.GetFileName(backup)) + "). Restart sshd now?", Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes) RestartWithRollback(backup);
        }

        private void ResetToDefault()
        {
            if (!File.Exists(Ssh.DefaultConfigPath)) throw new Exception("sshd_config_default not found in " + Ssh.InstallDir);
            var cand = SshdConfig.Load(Ssh.DefaultConfigPath); cand.Path = Ssh.ConfigPath; cand.LoadedHash = _cfg.LoadedHash;
            if (!Prefs.PreviewChanges && MessageBox.Show(this, "Replace sshd_config with the shipped sshd_config_default? Your current file is backed up first.", Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;
            var backup = SaveConfig(cand, "Replace sshd_config with the shipped sshd_config_default: every setting and rule made here is removed.", "Replace");
            UseConfig(SshdConfig.Load());
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
            var btnShow = Btn("Show its login methods", (s, e) => Safe(() => CheckAccount(false)), 190);
            var btnAsk = Btn("Ask the running server", (s, e) => Safe(() => CheckAccount(true)), 190);
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

        private void ApplyAuth()
        {
            var global = AuthFromUi();
            var cand = AuthCandidate();
            string warning = null; RunResult t = null;
            var tmp = WriteCandidate(cand);
            try
            {
                Bg("Checking the new settings with sshd...", () =>
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
            var backup = SaveConfig(cand, "Apply the login methods of the Authentication tab.", "Apply");
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
            Bg("Asking the running server which login methods it offers...", () =>
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
                Bg("Asking the running server...", () => offered = AuthConfig.Probe(name, "localhost", port, out err));
                if (offered == null) { SetAuthResult("The running server gave no list of methods for " + name + ": " + err, Red); return; }
                SetAuthResult("The running server offers " + name + ": " + AuthConfig.MethodNames(offered) + "." + (_auPending.Text.Length > 0 ? " Changes on this tab count only after Apply." : ""), Theme.Text);
                return;
            }
            var tmp = WriteCandidate(AuthCandidate());
            Dictionary<string, string> d = null;
            try { Bg("Asking sshd...", () => d = AuthConfig.EffectiveSettingsFor(name, tmp, port, out err)); }
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
            SetAuthResult(sb.ToString(), Theme.Text);
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
            bar.Controls.Add(Btn("Validate", (s, e) => Safe(() =>
            {
                var c = FromEditor(); var tmp = WriteCandidate(c);
                try { var r = Bg("Running sshd -t...", () => Ssh.TestConfig(tmp)); MessageBox.Show(this, r.Ok ? "No problems found." : r.Output.Replace(tmp, "sshd_config"), Program.AppName, MessageBoxButtons.OK, r.Ok ? MessageBoxIcon.Information : MessageBoxIcon.Warning); }
                finally { try { File.Delete(tmp); } catch { } }
            }), 110));
            // The editor text becomes the working configuration only after sshd accepted it; a rejected text must not
            // replace the configuration the Settings tab works on.
            bar.Controls.Add(Btn("Save", (s, e) => Safe(() => SaveRaw()), 110));
            bar.Controls.Add(Btn("Save and restart sshd", (s, e) => Safe(() => { var b = SaveRaw(); RestartWithRollback(b); }), 180));
            bar.Controls.Add(Btn("Reload", (s, e) => Safe(() => ReloadFromFile(false, true)), 100));
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
        private string SaveRaw()
        {
            var c = FromEditor();
            var b = SaveConfig(c, "Save the text of the sshd_config (text) tab.");
            UseConfig(c, true, false);
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
            _lvAdminKeys.KeyDown += (s, e) => { if (e.KeyCode == System.Windows.Forms.Keys.Delete) { e.Handled = true; Safe(() => RemoveKey(true)); } };
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
            _lvUserKeys.KeyDown += (s, e) => { if (e.KeyCode == System.Windows.Forms.Keys.Delete) { e.Handled = true; Safe(() => RemoveKey(false)); } };
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
        private void FillKeyList(ListView lv, string path)
        {
            var keys = Bg("Reading " + Path.GetFileName(path) + "...", () => Keys.Read(path)); // ssh-keygen -l for keys not seen before
            lv.BeginUpdate(); lv.Items.Clear();
            foreach (var k in keys) lv.Items.Add(new ListViewItem(new[] { k.Type, k.Comment, k.Fingerprint, k.Options }) { Tag = k.Line });
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

            _kgResult = new Label { AutoSize = true, Margin = new Padding(6, 6, 6, 2), MaximumSize = new Size(Ui.Px(980), 0), ForeColor = Theme.Muted, Text = "The public key appears below after generation." };
            root.Controls.Add(_kgResult, 0, 2);
            _kgPublic = new TextBox { Multiline = true, ReadOnly = true, WordWrap = true, ScrollBars = ScrollBars.Vertical, Dock = DockStyle.Fill, Font = new Font("Consolas", Ui.Pt(9.5f)) };
            _kgPublic.AccessibleName = "Public key"; root.Controls.Add(_kgPublic, 0, 3);
            root.Controls.Add(new Label
            {
                AutoSize = true, ForeColor = Theme.Muted, Margin = new Padding(6), MaximumSize = new Size(Ui.Px(980), 0),
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
            var comment = _kgComment.Text.Trim(); // read here: the work below runs on another thread
            try { Bg("Generating " + type.Label + " key...", () => res = KeyGen.GenerateReplacing(type, path, comment, pass, now)); }
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
            var backup = SaveConfig(cand, "Accept the experimental key type " + t.PublicType + ".", "Save and restart");
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
            try { Bg("Logging in to this server with " + Path.GetFileName(path) + "...", () => r = KeyGen.TestLogin(path, pass, port)); }
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

        // ---------------- Client (the ssh client of this account) ----------------
        private ListView _lvKnownHosts, _lvClientHosts, _lvAgentKeys; private Label _lblAgent2; private bool _clientLoaded;
        private List<ClientHost> _clientHosts = new List<ClientHost>();

        private TabPage BuildClient()
        {
            var page = new TabPage("Client");
            var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 4, Padding = new Padding(4) };
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize)); root.RowStyles.Add(new RowStyle(SizeType.Percent, 36)); root.RowStyles.Add(new RowStyle(SizeType.Percent, 34)); root.RowStyles.Add(new RowStyle(SizeType.Percent, 30));
            root.Controls.Add(new Label { AutoSize = true, ForeColor = Theme.Muted, MaximumSize = new Size(Ui.Px(980), 0), Margin = new Padding(6, 6, 4, 4), Text = "The ssh client of " + KeyGen.LoginName() + " (you), for connections from this computer to other servers: the hosts ssh knows, the host names of %USERPROFILE%\\.ssh\\config, and the keys in ssh-agent." }, 0, 0);

            var hostsBox = new GroupBox { Text = "Known hosts (" + SshClient.KnownHostsPath + ")", Dock = DockStyle.Fill, Padding = new Padding(6) };
            var hostsRoot = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2 };
            hostsRoot.RowStyles.Add(new RowStyle(SizeType.Percent, 100)); hostsRoot.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            _lvKnownHosts = Lv("Hosts|300", "Type|200", "SHA256 fingerprint|420", "Marker|110"); _lvKnownHosts.AccessibleName = "Known hosts"; _lvKnownHosts.MultiSelect = true;
            _lvKnownHosts.KeyDown += (s, e) => { if (e.KeyCode == System.Windows.Forms.Keys.Delete) { e.Handled = true; Safe(RemoveKnownHosts); } };
            hostsRoot.Controls.Add(_lvKnownHosts, 0, 0);
            var hb = Flow();
            hb.Controls.Add(Btn("Add a server's keys...", (s, e) => Safe(AddKnownHost), 180));
            hb.Controls.Add(Btn("Remove selected", (s, e) => Safe(RemoveKnownHosts), 140));
            hb.Controls.Add(Btn("Open in Notepad", (s, e) => Proc.OpenExternal("notepad.exe", "\"" + SshClient.KnownHostsPath + "\""), 140));
            _tips.SetToolTip(hb.Controls[0], "Reads the host keys a server offers (ssh-keyscan) and adds them after you compared the fingerprints, so the first connection is not a blind trust-on-first-use.");
            hostsRoot.Controls.Add(hb, 0, 1);
            hostsBox.Controls.Add(hostsRoot);
            root.Controls.Add(hostsBox, 0, 1);

            var cfgBox = new GroupBox { Text = "Hosts in " + SshClient.ConfigPath, Dock = DockStyle.Fill, Padding = new Padding(6) };
            var cfgRoot = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2 };
            cfgRoot.RowStyles.Add(new RowStyle(SizeType.Percent, 100)); cfgRoot.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            _lvClientHosts = Lv("Host|180", "Host name|220", "User|140", "Port|60", "Key file|260", "Jump host|140"); _lvClientHosts.AccessibleName = "Hosts of the ssh client configuration";
            ListSorter.Disable(_lvClientHosts); // ssh takes the first matching block: the order matters
            _lvClientHosts.ItemActivate += (s, e) => Safe(EditClientHost);
            _lvClientHosts.KeyDown += (s, e) => { if (e.KeyCode == System.Windows.Forms.Keys.Delete) { e.Handled = true; Safe(RemoveClientHost); } };
            cfgRoot.Controls.Add(_lvClientHosts, 0, 0);
            var cb = Flow();
            cb.Controls.Add(Btn("Add...", (s, e) => Safe(AddClientHost), 90));
            cb.Controls.Add(Btn("Edit...", (s, e) => Safe(EditClientHost), 90));
            cb.Controls.Add(Btn("Remove", (s, e) => Safe(RemoveClientHost), 90));
            cb.Controls.Add(Btn("Connect", (s, e) => Safe(() => { if (_lvClientHosts.SelectedItems.Count > 0) { var h = (ClientHost)_lvClientHosts.SelectedItems[0].Tag; if (!h.IsMatch && Regex.IsMatch(h.Pattern, @"^[A-Za-z0-9._@%+:\[\]][A-Za-z0-9._@%+:\[\]\-]*$")) Proc.OpenUnelevated(Ssh.Exe("ssh.exe"), "-- " + h.Pattern); else Status("Choose a host with a single plain name (no wildcards, spaces or leading -)"); } }), 100));
            cb.Controls.Add(Btn("Open in Notepad", (s, e) => Proc.OpenExternal("notepad.exe", "\"" + SshClient.ConfigPath + "\""), 140));
            cfgRoot.Controls.Add(cb, 0, 1);
            cfgBox.Controls.Add(cfgRoot);
            root.Controls.Add(cfgBox, 0, 2);

            var agentBox = new GroupBox { Text = "ssh-agent (keys it holds for your connections)", Dock = DockStyle.Fill, Padding = new Padding(6) };
            var agentRoot = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 3 };
            agentRoot.RowStyles.Add(new RowStyle(SizeType.AutoSize)); agentRoot.RowStyles.Add(new RowStyle(SizeType.Percent, 100)); agentRoot.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            _lblAgent2 = new Label { AutoSize = true, Margin = new Padding(4, 4, 4, 4) };
            agentRoot.Controls.Add(_lblAgent2, 0, 0);
            _lvAgentKeys = Lv("Type|230", "Comment|260", "SHA256 fingerprint|420"); _lvAgentKeys.AccessibleName = "Keys in ssh-agent";
            _lvAgentKeys.KeyDown += (s, e) => { if (e.KeyCode == System.Windows.Forms.Keys.Delete) { e.Handled = true; Safe(RemoveAgentKey); } };
            agentRoot.Controls.Add(_lvAgentKeys, 0, 1);
            var ab = Flow();
            ab.Controls.Add(Btn("Add a key...", (s, e) => Safe(AddAgentKey), 110));
            ab.Controls.Add(Btn("Remove selected", (s, e) => Safe(RemoveAgentKey), 140));
            ab.Controls.Add(Btn("Start the agent", (s, e) => Safe(() =>
            {
                if (MessageBox.Show(this, "Set the ssh-agent service to start automatically and start it now?", Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
                Bg("Starting ssh-agent...", () => { Services.SetStartMode("ssh-agent", "auto"); Services.Start("ssh-agent"); });
                LoadClient();
            }), 130));
            agentRoot.Controls.Add(ab, 0, 2);
            agentBox.Controls.Add(agentRoot);
            root.Controls.Add(agentBox, 0, 3);
            page.Controls.Add(root);
            return page;
        }

        private void LoadClient()
        {
            _clientLoaded = true;
            string agentMessage = null;
            var data = Bg("Reading the ssh client files and the agent...", () => new
            {
                Known = SshClient.ReadKnownHosts(SshClient.KnownHostsPath),
                Config = File.Exists(SshClient.ConfigPath) ? File.ReadAllLines(SshClient.ConfigPath).ToList() : new List<string>(),
                Agent = Services.Status("ssh-agent"),
                Keys = SshClient.AgentKeys(out agentMessage).Select(Keys.Parse).ToList(),
            });
            _lvKnownHosts.BeginUpdate(); _lvKnownHosts.Items.Clear();
            foreach (var k in data.Known) _lvKnownHosts.Items.Add(new ListViewItem(new[] { k.Hashed ? "(hashed name)" : k.Hosts, k.Type, k.Fingerprint ?? "", k.Marker }) { Tag = k });
            _lvKnownHosts.EndUpdate();
            _clientHosts = SshClient.ParseConfig(data.Config);
            _lvClientHosts.BeginUpdate(); _lvClientHosts.Items.Clear();
            foreach (var h in _clientHosts) _lvClientHosts.Items.Add(new ListViewItem(new[] { h.Pattern, h.Get("HostName"), h.Get("User"), h.Get("Port"), h.Get("IdentityFile"), h.Get("ProxyJump") }) { Tag = h });
            _lvClientHosts.EndUpdate();
            _lblAgent2.Text = "ssh-agent service: " + data.Agent.Status + ", start " + data.Agent.StartMode + (agentMessage != null && data.Agent.Status == "Running" ? ". " + agentMessage : "");
            _lblAgent2.ForeColor = data.Agent.Status == "Running" ? Green : Orange;
            _lvAgentKeys.BeginUpdate(); _lvAgentKeys.Items.Clear();
            foreach (var k in data.Keys) _lvAgentKeys.Items.Add(new ListViewItem(new[] { k.Type, k.Comment, k.Fingerprint }) { Tag = k.Line });
            _lvAgentKeys.EndUpdate();
            Status(data.Known.Count + " known host key(s), " + _clientHosts.Count + " host block(s), " + data.Keys.Count + " key(s) in the agent");
        }

        private void RemoveKnownHosts()
        {
            var sel = _lvKnownHosts.SelectedItems.Cast<ListViewItem>().Select(i => (KnownHost)i.Tag).ToList();
            if (sel.Count == 0) { Status("Select one or more known hosts first"); return; }
            if (MessageBox.Show(this, "Remove " + sel.Count + " known host key(s)?\n\n" + string.Join("\n", sel.Take(10).Select(k => (k.Hashed ? "(hashed name)" : k.Hosts) + "  " + k.Type)) + "\n\nssh asks again the next time it connects to such a host. The previous file is kept as known_hosts.old.", Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
            int n = SshClient.RemoveLines(SshClient.KnownHostsPath, new HashSet<int>(sel.Select(k => k.Line)));
            LoadClient(); Status(n + " known host key(s) removed");
        }

        private void AddKnownHost()
        {
            string input;
            using (var d = new InputDialog("Add a server's host keys", "Server name or address, optionally with :port (for example server.example.com or 192.168.1.10:2222):", "")) { if (d.ShowDialog(this) != DialogResult.OK) return; input = d.Value; }
            // name, name:port, IPv6 address, [IPv6 address]:port
            int port = 22; var host = input;
            var m = input.StartsWith("[") ? Regex.Match(input, @"^\[([^\]]+)\](?::(\d{1,5}))?$") : input.Count(c => c == ':') == 1 ? Regex.Match(input, @"^([^:]+):(\d{1,5})$") : Match.Empty;
            if (m.Success) { host = m.Groups[1].Value; if (m.Groups[2].Success) port = int.Parse(m.Groups[2].Value); }
            host = SshClient.CheckHostName(host);
            if (host == null || port < 1 || port > 65535) throw new ConfigException("\"" + input + "\" is not a host name or address.");
            var r = Bg("Asking " + host + " for its host keys (ssh-keyscan)...", () => SshClient.Scan(host, port));
            var lines = r.StdOut.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).Where(l => !l.StartsWith("#") && SshClient.ParseKnownHost(l) != null).ToList();
            if (lines.Count == 0) throw new ConfigException("No host keys from " + host + " port " + port + ".\n\n" + r.Output);
            var fps = Bg("Working out the fingerprints...", () => lines.Select(l => { var k = SshClient.ParseKnownHost(l); var parts = l.Split(' '); return k.Type + "  " + Keys.Fingerprint(k.Type + " " + parts[2]); }).ToList());
            if (MessageBox.Show(this, host + " port " + port + " offers these host keys:\n\n" + string.Join("\n", fps) +
                "\n\nCompare them with the fingerprints the server's administrator gives you (on that server: ssh-keygen -lf on its host keys, or the Dashboard of OpenSSH Server Manager). Add them to your known_hosts only when they match.\n\nAdd them?",
                Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Question, MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;
            Directory.CreateDirectory(KeyGen.SshDir);
            var existing = File.Exists(SshClient.KnownHostsPath) ? File.ReadAllText(SshClient.KnownHostsPath) : "";
            File.AppendAllText(SshClient.KnownHostsPath, (existing.Length > 0 && !existing.EndsWith("\n") ? "\n" : "") + string.Join("\n", lines) + "\n", new UTF8Encoding(false));
            LoadClient(); Status(lines.Count + " host key(s) of " + host + " added to known_hosts");
        }

        private List<string> ClientConfigLines() { return File.Exists(SshClient.ConfigPath) ? File.ReadAllLines(SshClient.ConfigPath).ToList() : new List<string>(); }

        private void AddClientHost()
        {
            using (var d = new ClientHostDialog(null))
            {
                if (d.ShowDialog(this) != DialogResult.OK) return;
                SshClient.WriteConfig(SshClient.WithHost(ClientConfigLines(), null, d.Pattern, d.Values));
            }
            LoadClient(); Status("Host added to " + SshClient.ConfigPath);
        }

        private void EditClientHost()
        {
            if (_lvClientHosts.SelectedItems.Count == 0) { Status("Select a host first"); return; }
            var h = (ClientHost)_lvClientHosts.SelectedItems[0].Tag;
            if (h.IsMatch) { Status("Match blocks are edited in Notepad"); return; }
            var lines = ClientConfigLines();
            var fresh = SshClient.ParseConfig(lines).FirstOrDefault(x => x.First == h.First && x.Pattern == h.Pattern);
            if (fresh == null) { LoadClient(); throw new ConfigException("The file changed meanwhile; it was read again. Choose the host again."); }
            using (var d = new ClientHostDialog(fresh))
            {
                if (d.ShowDialog(this) != DialogResult.OK) return;
                SshClient.WriteConfig(SshClient.WithHost(lines, fresh, d.Pattern, d.Values));
            }
            LoadClient(); Status("Host saved in " + SshClient.ConfigPath);
        }

        private void RemoveClientHost()
        {
            if (_lvClientHosts.SelectedItems.Count == 0) { Status("Select a host first"); return; }
            var h = (ClientHost)_lvClientHosts.SelectedItems[0].Tag;
            if (MessageBox.Show(this, "Remove \"" + h.Pattern + "\" and its settings from " + SshClient.ConfigPath + "? The previous file is kept as config.bak.", Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
            var lines = ClientConfigLines();
            var fresh = SshClient.ParseConfig(lines).FirstOrDefault(x => x.First == h.First && x.Pattern == h.Pattern);
            if (fresh == null) { LoadClient(); throw new ConfigException("The file changed meanwhile; it was read again. Choose the host again."); }
            SshClient.WriteConfig(SshClient.WithoutHost(lines, fresh));
            LoadClient(); Status("Host removed");
        }

        private void AddAgentKey()
        {
            string path;
            using (var dlg = new OpenFileDialog { Title = "Choose a private key (not the .pub file)", InitialDirectory = KeyGen.SshDir, Filter = "Private keys|id_*;*.key;*|All files|*.*" })
            {
                if (dlg.ShowDialog(this) != DialogResult.OK) return;
                path = dlg.FileName;
            }
            if (path.EndsWith(".pub", StringComparison.OrdinalIgnoreCase)) throw new ConfigException("That is the public key. Choose the private key file (the same name without .pub).");
            string pass = null;
            if (KeyGen.IsEncrypted(path)) using (var d = new PasswordDialog("Passphrase for " + Path.GetFileName(path))) { if (d.ShowDialog(this) != DialogResult.OK) return; pass = d.Value; }
            RunResult r;
            try { r = Bg("Adding the key to ssh-agent...", () => SshClient.AgentAdd(path, pass)); }
            finally { pass = null; }
            LoadClient();
            if (!r.Ok) throw new ConfigException("ssh-add did not add the key:\n\n" + r.Output);
            Status("Key added to ssh-agent");
        }

        private void RemoveAgentKey()
        {
            if (_lvAgentKeys.SelectedItems.Count == 0) { Status("Select a key first"); return; }
            var line = (string)_lvAgentKeys.SelectedItems[0].Tag;
            var r = Bg("Removing the key from ssh-agent...", () => SshClient.AgentRemove(line));
            LoadClient();
            if (!r.Ok) throw new ConfigException("ssh-add -d did not remove the key:\n\n" + r.Output);
            Status("Key removed from ssh-agent");
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
            bar.Controls.Add(Btn("Apply", (s, e) => Safe(ApplyFirewall), 110));
            _tips.SetToolTip(bar.Controls[0], "Ctrl+S");
            bar.Controls.Add(Btn("Use sshd port", (s, e) => Safe(() => { _fwPort.Value = _cfg.EffectivePort; }), 120));
            bar.Controls.Add(Btn("Remove rule", (s, e) => Safe(() => { if (MessageBox.Show(this, "Remove the inbound firewall rule for sshd? Remote clients will no longer reach the server.", Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Warning) == DialogResult.Yes) { Firewall.Remove(); LoadFirewall(); } }), 120));
            bar.Controls.Add(Btn("Windows Firewall console", (s, e) => Proc.OpenExternal("wf.msc"), 190));
            flow.Controls.Add(bar);
            flow.Controls.Add(new Label { AutoSize = true, ForeColor = Theme.Muted, Margin = new Padding(4, 12, 4, 4), MaximumSize = new Size(Ui.Px(800), 0), Text = "The rule is scoped to sshd.exe. Domain-joined Windows Servers use the Domain profile; laptops on untrusted networks use Public. Restrict remote addresses in the Windows Firewall console if the server must only be reachable from specific networks." });
            page.Controls.Add(flow);
            return page;
        }

        private void ApplyFirewall()
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
            // Taking sshd's own port away from the rule, or switching the rule off, cuts off remote clients: ask first.
            int sshdPort = _cfg == null ? 22 : _cfg.EffectivePort;
            if (!Program.Unattended && (!_fwEnabled.Checked || !Firewall.Covers(ports, sshdPort)) &&
                MessageBox.Show(this, (!_fwEnabled.Checked ? "The rule will be switched off" : "The rule will not allow port " + sshdPort + ", the port sshd listens on") + ": other computers can then no longer connect over SSH.\n\nApply anyway?", Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;
            Firewall.Apply(_fwEnabled.Checked, profiles, ports);
            LoadFirewall(); Status("Firewall rule updated");
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
            _txtFilter = new TextBox { Width = Ui.Px(200), Margin = new Padding(4, 6, 4, 4) }; _txtFilter.KeyDown += (s, e) => { if (e.KeyCode == System.Windows.Forms.Keys.Enter) { e.SuppressKeyPress = true; Safe(LoadLogs); } };
            _txtFilter.AccessibleName = "Event filter"; bar.Controls.Add(_txtFilter);
            _cmbPeriod = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = Ui.Px(130), Margin = new Padding(4, 6, 4, 4), AccessibleName = "Period" };
            _cmbPeriod.Items.AddRange(new object[] { "Last hour", "Last 24 hours", "Last 7 days", "Last 30 days", "All" }); _cmbPeriod.SelectedIndex = 1;
            _cmbPeriod.SelectedIndexChanged += (s, e) => { if (_lvEvents.Items.Count > 0) Safe(LoadLogs); };
            bar.Controls.Add(_cmbPeriod);
            bar.Controls.Add(Lbl("max:"));
            _numEvents = new NumericUpDown { Minimum = 50, Maximum = 20000, Value = 500, Increment = 50, Width = Ui.Px(80), Margin = new Padding(4, 6, 4, 4) }; _numEvents.AccessibleName = "Maximum number of events"; bar.Controls.Add(_numEvents);
            bar.Controls.Add(Btn("Refresh", (s, e) => Safe(LoadLogs), 100));
            bar.Controls.Add(Btn("Failed logins only", (s, e) => Safe(() => { _txtFilter.Text = "Failed"; LoadLogs(); }), 150));
            bar.Controls.Add(Btn("Accepted logins only", (s, e) => Safe(() => { _txtFilter.Text = "Accepted"; LoadLogs(); }), 160));
            bar.Controls.Add(Btn("Failed logins by address...", (s, e) => Safe(ShowFailedByAddress), 200));
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

        private void LoadLogs()
        {
            int max = (int)_numEvents.Value; var filter = _txtFilter.Text.Trim(); var period = LogPeriod();
            string fileText = null;
            var events = BgCancellable("Reading events (Cancel stops and shows what was read)...", token =>
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
        private void ShowFailedByAddress()
        {
            if (_events.Count == 0) LoadLogs();
            var sources = EventLogs.FailedByAddress(_events);
            var ports = _cfg == null ? "22" : string.Join(",", Enumerable.Repeat(_cfg.EffectivePort, 1).Concat(_cfg.GetAll("Port").Select(p => { int n; return int.TryParse(p.Value, out n) ? n : 0; }).Where(n => n > 0)).Distinct());
            using (var d = new FailedLoginsDialog(sources, _cmbPeriod.Text.ToLowerInvariant(), ports, Net.Sessions(_cfg == null ? 22 : _cfg.EffectivePort)))
                d.ShowDialog(this);
        }

        // ---------------- Hardening ----------------
        private TabPage BuildHardening()
        {
            var page = new TabPage("Hardening");
            var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2 };
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize)); root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            var bar = Flow();
            bar.Controls.Add(Btn("Run checks", (s, e) => Safe(RunChecks), 110));
            bar.Controls.Add(Btn("Fix selected...", (s, e) => Safe(FixSelectedChecks), 130));
            bar.Controls.Add(Btn("Apply recommended settings", (s, e) => Safe(ApplyRecommended), 210));
            bar.Controls.Add(Btn("Export report...", (s, e) => Safe(() => { var f = Export.SaveList(this, "OpenSSH hardening report", "openssh-hardening", "Hardening checks of " + Environment.MachineName + " (" + Ssh.ServerVersion() + "), " + DateTime.Now.ToString("yyyy-MM-dd HH:mm") + ", by " + Program.AppName + " " + Program.AppVersion + ".", _lvChecks, r => r.Count > 1 ? (r[1] == "OK" ? "ok" : r[1] == "WARN" ? "warn" : null) : null); if (f != null) Status("Exported to " + f); }), 140));
            _tips.SetToolTip(bar.Controls[1], "Fixes the selected warnings (double-click or Enter on one also works). Settings in sshd_config are shown before they are saved; login methods and login restrictions open their tab instead.");
            bar.Controls.Add(new Label { AutoSize = true, Margin = new Padding(12, 10, 4, 4), ForeColor = Theme.Muted, MaximumSize = new Size(Ui.Px(700), 0), Text = "Recommended: ClientAliveInterval 300, MaxAuthTries 4, LoginGraceTime 60, RequiredRSASize 2048, LogLevel VERBOSE, keyboard-interactive off, PerSourcePenalties on. Windows authentication and login restrictions are never changed automatically (see the Authentication and Settings tabs)." });
            root.Controls.Add(bar, 0, 0);
            _lvChecks = Lv("Check|220", "Status|70", "Detail|700"); _lvChecks.AccessibleName = "Hardening checks";
            _lvChecks.MultiSelect = true;
            _lvChecks.ItemActivate += (s, e) => Safe(FixSelectedChecks);
            root.Controls.Add(_lvChecks, 0, 1);
            page.Controls.Add(root);
            return page;
        }

        private void RunChecks()
        {
            var cfg = _cfg;
            var checks = Bg("Running checks...", () => Hardening.Run(cfg));
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

        /// <summary>Fixes the selected warnings: settings in one save (shown first) and one restart; other fixes one by one, each asked.</summary>
        private void FixSelectedChecks()
        {
            var selected = _lvChecks.SelectedItems.Cast<ListViewItem>().Select(i => i.Tag as CheckResult).Where(c => c != null && c.Status == "WARN").ToList();
            if (selected.Count == 0) { Status("Select one or more checks with WARN first"); return; }
            var cfgFixes = selected.Where(c => ConfigFix(c.Name) != null).ToList();
            foreach (var c in selected.Where(x => ConfigFix(x.Name) == null))
            {
                if (c.Name == "Password authentication") { _tabs.SelectedTab = _pgAuth; Status("Login methods are changed on the Authentication tab"); return; }
                if (c.Name == "Login restriction") { _tabs.SelectedTab = _pgSettings; _fields["AllowGroups"].Focus(); Status("Enter the groups allowed to log in (AllowGroups), for example administrators \"openssh users\""); return; }
                if (c.Name == "Firewall rule") { _tabs.SelectedTab = _pgFirewall; Status("Tick \"Inbound rule enabled\" and click Apply"); return; }
                if (c.Name == "sshd service")
                {
                    if (MessageBox.Show(this, "Set the sshd service to start automatically and start it now?", Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) continue;
                    _expectedStateChange = DateTime.UtcNow;
                    Bg("Starting sshd...", () => { Services.SetStartMode("sshd", "auto"); Services.Start("sshd"); });
                    continue;
                }
                if (c.Name == "Host keys") { GenerateHostKeys(); continue; }
                if (c.Name == "administrators_authorized_keys ACL")
                {
                    Bg("Fixing permissions...", () => { Acl.Restrict(Ssh.AdminKeysPath, null); Acl.EnsureOwner(Ssh.AdminKeysPath, null); });
                    LoadKeys(); continue;
                }
                if (c.Name == "Public network exposure")
                {
                    var fw = Firewall.Get(); if (fw == null) continue;
                    int profiles = fw.Profiles & 3; if ((fw.Profiles & 0x7fffffff) == 0x7fffffff) profiles = 3; if (profiles == 0) profiles = 3;
                    if (MessageBox.Show(this, "Limit the sshd firewall rule to the " + FirewallRule.ProfileText(profiles) + " profile(s)? Computers on a public network (a café, a hotel) can then no longer connect.", Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) continue;
                    Firewall.Apply(fw.Enabled, profiles, fw.Ports); LoadFirewall(); continue;
                }
                MessageBox.Show(this, c.Name + ": " + c.Detail + "\n\nThis cannot be fixed from here. Repair the package (msiexec /fa <package>.msi) or correct the permissions by hand.", Program.AppName, MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            if (cfgFixes.Count > 0)
            {
                var cand = _cfg.Copy();
                foreach (var c in cfgFixes) ConfigFix(c.Name)(cand);
                var b = SaveConfig(cand, "Fix: " + string.Join(", ", cfgFixes.Select(c => c.Name)) + ".", "Save and restart");
                UseConfig(cand);
                RestartWithRollback(b);
            }
            RunChecks();
        }

        private void ApplyRecommended()
        {
            if (MessageBox.Show(this, "Write these settings to sshd_config?\n\n  ClientAliveInterval 300\n  ClientAliveCountMax 3\n  MaxAuthTries 4\n  LoginGraceTime 60\n  RequiredRSASize 2048\n  LogLevel VERBOSE\n  KbdInteractiveAuthentication no (it has no Windows back end)\n  PerSourcePenalties (sshd default, enabled)\n\nA backup is created and the file is validated first. sshd is restarted afterwards.", Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
            var c = _cfg.Copy();
            c.Set("ClientAliveInterval", "300"); c.Set("ClientAliveCountMax", "3"); c.Set("MaxAuthTries", "4"); c.Set("LogLevel", "VERBOSE");
            c.Set("LoginGraceTime", "60"); c.Set("RequiredRSASize", "2048");
            c.Set("KbdInteractiveAuthentication", "no"); c.Set("ChallengeResponseAuthentication", "");
            if ((c.Get("PerSourcePenalties") ?? "").Equals("no", StringComparison.OrdinalIgnoreCase)) c.Set("PerSourcePenalties", "");
            var b = SaveConfig(c, "Apply the recommended settings.", "Save and restart"); UseConfig(c);
            RestartWithRollback(b); RunChecks();
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
            _trayMenu.Items.Add("Start sshd", null, (s, e) => { ShowFromTray(); ServiceAction("start"); });
            _trayMenu.Items.Add("Restart sshd", null, (s, e) => { ShowFromTray(); ServiceAction("restart"); });
            _trayMenu.Items.Add("Stop sshd", null, (s, e) => { ShowFromTray(); ServiceAction("stop"); });
            _trayMenu.Items.Add(new ToolStripSeparator());
            _trayMenu.Items.Add("Sessions", null, (s, e) => { ShowFromTray(); _tabs.SelectedTab = _pgSessions; });
            _trayMenu.Items.Add("Logs", null, (s, e) => { ShowFromTray(); _tabs.SelectedTab = _pgLogs; });
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
                    using (e.EventRecord) { try { msg = e.EventRecord.FormatDescription(); } catch { msg = null; } }
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
        private void OfferWizard()
        {
            if (Program.Unattended || Prefs.WizardOffered) return;
            Prefs.WizardOffered = true;
            if (MessageBox.Show(this, "Set up the SSH server now? A short wizard helps with the port and networks, a key for you, how accounts log in, and the recommended settings.\n\nYou can start it any time with \"Setup wizard...\" on the Dashboard.", Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes)
                RunWizard();
        }

        /// <summary>Keys authorized for the account running this program, in the file sshd reads for it.</summary>
        private static int MyKeyCount()
        {
            try
            {
                var file = Ssh.AuthorizedKeysFileFor(KeyGen.LoginName(), Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));
                if (file == null) file = Elevation.IsAdministrator() ? Ssh.AdminKeysPath : Keys.UserKeysPath(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));
                return Keys.Read(file).Count(k => k.Type != "?");
            }
            catch { return 0; }
        }

        private void RunWizard()
        {
            var fw = Bg("Reading the current settings...", () => Firewall.Get());
            string err; var allow = _cfg.GetCombinedArgs("AllowGroups", out err);
            WizardPlan plan;
            using (var w = new SetupWizard(_cfg.EffectivePort, fw, allow == null || allow.Count == 0 ? null : SshdArgs.FormatTyped(allow), () => Bg("Reading your keys...", () => MyKeyCount()), QuickAddMyKey))
            {
                if (w.ShowDialog(this) != DialogResult.OK) return;
                plan = w.Plan;
            }
            ApplyWizard(plan, fw);
        }

        /// <summary>Applies the wizard's plan: one save of sshd_config (with the preview and your-access check), the firewall rule, one restart with the keep-or-restore question.</summary>
        private void ApplyWizard(WizardPlan plan, FirewallRule fw)
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
            var fwProfiles = fw == null ? 0 : ((fw.Profiles & 0x7fffffff) == 0x7fffffff ? 7 : fw.Profiles & 7);
            var changes = plan.Describe(_cfg.EffectivePort, fwProfiles, fw != null);
            string backup = null;
            if (cand.Text != _cfg.Text)
            {
                backup = SaveConfig(cand, "Setup wizard: " + string.Join(" ", changes), "Apply");
                UseConfig(cand);
            }
            Action undo = null, keep = null;
            if (fw == null || fwProfiles != plan.Profiles || !Firewall.Covers(fw.Ports, plan.Port) || fw.Enabled != plan.FirewallEnabled)
            {
                // A new port is added to the rule; a rule that had one port drops the old one only when the new settings
                // are kept, so the server stays reachable while you decide, and the rule comes back with the old file.
                var before = fw;
                var pending = fw == null ? plan.Port.ToString() : (Firewall.Covers(fw.Ports, plan.Port) ? fw.Ports : fw.Ports + "," + plan.Port);
                Firewall.Apply(plan.FirewallEnabled, plan.Profiles, pending);
                LoadFirewall();
                undo = () => { if (before == null) Firewall.Remove(); else Firewall.Apply(before.Enabled, before.Profiles, before.Ports); };
                if (fw != null && Firewall.IsSinglePort(fw.Ports) && pending != plan.Port.ToString())
                    keep = () => { Firewall.Apply(plan.FirewallEnabled, plan.Profiles, plan.Port.ToString()); LoadFirewall(); };
            }
            if (backup != null) { if (RestartWithRollback(backup, undo) && keep != null) keep(); }
            else if (keep != null) keep();
            RefreshDashboard();
            Status("Setup wizard applied");
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

            // Preferences of this account (HKCU\Software\OpenSSH Server Manager).
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
            pref("Show the changes to sshd_config before every save", Prefs.PreviewChanges, v => Prefs.PreviewChanges = v);
            pref("After a restart with new settings, ask to keep them; restore the previous settings after " + Prefs.ConfirmSeconds + " s without an answer", Prefs.ConfirmAfterRestart, v => Prefs.ConfirmAfterRestart = v);
            pref("Icon in the notification area, with a notification when sshd stops or logins fail repeatedly", Prefs.TrayIcon, v => { Prefs.TrayIcon = v; if (v) InitTray(); else StopWatchers(); });
            pref("Minimize to the notification area", Prefs.MinimizeToTray, v => Prefs.MinimizeToTray = v);
            var failRow = Flow(); failRow.Dock = DockStyle.None; failRow.Padding = new Padding(0);
            failRow.Controls.Add(Lbl("Notify after"));
            var failN = new NumericUpDown { Minimum = 0, Maximum = 10000, Value = Prefs.FailedLoginThreshold, Width = Ui.Px(70), Margin = new Padding(4, 6, 4, 4), AccessibleName = "Failed logins before a notification (0 = never)" };
            failN.ValueChanged += (s, e) => Prefs.FailedLoginThreshold = (int)failN.Value;
            failRow.Controls.Add(failN);
            failRow.Controls.Add(Lbl("failed logins within"));
            var failM = new NumericUpDown { Minimum = 1, Maximum = 1440, Value = Prefs.FailedLoginMinutes, Width = Ui.Px(70), Margin = new Padding(4, 6, 4, 4), AccessibleName = "Minutes for counting failed logins" };
            failM.ValueChanged += (s, e) => Prefs.FailedLoginMinutes = (int)failM.Value;
            failRow.Controls.Add(failM);
            failRow.Controls.Add(Lbl("minute(s) (0 = never)"));
            flow.Controls.Add(failRow);
            flow.Controls.Add(new Label { AutoSize = true, ForeColor = Theme.Muted, MaximumSize = new Size(Ui.Px(900), 0), Margin = new Padding(4, 6, 4, 4), Text = "Keyboard: Ctrl+S saves the tab shown, F5 refreshes it, Ctrl+1 to Ctrl+9 open the tabs, Ctrl+F finds in the sshd_config text, Enter opens the selected item of a list, Delete removes it." });
            page.Controls.Add(flow);
            flow.AutoScroll = true;
            return page;
        }

        /// <summary>Switches the colours of the window to the preference (light, dark, like Windows); high contrast always wins.</summary>
        private void ApplyTheme()
        {
            var previous = Theme.Current;
            Theme.Current = Theme.For(Prefs.Theme);
            Theme.Apply(this, previous);
            // List rows coloured by state take the new colours the next time they are filled.
            _lvChecks.Items.Clear();
            Invalidate(true);
        }
    }
}

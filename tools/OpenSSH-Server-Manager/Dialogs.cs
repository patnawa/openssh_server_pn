// OpenSSH Server Manager for Windows: Dialogs

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
    // ------------------------------------------------------------------------------------------
    // Rule dialog of the Authentication tab
    // ------------------------------------------------------------------------------------------
    /// <summary>Adds or edits the login methods of one user or group.</summary>
    internal sealed class RuleDialog : ThemedForm
    {
        private readonly RadioButton _user = new RadioButton { Text = "User", AutoSize = true, Checked = true, Margin = new Padding(3, 5, 3, 3) };
        private readonly RadioButton _group = new RadioButton { Text = "Group", AutoSize = true, Margin = new Padding(16, 5, 3, 3) };
        private readonly ComboBox _name = new ComboBox { AccessibleName = "User or group name", DropDownStyle = ComboBoxStyle.DropDown, Width = Ui.Px(400), Margin = new Padding(3, 2, 3, 6) };
        private readonly CheckBox _pw = new CheckBox { Text = "Windows authentication (account name and password)", AutoSize = true, Checked = true };
        private readonly CheckBox _key = new CheckBox { Text = "Public key", AutoSize = true, Checked = true };
        private readonly CheckBox _krb = new CheckBox { Text = "Kerberos single sign-on (domain accounts)", AutoSize = true };
        private readonly RadioButton _either = new RadioButton { Text = "Either one is enough", AutoSize = true, Checked = true, Margin = new Padding(24, 2, 3, 0) };
        private readonly RadioButton _both = new RadioButton { Text = "Both required: the key first, then the Windows password", AutoSize = true, Margin = new Padding(24, 0, 3, 0) };
        private readonly RadioButton _keep = new RadioButton { AutoSize = true, Margin = new Padding(24, 0, 3, 0), Visible = false };
        private readonly List<AuthRule> _others;
        private readonly string _custom;
        public AuthRule Result;

        public RuleDialog(AuthRule existing, List<AuthRule> others, bool kerberosAvailable)
        {
            _others = others ?? new List<AuthRule>();
            Text = existing == null ? "Add a rule" : "Rule for " + existing.Kind.ToLowerInvariant() + " " + existing.Name;
            StartPosition = FormStartPosition.CenterParent; FormBorderStyle = FormBorderStyle.FixedDialog; if (Ui.AppIcon != null) Icon = Ui.AppIcon;
            MinimizeBox = MaximizeBox = false; ShowInTaskbar = false; AutoSize = true; AutoSizeMode = AutoSizeMode.GrowAndShrink;
            Padding = new Padding(10); Font = new Font("Segoe UI", Ui.Pt(9.5f));

            var p = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoSize = true, Dock = DockStyle.Fill };
            var kind = new FlowLayoutPanel { FlowDirection = FlowDirection.LeftToRight, WrapContents = false, AutoSize = true };
            kind.Controls.Add(new Label { Text = "Applies to:", AutoSize = true, Margin = new Padding(3, 7, 8, 3) });
            kind.Controls.Add(_user); kind.Controls.Add(_group);
            p.Controls.Add(kind);
            p.Controls.Add(new Label { Text = "Name: a local account or group, or DOMAIN\\name for a domain account", AutoSize = true, Margin = new Padding(3, 8, 3, 0) });
            p.Controls.Add(_name);
            p.Controls.Add(new Label { Text = "Login methods:", AutoSize = true, Margin = new Padding(3, 6, 3, 0) });
            p.Controls.Add(_pw); p.Controls.Add(_key); p.Controls.Add(_krb);
            var combo = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoSize = true };
            combo.Controls.Add(_either); combo.Controls.Add(_both); combo.Controls.Add(_keep);
            p.Controls.Add(combo);
            var ok = new Button { Text = "OK", Width = Ui.Px(100), Height = Ui.Px(30) };
            var cancel = new Button { Text = "Cancel", DialogResult = DialogResult.Cancel, Width = Ui.Px(100), Height = Ui.Px(30) };
            var bar = new FlowLayoutPanel { FlowDirection = FlowDirection.RightToLeft, AutoSize = true, Width = Ui.Px(420), Margin = new Padding(3, 12, 3, 3) };
            bar.Controls.Add(cancel); bar.Controls.Add(ok);
            p.Controls.Add(bar);
            Controls.Add(p);
            AcceptButton = ok; CancelButton = cancel;

            _krb.Enabled = kerberosAvailable || (existing != null && existing.Methods.Kerberos);
            if (existing != null)
            {
                _group.Checked = existing.IsGroup; _user.Checked = !existing.IsGroup;
                _pw.Checked = existing.Methods.Password; _key.Checked = existing.Methods.PublicKey; _krb.Checked = existing.Methods.Kerberos;
                _custom = existing.Methods.Custom;
                if (_custom != null) { _keep.Text = "Keep the rule from sshd_config: AuthenticationMethods " + _custom; _keep.Visible = true; _keep.Checked = true; }
                else if (existing.Methods.RequireBoth) _both.Checked = true;
            }
            FillSuggestions();
            if (existing != null) _name.Text = existing.Name;
            _user.CheckedChanged += (s, e) => FillSuggestions();
            EventHandler update = (s, e) => { _either.Enabled = _both.Enabled = _pw.Checked && _key.Checked; };
            _pw.CheckedChanged += update; _key.CheckedChanged += update; update(null, null);
            ok.Click += OnOk;
        }

        private void FillSuggestions()
        {
            var text = _name.Text;
            _name.Items.Clear();
            foreach (var n in _group.Checked ? Accounts.LocalGroups() : Accounts.LocalUsers()) _name.Items.Add(n);
            _name.Text = text;
        }

        private void OnOk(object sender, EventArgs e)
        {
            bool group = _group.Checked; string err;
            var typed = _name.Text.Trim();
            var name = Accounts.Canonical(typed, group, out err);
            if (name == null)
            {
                // A domain account cannot be looked up while no domain controller answers; it can be used after a warning.
                bool domainName = typed.Replace('/', '\\').IndexOf('\\') > 0 && !typed.StartsWith(".") && err.Contains("was not found") && Accounts.DomainJoined();
                if (!domainName) { MessageBox.Show(this, err, Program.AppName, MessageBoxButtons.OK, MessageBoxIcon.Warning); return; }
                if (MessageBox.Show(this, err + "\n\nUse \"" + typed + "\" anyway? sshd matches it only when it is spelled exactly as DOMAIN\\name.", Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;
                name = Accounts.AsciiLower(typed.Replace('/', '\\'));
            }
            var m = new AuthMethods { Password = _pw.Checked, PublicKey = _key.Checked, Kerberos = _krb.Checked, RequireBoth = _both.Checked };
            if (_keep.Visible && _keep.Checked) m.Custom = _custom;
            if (!m.AnyEnabled) { MessageBox.Show(this, "Tick at least one login method.", Program.AppName, MessageBoxButtons.OK, MessageBoxIcon.Warning); return; }
            if (_others.Any(o => o.IsGroup == group && o.Name == name)) { MessageBox.Show(this, "There is already a rule for " + (group ? "group " : "user ") + name + ".", Program.AppName, MessageBoxButtons.OK, MessageBoxIcon.Warning); return; }
            Result = new AuthRule { IsGroup = group, Name = name, Methods = m };
            DialogResult = DialogResult.OK;
        }
    }

    // ------------------------------------------------------------------------------------------
    // Small multi-line input dialog
    // ------------------------------------------------------------------------------------------
    internal sealed class PasswordDialog : ThemedForm
    {
        private readonly TextBox _txt = new TextBox { AccessibleName = "Passphrase", UseSystemPasswordChar = true, Width = Ui.Px(360), Margin = new Padding(8) };
        public string Value { get { return _txt.Text; } }
        public PasswordDialog(string title)
        {
            Text = title; StartPosition = FormStartPosition.CenterParent; FormBorderStyle = FormBorderStyle.FixedDialog; if (Ui.AppIcon != null) Icon = Ui.AppIcon;
            MinimizeBox = MaximizeBox = false; ShowInTaskbar = false; AutoSize = true; AutoSizeMode = AutoSizeMode.GrowAndShrink; Padding = new Padding(8);
            var ok = new Button { Text = "OK", DialogResult = DialogResult.OK, Width = Ui.Px(100), Height = Ui.Px(30) };
            var cancel = new Button { Text = "Cancel", DialogResult = DialogResult.Cancel, Width = Ui.Px(100), Height = Ui.Px(30) };
            var panel = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, AutoSize = true, Dock = DockStyle.Fill };
            panel.Controls.Add(new Label { Text = "Passphrase:", AutoSize = true, Margin = new Padding(8, 8, 8, 0) });
            panel.Controls.Add(_txt);
            var bar = new FlowLayoutPanel { FlowDirection = FlowDirection.RightToLeft, AutoSize = true, Width = Ui.Px(380) };
            bar.Controls.Add(cancel); bar.Controls.Add(ok);
            panel.Controls.Add(bar);
            Controls.Add(panel);
            AcceptButton = ok; CancelButton = cancel;
        }
    }

    internal sealed class TextDialog : ThemedForm
    {
        private readonly TextBox _txt = new TextBox { AccessibleName = "Text", Multiline = true, ScrollBars = ScrollBars.Both, Dock = DockStyle.Fill, Font = new Font("Consolas", Ui.Pt(9.5f)), WordWrap = false };
        public string Value { get { return _txt.Text; } }
        /// <summary>An input box; with readOnlyText, a window that shows a text to read and copy (event details), with Close only.</summary>
        public TextDialog(string title, string readOnlyText = null)
        {
            Text = title; _txt.AccessibleName = title; StartPosition = FormStartPosition.CenterParent; if (Ui.AppIcon != null) Icon = Ui.AppIcon; Size = new Size(Ui.Px(760), Ui.Px(300)); MinimizeBox = MaximizeBox = false; ShowInTaskbar = false;
            var ok = new Button { Text = "OK", DialogResult = DialogResult.OK, Width = Ui.Px(100), Height = Ui.Px(30) };
            var cancel = new Button { Text = readOnlyText != null ? "Close" : "Cancel", DialogResult = DialogResult.Cancel, Width = Ui.Px(100), Height = Ui.Px(30) };
            var bar = new FlowLayoutPanel { Dock = DockStyle.Bottom, FlowDirection = FlowDirection.RightToLeft, Height = Ui.Px(44), Padding = new Padding(6) };
            bar.Controls.Add(cancel); if (readOnlyText == null) bar.Controls.Add(ok);
            if (readOnlyText != null) { _txt.ReadOnly = true; _txt.WordWrap = true; _txt.ScrollBars = ScrollBars.Vertical; _txt.Text = readOnlyText.Replace("\r\n", "\n").Replace("\n", "\r\n"); }
            Controls.Add(_txt); Controls.Add(bar);
            AcceptButton = null; CancelButton = cancel;
        }
    }

    // ------------------------------------------------------------------------------------------
    // Themed window base, comparison view, and the dialogs around saving sshd_config
    // ------------------------------------------------------------------------------------------
    /// <summary>A window that takes the current colours (Theme) when it is shown, dark title bar included.</summary>
    internal class ThemedForm : Form
    {
        protected override void OnHandleCreated(EventArgs e) { base.OnHandleCreated(e); Theme.TitleBar(this); }
        protected override void OnLoad(EventArgs e) { Theme.Apply(this, null); base.OnLoad(e); }
    }

    internal static class DiffView
    {
        /// <summary>A read-only box in a fixed-width font for a comparison.</summary>
        public static RichTextBox Create(string accessibleName)
        {
            return new RichTextBox { ReadOnly = true, Dock = DockStyle.Fill, WordWrap = false, Font = new Font("Consolas", Ui.Pt(9.5f)), DetectUrls = false, AccessibleName = accessibleName, HideSelection = false };
        }

        /// <summary>Shows changed lines with their context: "+ " added (green background), "- " removed (red background).</summary>
        public static void Show(RichTextBox box, List<DiffLine> lines)
        {
            var p = Theme.Current;
            box.SuspendLayout();
            box.Clear();
            box.BackColor = p.Surface; box.ForeColor = p.SurfaceText;
            if (lines.Count == 0 || lines.All(l => l.Kind == ' ')) { box.SelectionColor = p.Muted; box.AppendText("No differences."); box.ResumeLayout(); return; }
            foreach (var l in lines)
            {
                int start = box.TextLength;
                string text = l.Kind == '@' ? "   ..." : (l.Kind == ' ' ? "  " : l.Kind + " ") + l.Text;
                box.AppendText(text + "\n");
                box.Select(start, text.Length + 1);
                box.SelectionBackColor = l.Kind == '+' ? p.Added : l.Kind == '-' ? p.Removed : p.Surface;
                box.SelectionColor = l.Kind == '@' ? p.Muted : p.SurfaceText;
            }
            box.Select(0, 0);
            box.ResumeLayout();
        }
    }

    /// <summary>What a save would change in sshd_config, before it is written: Save or Cancel.</summary>
    internal sealed class ChangesDialog : ThemedForm
    {
        private readonly RichTextBox _box;
        /// <summary>Tests: the text of the comparison, and the background of the first line that starts with a text.</summary>
        internal string DiffTextForTest { get { return _box.Text; } }
        internal Color LineBackForTest(string start)
        {
            int i = _box.Text.IndexOf(start, StringComparison.Ordinal);
            if (i < 0) return Color.Empty;
            _box.Select(i, 1); var c = _box.SelectionBackColor; _box.Select(0, 0); return c;
        }

        public ChangesDialog(string title, string intro, string oldText, string newText, string okText)
        {
            Text = title; StartPosition = FormStartPosition.CenterParent; if (Ui.AppIcon != null) Icon = Ui.AppIcon;
            Size = new Size(Ui.Px(900), Ui.Px(620)); MinimumSize = new Size(Ui.Px(600), Ui.Px(400)); MinimizeBox = false; ShowInTaskbar = false;
            Font = new Font("Segoe UI", Ui.Pt(9.5f)); Padding = new Padding(Ui.Px(8));
            var all = Diff.Lines(Diff.SplitLines(oldText), Diff.SplitLines(newText));
            var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 4 };
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize)); root.RowStyles.Add(new RowStyle(SizeType.AutoSize)); root.RowStyles.Add(new RowStyle(SizeType.Percent, 100)); root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.Controls.Add(new Label { Text = intro, AutoSize = true, MaximumSize = new Size(Ui.Px(860), 0), Margin = new Padding(3, 3, 3, 6) }, 0, 0);
            root.Controls.Add(new Label { Text = Diff.Changed(all, '+') + " line(s) added, " + Diff.Changed(all, '-') + " removed (green: new, red: removed; three unchanged lines around each change).", AutoSize = true, ForeColor = Theme.Muted, Margin = new Padding(3, 0, 3, 4) }, 0, 1);
            var box = _box = DiffView.Create("Changes to sshd_config");
            root.Controls.Add(box, 0, 2);
            var bar = new FlowLayoutPanel { FlowDirection = FlowDirection.RightToLeft, AutoSize = true, Dock = DockStyle.Fill, Margin = new Padding(0, 6, 0, 0) };
            var cancel = new Button { Text = "Cancel", DialogResult = DialogResult.Cancel, AutoSize = true, MinimumSize = new Size(Ui.Px(100), Ui.Px(30)) };
            var ok = new Button { Text = okText, DialogResult = DialogResult.OK, AutoSize = true, MinimumSize = new Size(Ui.Px(100), Ui.Px(30)) };
            var again = new CheckBox { Text = "Show the changes before every save", Checked = Prefs.PreviewChanges, AutoSize = true, Margin = new Padding(3, 8, 24, 3) };
            again.CheckedChanged += (s, e) => Prefs.PreviewChanges = again.Checked;
            bar.Controls.Add(cancel); bar.Controls.Add(ok); bar.Controls.Add(again);
            root.Controls.Add(bar, 0, 3);
            Controls.Add(root);
            AcceptButton = ok; CancelButton = cancel;
            Load += (s, e) => DiffView.Show(box, Diff.WithContext(all));
        }
    }

    /// <summary>
    /// After sshd restarted with new settings: keep them, or go back to the previous file. Nobody answering within the time
    /// counts as going back, like the display settings of Windows, because a setting that locks the administrator out also
    /// keeps them from answering remotely.
    /// </summary>
    internal sealed class KeepSettingsDialog : ThemedForm
    {
        private readonly Label _report, _countdown;
        private readonly System.Windows.Forms.Timer _timer = new System.Windows.Forms.Timer { Interval = 1000 };
        private int _left;

        public KeepSettingsDialog(string report, bool problems, int seconds, Func<KeyValuePair<string, bool>> checkAgain)
        {
            Text = "Keep the new sshd settings?"; StartPosition = FormStartPosition.CenterParent; if (Ui.AppIcon != null) Icon = Ui.AppIcon;
            FormBorderStyle = FormBorderStyle.FixedDialog; MinimizeBox = MaximizeBox = false; ShowInTaskbar = false; AutoSize = true; AutoSizeMode = AutoSizeMode.GrowAndShrink;
            Font = new Font("Segoe UI", Ui.Pt(9.5f)); Padding = new Padding(Ui.Px(10));
            _left = seconds;
            var p = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoSize = true, Dock = DockStyle.Fill };
            p.Controls.Add(new Label { Text = "sshd restarted with the new settings.", AutoSize = true, Font = new Font("Segoe UI", Ui.Pt(11f), FontStyle.Bold), Margin = new Padding(3, 3, 3, 8) });
            _report = new Label { AutoSize = true, MaximumSize = new Size(Ui.Px(600), 0), Margin = new Padding(3, 0, 3, 8) };
            p.Controls.Add(_report);
            p.Controls.Add(new Label
            {
                AutoSize = true, MaximumSize = new Size(Ui.Px(600), 0), Margin = new Padding(3, 0, 3, 8),
                Text = "Before you keep them, open a NEW SSH connection to this computer and check that you can still log in. Sessions that are open now stay connected either way, so they prove nothing."
            });
            _countdown = new Label { AutoSize = true, MaximumSize = new Size(Ui.Px(600), 0), Font = new Font("Segoe UI", Ui.Pt(9.5f), FontStyle.Bold), Margin = new Padding(3, 0, 3, 10) };
            p.Controls.Add(_countdown);
            var bar = new FlowLayoutPanel { FlowDirection = FlowDirection.LeftToRight, AutoSize = true, WrapContents = false };
            var keep = new Button { Text = "&Keep the new settings", AutoSize = true, MinimumSize = new Size(0, Ui.Px(32)), DialogResult = DialogResult.OK };
            var back = new Button { Text = "&Restore the previous settings", AutoSize = true, MinimumSize = new Size(0, Ui.Px(32)), DialogResult = DialogResult.Abort };
            var again = new Button { Text = "&Check again", AutoSize = true, MinimumSize = new Size(0, Ui.Px(32)) };
            again.Click += (s, e) =>
            {
                UseWaitCursor = true;
                try { var r = checkAgain(); ShowReport(r.Key, r.Value); }
                finally { UseWaitCursor = false; }
            };
            bar.Controls.Add(keep); bar.Controls.Add(back); bar.Controls.Add(again);
            p.Controls.Add(bar);
            Controls.Add(p);
            CancelButton = back;
            ShowReport(report, problems);
            Tick();
            _timer.Tick += (s, e) => { _left--; Tick(); if (_left <= 0) { _timer.Stop(); DialogResult = DialogResult.Abort; } };
            Shown += (s, e) => { _timer.Start(); keep.Focus(); };
            FormClosed += (s, e) => _timer.Dispose();
        }

        private void ShowReport(string text, bool problems) { _report.Text = text; _report.ForeColor = problems ? Theme.Bad : Theme.Text; }
        private void Tick() { _countdown.Text = "The previous settings come back in " + Math.Max(0, _left) + " s unless you keep the new ones."; }
    }

    /// <summary>
    /// Failed logins by client address (from the events read on the Logs tab), and the firewall block list: addresses in
    /// it cannot reach sshd's ports at all. sshd's own PerSourcePenalties slows such sources down for minutes; this is for
    /// the ones that keep coming back.
    /// </summary>
    internal sealed class FailedLoginsDialog : ThemedForm
    {
        private readonly ListView _sources, _blocked;
        private readonly string _ports;
        private readonly List<string> _connected;
        private readonly Label _note;

        public FailedLoginsDialog(List<EventLogs.FailedSource> sources, string period, string ports, List<string> connectedPeers)
        {
            _ports = ports; _connected = (connectedPeers ?? new List<string>()).Select(p => { int i = p.LastIndexOf(':'); return (i > 0 ? p.Substring(0, i) : p).Trim('[', ']'); }).ToList();
            Text = "Failed logins by address"; StartPosition = FormStartPosition.CenterParent; if (Ui.AppIcon != null) Icon = Ui.AppIcon;
            Size = new Size(Ui.Px(980), Ui.Px(640)); MinimumSize = new Size(Ui.Px(700), Ui.Px(450)); MinimizeBox = false; ShowInTaskbar = false;
            Font = new Font("Segoe UI", Ui.Pt(9.5f)); Padding = new Padding(Ui.Px(8));
            var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 6 };
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize)); root.RowStyles.Add(new RowStyle(SizeType.Percent, 60)); root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize)); root.RowStyles.Add(new RowStyle(SizeType.Percent, 40)); root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.Controls.Add(new Label
            {
                AutoSize = true, MaximumSize = new Size(Ui.Px(940), 0), Margin = new Padding(3, 3, 3, 6),
                Text = "Failed or abandoned logins in the events read on the Logs tab (" + period + "), by client address, " + sources.Sum(s => s.Count) + " in all. " +
                       "sshd itself slows repeat offenders down for a while (PerSourcePenalties). An address on the block list below cannot reach port " + ports + " at all, until you remove it."
            }, 0, 0);
            _sources = new ListView { View = View.Details, FullRowSelect = true, GridLines = true, Dock = DockStyle.Fill, HideSelection = false, MultiSelect = true, AccessibleName = "Addresses with failed logins" };
            foreach (var c in new[] { "Address|200", "Failed|70", "First|150", "Last|150", "Accounts tried|300" }) { var p = c.Split('|'); _sources.Columns.Add(p[0], Ui.Px(int.Parse(p[1]))); }
            _sources.ColumnClick += (s, e) => ListSorter.Toggle(_sources, e.Column);
            foreach (var s in sources)
                _sources.Items.Add(new ListViewItem(new[] { s.Address, s.Count.ToString(), s.First.ToString("yyyy-MM-dd HH:mm:ss"), s.Last.ToString("yyyy-MM-dd HH:mm:ss"), string.Join(", ", s.Users.Take(12)) + (s.Users.Count > 12 ? ", ..." : "") }) { Tag = s.Address });
            root.Controls.Add(_sources, 0, 1);
            var bar1 = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Fill, Margin = new Padding(0, 4, 0, 4) };
            var block = new Button { Text = "&Block selected", AutoSize = true, MinimumSize = new Size(Ui.Px(130), Ui.Px(30)) };
            bar1.Controls.Add(block);
            _note = new Label { AutoSize = true, Margin = new Padding(12, 8, 3, 3), ForeColor = Theme.Muted, MaximumSize = new Size(Ui.Px(760), 0) };
            bar1.Controls.Add(_note);
            root.Controls.Add(bar1, 0, 2);
            root.Controls.Add(new Label { Text = "Blocked now (firewall rule \"" + Firewall.BlockRuleName + "\"):", AutoSize = true, Font = new Font("Segoe UI", Ui.Pt(9.5f), FontStyle.Bold), Margin = new Padding(3, 8, 3, 3) }, 0, 3);
            _blocked = new ListView { View = View.Details, FullRowSelect = true, GridLines = true, Dock = DockStyle.Fill, HideSelection = false, MultiSelect = true, AccessibleName = "Blocked addresses" };
            _blocked.Columns.Add("Address", Ui.Px(300));
            root.Controls.Add(_blocked, 0, 4);
            var bar2 = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Fill, Margin = new Padding(0, 6, 0, 0) };
            var unblock = new Button { Text = "&Unblock selected", AutoSize = true, MinimumSize = new Size(Ui.Px(130), Ui.Px(30)) };
            var close = new Button { Text = "Close", AutoSize = true, MinimumSize = new Size(Ui.Px(100), Ui.Px(30)), DialogResult = DialogResult.Cancel };
            bar2.Controls.Add(unblock); bar2.Controls.Add(close);
            root.Controls.Add(bar2, 0, 5);
            Controls.Add(root);
            CancelButton = close;
            block.Click += (s, e) => Guard(Block);
            unblock.Click += (s, e) => Guard(Unblock);
            _sources.KeyDown += (s, e) => { if (e.KeyCode == System.Windows.Forms.Keys.Delete || (e.Control && e.KeyCode == System.Windows.Forms.Keys.B)) { e.Handled = true; Guard(Block); } };
            _blocked.KeyDown += (s, e) => { if (e.KeyCode == System.Windows.Forms.Keys.Delete) { e.Handled = true; Guard(Unblock); } };
            Load += (s, e) => FillBlocked();
        }

        private void Guard(Action a)
        {
            try { a(); }
            catch (Exception ex) { Log.Error("Firewall block list", ex, false); MessageBox.Show(this, ex.Message, Program.AppName, MessageBoxButtons.OK, MessageBoxIcon.Warning); }
        }

        private void FillBlocked()
        {
            var list = Firewall.BlockedAddresses();
            _blocked.BeginUpdate(); _blocked.Items.Clear();
            foreach (var a in list) _blocked.Items.Add(new ListViewItem(a) { Tag = a });
            _blocked.EndUpdate();
            foreach (ListViewItem i in _sources.Items) i.ForeColor = list.Contains((string)i.Tag) ? Theme.Faint : Theme.Current.SurfaceText;
            _note.Text = list.Count == 0 ? "No address is blocked." : list.Count + " address(es) blocked (shown grey above).";
        }

        private void Block()
        {
            var chosen = _sources.SelectedItems.Cast<ListViewItem>().Select(i => (string)i.Tag).ToList();
            if (chosen.Count == 0) { _note.Text = "Select one or more addresses first."; return; }
            var refused = chosen.Select(Firewall.NotBlockable).Where(x => x != null).ToList();
            chosen = chosen.Where(a => Firewall.NotBlockable(a) == null).ToList();
            var connected = chosen.Where(a => _connected.Contains(a)).ToList();
            var text = "Block " + string.Join(", ", chosen) + " from SSH (port " + _ports + ")?" +
                       (connected.Count > 0 ? "\n\nWarning: " + string.Join(", ", connected) + " has an SSH connection open right now. If that is you, you lock yourself out." : "") +
                       (refused.Count > 0 ? "\n\nNot blocked: " + string.Join("; ", refused) + "." : "");
            if (chosen.Count == 0) { MessageBox.Show(this, "Nothing to block: " + string.Join("; ", refused) + ".", Program.AppName, MessageBoxButtons.OK, MessageBoxIcon.Information); return; }
            if (MessageBox.Show(this, text, Program.AppName, MessageBoxButtons.YesNo, connected.Count > 0 ? MessageBoxIcon.Warning : MessageBoxIcon.Question, connected.Count > 0 ? MessageBoxDefaultButton.Button2 : MessageBoxDefaultButton.Button1) != DialogResult.Yes) return;
            var list = Firewall.BlockedAddresses();
            foreach (var a in chosen) if (!list.Contains(a)) list.Add(a);
            Firewall.SetBlockedAddresses(list, _ports);
            Log.Info("Blocked from SSH: " + string.Join(", ", chosen));
            FillBlocked();
        }

        private void Unblock()
        {
            var chosen = _blocked.SelectedItems.Cast<ListViewItem>().Select(i => (string)i.Tag).ToList();
            if (chosen.Count == 0) { _note.Text = "Select one or more blocked addresses first."; return; }
            var list = Firewall.BlockedAddresses().Where(a => !chosen.Contains(a)).ToList();
            Firewall.SetBlockedAddresses(list, _ports);
            Log.Info("Unblocked from SSH: " + string.Join(", ", chosen));
            FillBlocked();
        }
    }

    /// <summary>One line of input with a label.</summary>
    internal sealed class InputDialog : ThemedForm
    {
        private readonly TextBox _txt;
        public string Value { get { return _txt.Text.Trim(); } }
        public InputDialog(string title, string label, string value)
        {
            Text = title; StartPosition = FormStartPosition.CenterParent; FormBorderStyle = FormBorderStyle.FixedDialog; if (Ui.AppIcon != null) Icon = Ui.AppIcon;
            MinimizeBox = MaximizeBox = false; ShowInTaskbar = false; AutoSize = true; AutoSizeMode = AutoSizeMode.GrowAndShrink; Padding = new Padding(Ui.Px(8)); Font = new Font("Segoe UI", Ui.Pt(9.5f));
            var p = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, AutoSize = true, Dock = DockStyle.Fill, WrapContents = false };
            p.Controls.Add(new Label { Text = label, AutoSize = true, MaximumSize = new Size(Ui.Px(460), 0), Margin = new Padding(3, 3, 3, 4) });
            _txt = new TextBox { Width = Ui.Px(460), Text = value ?? "", AccessibleName = label };
            p.Controls.Add(_txt);
            var bar = new FlowLayoutPanel { FlowDirection = FlowDirection.RightToLeft, AutoSize = true, Width = Ui.Px(470), Margin = new Padding(0, 10, 0, 0) };
            var ok = new Button { Text = "OK", DialogResult = DialogResult.OK, Width = Ui.Px(100), Height = Ui.Px(30) };
            var cancel = new Button { Text = "Cancel", DialogResult = DialogResult.Cancel, Width = Ui.Px(100), Height = Ui.Px(30) };
            bar.Controls.Add(cancel); bar.Controls.Add(ok);
            p.Controls.Add(bar);
            Controls.Add(p);
            AcceptButton = ok; CancelButton = cancel;
        }
    }

    /// <summary>A Host block of the ssh client configuration: the name typed after ssh and where it leads.</summary>
    internal sealed class ClientHostDialog : ThemedForm
    {
        private readonly TextBox _pattern;
        private readonly Dictionary<string, TextBox> _fields = new Dictionary<string, TextBox>(StringComparer.OrdinalIgnoreCase);
        public string Pattern { get { return _pattern.Text.Trim(); } }
        public Dictionary<string, string> Values { get { return _fields.ToDictionary(kv => kv.Key, kv => kv.Value.Text.Trim(), StringComparer.OrdinalIgnoreCase); } }

        public ClientHostDialog(ClientHost existing)
        {
            Text = existing == null ? "Add a host" : "Host " + existing.Pattern; StartPosition = FormStartPosition.CenterParent; FormBorderStyle = FormBorderStyle.FixedDialog; if (Ui.AppIcon != null) Icon = Ui.AppIcon;
            MinimizeBox = MaximizeBox = false; ShowInTaskbar = false; AutoSize = true; AutoSizeMode = AutoSizeMode.GrowAndShrink; Padding = new Padding(Ui.Px(8)); Font = new Font("Segoe UI", Ui.Pt(9.5f));
            var grid = new TableLayoutPanel { ColumnCount = 3, AutoSize = true, Dock = DockStyle.Fill };
            Func<string, string, string, TextBox> row = (label, value, hint) =>
            {
                grid.Controls.Add(new Label { Text = label, AutoSize = true, Margin = new Padding(3, 8, 3, 3) });
                var t = new TextBox { Width = Ui.Px(360), Text = value ?? "", AccessibleName = label.TrimEnd(':'), AccessibleDescription = hint };
                grid.Controls.Add(t);
                grid.Controls.Add(new Label { Text = hint, AutoSize = true, ForeColor = Theme.Faint, Margin = new Padding(3, 8, 3, 3) });
                return t;
            };
            _pattern = row("Host:", existing == null ? "" : existing.Pattern, "the name you type: ssh <host>");
            _fields["HostName"] = row("Host name:", existing == null ? "" : existing.Get("HostName"), "server name or address");
            _fields["User"] = row("User:", existing == null ? "" : existing.Get("User"), "account on the server");
            _fields["Port"] = row("Port:", existing == null ? "" : existing.Get("Port"), "empty = 22");
            _fields["IdentityFile"] = row("Key file:", existing == null ? "" : existing.Get("IdentityFile"), "private key, e.g. ~/.ssh/id_ed25519");
            _fields["ProxyJump"] = row("Jump host:", existing == null ? "" : existing.Get("ProxyJump"), "optional: connect through this host");
            var bar = new FlowLayoutPanel { FlowDirection = FlowDirection.RightToLeft, AutoSize = true, Dock = DockStyle.Fill, Margin = new Padding(0, 10, 0, 0) };
            var ok = new Button { Text = "OK", Width = Ui.Px(100), Height = Ui.Px(30) };
            var cancel = new Button { Text = "Cancel", DialogResult = DialogResult.Cancel, Width = Ui.Px(100), Height = Ui.Px(30) };
            bar.Controls.Add(cancel); bar.Controls.Add(ok);
            grid.Controls.Add(bar); grid.SetColumnSpan(bar, 3);
            Controls.Add(grid);
            AcceptButton = ok; CancelButton = cancel;
            ok.Click += (s, e) =>
            {
                int port;
                if (Pattern.Length == 0) { MessageBox.Show(this, "Enter the host name you want to type after ssh.", Program.AppName, MessageBoxButtons.OK, MessageBoxIcon.Warning); return; }
                if (_fields["Port"].Text.Trim().Length > 0 && (!int.TryParse(_fields["Port"].Text.Trim(), out port) || port < 1 || port > 65535)) { MessageBox.Show(this, "The port must be a number from 1 to 65535.", Program.AppName, MessageBoxButtons.OK, MessageBoxIcon.Warning); return; }
                DialogResult = DialogResult.OK;
            };
        }
    }

    /// <summary>The backups of sshd_config: compare one with the current file, restore it, or delete old ones.</summary>
    internal sealed class BackupsDialog : ThemedForm
    {
        private readonly ListView _list;
        private readonly RichTextBox _diff;
        private readonly string _configPath, _current;
        /// <summary>The backup chosen with "Restore", when the dialog closed with OK.</summary>
        public string Chosen;

        public BackupsDialog(string configPath, string currentText)
        {
            _configPath = configPath; _current = currentText ?? "";
            Text = "Backups of sshd_config"; StartPosition = FormStartPosition.CenterParent; if (Ui.AppIcon != null) Icon = Ui.AppIcon;
            Size = new Size(Ui.Px(980), Ui.Px(660)); MinimumSize = new Size(Ui.Px(700), Ui.Px(450)); MinimizeBox = false; ShowInTaskbar = false;
            Font = new Font("Segoe UI", Ui.Pt(9.5f)); Padding = new Padding(Ui.Px(8));
            var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 4 };
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize)); root.RowStyles.Add(new RowStyle(SizeType.Percent, 38)); root.RowStyles.Add(new RowStyle(SizeType.Percent, 62)); root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.Controls.Add(new Label { AutoSize = true, MaximumSize = new Size(Ui.Px(940), 0), Margin = new Padding(3, 3, 3, 6), Text = "Every save keeps the previous file as sshd_config.bak.<date>-<time> (the newest " + SshdConfig.KeepBackups + " are kept). Select one to see what restoring it would change in the current file." }, 0, 0);
            _list = new ListView { View = View.Details, FullRowSelect = true, GridLines = true, Dock = DockStyle.Fill, HideSelection = false, MultiSelect = false, AccessibleName = "Backups" };
            _list.Columns.Add("Saved", Ui.Px(170)); _list.Columns.Add("File", Ui.Px(330)); _list.Columns.Add("Size", Ui.Px(90)); _list.Columns.Add("Difference to the current file", Ui.Px(260));
            root.Controls.Add(_list, 0, 1);
            _diff = DiffView.Create("What restoring the selected backup would change");
            root.Controls.Add(_diff, 0, 2);
            var bar = new FlowLayoutPanel { FlowDirection = FlowDirection.LeftToRight, AutoSize = true, Dock = DockStyle.Fill, Margin = new Padding(0, 6, 0, 0) };
            var restore = new Button { Text = "&Restore selected...", AutoSize = true, MinimumSize = new Size(Ui.Px(140), Ui.Px(30)) };
            var delete = new Button { Text = "&Delete selected", AutoSize = true, MinimumSize = new Size(Ui.Px(120), Ui.Px(30)) };
            var folder = new Button { Text = "Open &folder", AutoSize = true, MinimumSize = new Size(Ui.Px(110), Ui.Px(30)) };
            var close = new Button { Text = "Close", AutoSize = true, MinimumSize = new Size(Ui.Px(100), Ui.Px(30)), DialogResult = DialogResult.Cancel };
            bar.Controls.Add(restore); bar.Controls.Add(delete); bar.Controls.Add(folder); bar.Controls.Add(close);
            root.Controls.Add(bar, 0, 3);
            Controls.Add(root);
            CancelButton = close;
            _list.SelectedIndexChanged += (s, e) => ShowSelected();
            _list.ItemActivate += (s, e) => restore.PerformClick();
            restore.Click += (s, e) => { var f = Selected(); if (f == null) return; Chosen = f; DialogResult = DialogResult.OK; };
            delete.Click += (s, e) =>
            {
                var f = Selected(); if (f == null) return;
                if (MessageBox.Show(this, "Delete the backup " + Path.GetFileName(f) + "?", Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Question, MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;
                try { File.Delete(f); Fill(); } catch (Exception ex) { MessageBox.Show(this, ex.Message, Program.AppName, MessageBoxButtons.OK, MessageBoxIcon.Warning); }
            };
            folder.Click += (s, e) => { var f = Selected(); Proc.OpenExternal("explorer.exe", f != null ? "/select,\"" + f + "\"" : "\"" + Path.GetDirectoryName(_configPath) + "\""); };
            Load += (s, e) => Fill();
        }

        private string Selected() { return _list.SelectedItems.Count > 0 ? (string)_list.SelectedItems[0].Tag : null; }

        private void Fill()
        {
            var current = Diff.SplitLines(_current);
            _list.BeginUpdate(); _list.Items.Clear();
            foreach (var f in SshdConfig.ListBackups(_configPath))
            {
                string text; try { text = File.ReadAllText(f); } catch (Exception ex) { text = null; Log.Error("Reading " + f, ex, false); }
                var d = text == null ? null : Diff.Lines(current, Diff.SplitLines(text));
                var fi = new FileInfo(f);
                _list.Items.Add(new ListViewItem(new[] { fi.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss"), fi.Name, fi.Length + " bytes",
                    d == null ? "cannot be read" : Diff.Changed(d, '+') + Diff.Changed(d, '-') == 0 ? "same as the current file" : "+" + Diff.Changed(d, '+') + " / -" + Diff.Changed(d, '-') + " lines" }) { Tag = f });
            }
            _list.EndUpdate();
            if (_list.Items.Count > 0) _list.Items[0].Selected = true; else DiffView.Show(_diff, new List<DiffLine>());
        }

        private void ShowSelected()
        {
            var f = Selected(); if (f == null) return;
            try { DiffView.Show(_diff, Diff.WithContext(Diff.Lines(Diff.SplitLines(_current), Diff.SplitLines(File.ReadAllText(f))))); }
            catch (Exception ex) { _diff.Text = ex.Message; }
        }
    }
}

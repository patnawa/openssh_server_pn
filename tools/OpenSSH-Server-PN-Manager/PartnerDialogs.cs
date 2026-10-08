// OpenSSH Server PN Manager: partner dialogs

using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace OpenSSHServerPNManager
{
    // ------------------------------------------------------------------------------------------
    // Dialogs of the Partners tab: a partner's settings, a password shown once, its keys, deleting it
    // ------------------------------------------------------------------------------------------

    /// <summary>A new partner, or the settings of one (its name cannot change: it names the folder and the keys file).</summary>
    internal sealed class PartnerDialog : KeyTaskDialog
    {
        private readonly PartnerAccount _existing;
        private readonly TextBox _name, _fullName, _company, _notify;
        private readonly RadioButton _full, _readOnly, _password, _keyOnly;
        private readonly CheckBox _expires;
        private readonly DateTimePicker _lastDay;
        private readonly Func<PartnerDialog, Task> _run;

        public string AccountName { get { return _existing != null ? _existing.Name : _name.Text.Trim(); } }
        public string FullName { get { return _fullName.Text.Trim(); } }
        public string Company { get { return _company.Text.Trim(); } }
        public bool ReadOnlyAccess { get { return _readOnly.Checked; } }
        public bool KeyOnly { get { return _keyOnly.Checked; } }
        /// <summary>The last day the partner may log in, or null.</summary>
        public DateTime? LastDay { get { return _expires.Checked ? (DateTime?)_lastDay.Value.Date : null; } }
        /// <summary>Who is told when the partner's files arrive (Alerts tab): e-mail addresses, or empty for the admins.</summary>
        public string Notify { get { return string.Join(", ", AlertSettings.Addresses(_notify.Text)); } }

        public PartnerDialog(PartnerAccount existing, string root, string notify, Action<PartnerDialog> run) : this(existing, root, notify, d => { run(d); return Task.FromResult(0); }) { }
        public PartnerDialog(PartnerAccount existing, string root, string notify, Func<PartnerDialog, Task> run)
            : base(existing == null ? "New SFTP partner" : "SFTP partner " + existing.Name, existing == null ? "Create partner" : "Save")
        {
            _existing = existing; _run = run;
            Body.Controls.Add(Caption(existing == null
                ? "A local account that can only transfer files over SFTP, in a folder of its own under " + root + ". Its password is generated and shown once."
                : "Folder " + Partners.FolderOf(root, existing.Name) + ". Changes take effect at the partner's next login; sshd is not restarted."));
            _name = new TextBox { Width = Ui.Px(260), AccessibleName = "Account name", Margin = new Padding(12, 2, 3, 2) };
            if (existing == null)
            {
                Body.Controls.Add(Caption("Account name (the partner logs in with it; letters, digits, - _ and ., at most 20):"));
                Body.Controls.Add(_name);
            }
            _fullName = new TextBox { Width = Ui.Px(430), AccessibleName = "Contact name", Margin = new Padding(12, 2, 3, 2), Text = existing == null ? "" : existing.FullName };
            _company = new TextBox { Width = Ui.Px(430), AccessibleName = "Company", Margin = new Padding(12, 2, 3, 2), Text = existing == null ? "" : existing.Company };
            Body.Controls.Add(Caption("Contact name:")); Body.Controls.Add(_fullName);
            Body.Controls.Add(Caption("Company:")); Body.Controls.Add(_company);
            Body.Controls.Add(Caption("Access to its folder:"));
            _full = new RadioButton { Text = "Upload and download", AutoSize = true, Margin = new Padding(12, 2, 3, 2), Checked = existing == null || !existing.ReadOnly };
            _readOnly = new RadioButton { Text = "Download only: no upload, rename, removal or new folders", AutoSize = true, Margin = new Padding(12, 2, 3, 2), Checked = existing != null && existing.ReadOnly };
            var accessChoices = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoSize = true, Margin = new Padding(0) };
            accessChoices.Controls.Add(_full); accessChoices.Controls.Add(_readOnly);
            Body.Controls.Add(accessChoices);
            Body.Controls.Add(Caption("Login:"));
            _password = new RadioButton { Text = "Password (a public key can be added as well, with Keys...)", AutoSize = true, Margin = new Padding(12, 2, 3, 2), Checked = existing == null || !existing.KeyOnly };
            _keyOnly = new RadioButton { Text = "Public key only: the password is refused", AutoSize = true, Margin = new Padding(12, 2, 3, 2), Checked = existing != null && existing.KeyOnly };
            var loginChoices = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoSize = true, Margin = new Padding(0) };
            loginChoices.Controls.Add(_password); loginChoices.Controls.Add(_keyOnly);
            Body.Controls.Add(loginChoices);
            _expires = new CheckBox { Text = "Can log in until the end of", AutoSize = true, Margin = new Padding(3, 12, 3, 2) };
            _lastDay = new DateTimePicker { Format = DateTimePickerFormat.Long, Width = Ui.Px(220), AccessibleName = "Last day the partner can log in", Margin = new Padding(3, 9, 3, 2) };
            var lastDay = existing == null ? null : LocalAccounts.LastDay(existing.Expires);
            _expires.Checked = lastDay != null;
            _lastDay.Value = lastDay ?? DateTime.Today.AddMonths(12);
            _lastDay.Enabled = _expires.Checked;
            _expires.CheckedChanged += (s, e) => _lastDay.Enabled = _expires.Checked;
            Body.Controls.Add(Row(_expires, _lastDay));
            Body.Controls.Add(Caption("When its files arrive, tell (e-mail addresses; empty: the admins set on the Alerts tab):"));
            _notify = new TextBox { Width = Ui.Px(430), AccessibleName = "Who is told when the partner's files arrive", Margin = new Padding(12, 2, 3, 2), Text = notify ?? "" };
            Body.Controls.Add(_notify);
            Body.Controls.Add(Note("The password never expires and the partner cannot change it (over SFTP it could not anyway); the date above decides until when the account can log in. The account is hidden from the Windows sign-in screen and cannot use a shell, commands or forwarding."));
        }

        protected override async Task WorkAsync()
        {
            if (_existing == null) { var e = Partners.NameError(AccountName); if (e != null) { _name.Focus(); throw new ConfigException(e); } }
            if (FullName.Any(char.IsControl) || Company.Any(char.IsControl) || FullName.Length > 100 || Company.Length > 100) throw new ConfigException("The contact name and the company are one line each, at most 100 characters.");
            if (LastDay != null && LastDay.Value < DateTime.Today) throw new ConfigException("The last day to log in is in the past. Choose a later date, or disable the partner instead.");
            AlertSettings.Addresses(_notify.Text); // throws ConfigException for an address that is not valid
            await _run(this);
        }
    }

    /// <summary>A generated password, shown once: it is not stored anywhere.</summary>
    internal sealed class PasswordShownDialog : ThemedForm
    {
        public PasswordShownDialog(string account, string password, string server, int port, string what)
        {
            Text = "Password of " + account; StartPosition = FormStartPosition.CenterParent; FormBorderStyle = FormBorderStyle.FixedDialog; if (Ui.AppIcon != null) Icon = Ui.AppIcon;
            MinimizeBox = MaximizeBox = false; ShowInTaskbar = false; AutoSize = true; AutoSizeMode = AutoSizeMode.GrowAndShrink; Padding = new Padding(Ui.Px(10)); Font = new Font("Segoe UI", Ui.Pt(9.5f));
            var p = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoSize = true, Dock = DockStyle.Fill };
            p.Controls.Add(new Label { Text = what, AutoSize = true, MaximumSize = new Size(Ui.Px(520), 0), Margin = new Padding(3, 3, 3, 8) });
            var details = "Server: " + server + (port == 22 ? "" : "\r\nPort: " + port) + "\r\nProtocol: SFTP\r\nAccount: " + account;
            p.Controls.Add(new TextBox { Text = details, Multiline = true, ReadOnly = true, Width = Ui.Px(520), Height = Ui.Px(port == 22 ? 58 : 76), Font = new Font("Consolas", Ui.Pt(10f)), AccessibleName = "Login details", Margin = new Padding(3, 2, 3, 6) });
            p.Controls.Add(new Label { Text = "Password:", AutoSize = true, Margin = new Padding(3, 4, 3, 2) });
            var pw = new TextBox { Text = password, ReadOnly = true, Width = Ui.Px(520), Font = new Font("Consolas", Ui.Pt(12f)), AccessibleName = "Password" };
            p.Controls.Add(pw);
            p.Controls.Add(new Label
            {
                Text = "The password is not stored anywhere: copy it now. Give it to the partner in a safe way, for example by phone or in a message separate from the login details. Reset password makes a new one.",
                AutoSize = true, MaximumSize = new Size(Ui.Px(520), 0), ForeColor = Theme.Muted, Margin = new Padding(3, 8, 3, 4)
            });
            var bar = new FlowLayoutPanel { FlowDirection = FlowDirection.LeftToRight, AutoSize = true, Margin = new Padding(0, 8, 0, 0) };
            var copyPw = new Button { Text = "Copy password", AutoSize = true, MinimumSize = new Size(Ui.Px(130), Ui.Px(30)) };
            var copyDetails = new Button { Text = "Copy login details", AutoSize = true, MinimumSize = new Size(Ui.Px(150), Ui.Px(30)) };
            var close = new Button { Text = "Close", AutoSize = true, MinimumSize = new Size(Ui.Px(100), Ui.Px(30)), DialogResult = DialogResult.OK };
            copyPw.Click += (s, e) => { try { Clipboard.SetText(password); copyPw.Text = "Copied"; } catch (Exception ex) { MessageBox.Show(this, ex.Message, Program.AppName); } };
            copyDetails.Click += (s, e) => { try { Clipboard.SetText(details); copyDetails.Text = "Copied"; } catch (Exception ex) { MessageBox.Show(this, ex.Message, Program.AppName); } };
            bar.Controls.Add(copyPw); bar.Controls.Add(copyDetails); bar.Controls.Add(close);
            p.Controls.Add(bar);
            Controls.Add(p);
            AcceptButton = close; CancelButton = close;
            Shown += (s, e) => { pw.Focus(); pw.SelectAll(); };
            FormClosed += (s, e) => pw.Text = "";
        }
    }

    /// <summary>The public keys a partner may log in with, in its keys file (administrators only).</summary>
    internal sealed class PartnerKeysDialog : ThemedForm
    {
        private readonly ListView _list;
        private readonly string _file;

        public PartnerKeysDialog(PartnerAccount partner, string file)
        {
            _file = file;
            Text = "Keys of " + partner.Name; StartPosition = FormStartPosition.CenterParent; if (Ui.AppIcon != null) Icon = Ui.AppIcon;
            Size = new Size(Ui.Px(820), Ui.Px(420)); MinimumSize = new Size(Ui.Px(600), Ui.Px(320)); MinimizeBox = false; ShowInTaskbar = false; Font = new Font("Segoe UI", Ui.Pt(9.5f)); Padding = new Padding(Ui.Px(8));
            var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 3 };
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize)); root.RowStyles.Add(new RowStyle(SizeType.Percent, 100)); root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.Controls.Add(new Label
            {
                AutoSize = true, MaximumSize = new Size(Ui.Px(780), 0), Margin = new Padding(3, 3, 3, 6),
                Text = "Public keys " + partner.Name + " may log in with (" + file + "; only administrators can change the file, the partner cannot)." +
                       (partner.KeyOnly ? " The partner logs in with a key only." : " The partner can log in with its password as well.") + " Ask the partner for the public key (.pub) only, never the private key."
            }, 0, 0);
            _list = new ListView { View = View.Details, FullRowSelect = true, GridLines = true, Dock = DockStyle.Fill, HideSelection = false, MultiSelect = false, AccessibleName = "Public keys of the partner" };
            _list.Columns.Add("Type", Ui.Px(180)); _list.Columns.Add("Comment", Ui.Px(200)); _list.Columns.Add("SHA256 fingerprint", Ui.Px(380));
            root.Controls.Add(_list, 0, 1);
            var bar = new FlowLayoutPanel { FlowDirection = FlowDirection.LeftToRight, AutoSize = true, Dock = DockStyle.Fill, Margin = new Padding(0, 6, 0, 0) };
            Func<string, EventHandler, Button> btn = (t, h) => { var b = new Button { Text = t, AutoSize = true, MinimumSize = new Size(Ui.Px(110), Ui.Px(30)) }; b.Click += h; bar.Controls.Add(b); return b; };
            btn("Add from file...", (s, e) => Guard(AddFromFile));
            btn("Paste key...", (s, e) => Guard(Paste));
            btn("Remove selected", (s, e) => Guard(Remove));
            var close = btn("Close", (s, e) => Close()); close.DialogResult = DialogResult.OK;
            root.Controls.Add(bar, 0, 2);
            Controls.Add(root);
            CancelButton = close;
            _list.KeyDown += (s, e) => { if (e.KeyCode == System.Windows.Forms.Keys.Delete) { e.Handled = true; Guard(Remove); } };
            Load += (s, e) => Guard(Fill);
        }

        private void Guard(Action a)
        {
            try { a(); }
            catch (ConfigException ex) { MessageBox.Show(this, ex.Message, Program.AppName, MessageBoxButtons.OK, MessageBoxIcon.Warning); }
            catch (Exception ex) { Log.Error(Text, ex, false); MessageBox.Show(this, ex.Message, Program.AppName, MessageBoxButtons.OK, MessageBoxIcon.Error); }
        }

        private void Fill()
        {
            _list.BeginUpdate(); _list.Items.Clear();
            foreach (var k in Keys.Read(_file)) _list.Items.Add(new ListViewItem(new[] { k.Type, k.Comment, k.Fingerprint }) { Tag = k.Line });
            _list.EndUpdate();
        }

        private void AddLines(IEnumerable<string> lines)
        {
            var clean = lines.Select(l => (l ?? "").Trim()).Where(l => l.Length > 0 && !l.StartsWith("#")).ToList();
            if (clean.Any(l => l.IndexOf("PRIVATE KEY", StringComparison.OrdinalIgnoreCase) >= 0 || PpkFile.IsPpk(l)))
                throw new ConfigException("That is a private key. Ask the partner for the public key: the .pub file, or the line that starts with ssh-ed25519, ecdsa-sha2 or ssh-rsa.");
            var r = Keys.AddLines(_file, clean, null); // SYSTEM and Administrators only, like administrators_authorized_keys
            Fill();
            if (r[0] == 0 && r[1] > 0) MessageBox.Show(this, "The key is there already.", Program.AppName, MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        private void AddFromFile()
        {
            using (var d = new OpenFileDialog { Title = "The partner's public key", Filter = "Public keys (*.pub)|*.pub|All files (*.*)|*.*" })
            {
                if (d.ShowDialog(this) != DialogResult.OK) return;
                if (new FileInfo(d.FileName).Length > KeyGen.MaxKeyFileSize) throw new ConfigException("This file is too large for a public key.");
                AddLines(File.ReadAllLines(d.FileName));
            }
        }

        private void Paste()
        {
            using (var d = new TextDialog("Paste the partner's public key (one per line)")) { if (d.ShowDialog(this) == DialogResult.OK) AddLines(d.Value.Split('\n')); }
        }

        private void Remove()
        {
            if (_list.SelectedItems.Count == 0) return;
            var line = (string)_list.SelectedItems[0].Tag;
            if (MessageBox.Show(this, "Remove this key? The partner can no longer log in with it.\n\n" + line, Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Question, MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;
            Keys.RemoveKey(_file, line, null);
            Fill();
        }

        // --screenshot and --selftest
        internal int KeyCountForTest { get { return _list.Items.Count; } }
        internal void AddForTest(string line) { AddLines(new[] { line }); }
    }

    /// <summary>The transfer history: who uploaded or downloaded which file, when and from where; export and report.</summary>
    internal sealed class TransfersWindow : ThemedForm
    {
        private readonly ComboBox _period, _account;
        private readonly CheckBox _changes;
        private readonly ListView _list;
        private readonly Label _summary;
        private readonly Button _more;
        private readonly Func<DateTime, DateTime, CancellationToken, Task<List<TransferRecord>>> _load;
        private readonly Func<Task<bool>> _enlarge;
        private int _loadGeneration;
        private bool _enlarging;
        private CancellationTokenSource _readCancellation;
        private Button _cancelRead;
        private readonly IDictionary<string, string> _companies;
        private List<TransferRecord> _records = new List<TransferRecord>();
        private DateTime _from, _to;

        private static readonly string[] Periods = { "Today", "Yesterday", "Last 7 days", "This month", "Last month", "Last 30 days", "Last 365 days" };

        /// <summary>load reads a period (in the background); enlarge makes the event log keep more (null when it does already).</summary>
        public TransfersWindow(Func<DateTime, DateTime, List<TransferRecord>> load, Func<bool> enlarge, IDictionary<string, string> companies, string account)
            : this((from, to) => Task.FromResult(load(from, to)), enlarge == null ? (Func<Task<bool>>)null : () => Task.FromResult(enlarge()), companies, account) { }

        public TransfersWindow(Func<DateTime, DateTime, Task<List<TransferRecord>>> load, Func<Task<bool>> enlarge, IDictionary<string, string> companies, string account)
            : this((from, to, cancellation) => load(from, to), enlarge, companies, account) { }

        public TransfersWindow(Func<DateTime, DateTime, CancellationToken, Task<List<TransferRecord>>> load, Func<Task<bool>> enlarge, IDictionary<string, string> companies, string account)
        {
            _load = load; _enlarge = enlarge; _companies = companies ?? new Dictionary<string, string>();
            Text = "SFTP transfers"; StartPosition = FormStartPosition.CenterParent; if (Ui.AppIcon != null) Icon = Ui.AppIcon;
            Size = new Size(Ui.Px(1000), Ui.Px(620)); MinimumSize = new Size(Ui.Px(760), Ui.Px(420)); MinimizeBox = false; ShowInTaskbar = false; Font = new Font("Segoe UI", Ui.Pt(9.5f)); Padding = new Padding(Ui.Px(8));
            var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 4 };
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize)); root.RowStyles.Add(new RowStyle(SizeType.Percent, 100)); root.RowStyles.Add(new RowStyle(SizeType.AutoSize)); root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            var top = new FlowLayoutPanel { FlowDirection = FlowDirection.LeftToRight, AutoSize = true, Dock = DockStyle.Fill, WrapContents = true };
            top.Controls.Add(new Label { Text = "Period:", AutoSize = true, Margin = new Padding(3, 7, 3, 3) });
            _period = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = Ui.Px(140), AccessibleName = "Period" };
            _period.Items.AddRange(Periods); _period.SelectedIndex = 3;
            top.Controls.Add(_period);
            top.Controls.Add(new Label { Text = "Account:", AutoSize = true, Margin = new Padding(12, 7, 3, 3) });
            _account = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = Ui.Px(180), AccessibleName = "Account" };
            _account.Items.Add("All accounts");
            foreach (var n in _companies.Keys.OrderBy(n => n, StringComparer.OrdinalIgnoreCase)) _account.Items.Add(n);
            _account.SelectedIndex = Math.Max(0, account == null ? 0 : _account.Items.IndexOf(account));
            top.Controls.Add(_account);
            _changes = new CheckBox { Text = "Also renames, removals and refused requests", AutoSize = true, Margin = new Padding(12, 6, 3, 3) };
            top.Controls.Add(_changes);
            root.Controls.Add(top, 0, 0);
            _list = new ListView { View = View.Details, FullRowSelect = true, GridLines = true, Dock = DockStyle.Fill, HideSelection = false, AccessibleName = "SFTP transfers" };
            foreach (var c in new[] { "Time|135", "Account|110", "Address|115", "Action|95", "File|330", "Size|85", "Detail|110" }) { var p = c.Split('|'); _list.Columns.Add(p[0], Ui.Px(int.Parse(p[1]))); }
            _list.Columns[5].TextAlign = HorizontalAlignment.Right;
            _list.ColumnClick += (s, e) => ListSorter.Toggle(_list, e.Column);
            root.Controls.Add(_list, 0, 1);
            _summary = new Label { AutoSize = true, MaximumSize = new Size(Ui.Px(960), 0), Margin = new Padding(3, 6, 3, 3) };
            root.Controls.Add(_summary, 0, 2);
            var bar = new FlowLayoutPanel { FlowDirection = FlowDirection.LeftToRight, AutoSize = true, Dock = DockStyle.Fill, Margin = new Padding(0, 4, 0, 0) };
            Func<string, EventHandler, Button> btn = (t, h) => { var b = new Button { Text = t, AutoSize = true, MinimumSize = new Size(Ui.Px(110), Ui.Px(30)) }; b.Click += h; bar.Controls.Add(b); return b; };
            btn("Refresh", async (s, e) => await GuardAsync(Reload));
            _cancelRead = btn("Cancel reading", (s, e) => { if (_readCancellation != null) _readCancellation.Cancel(); });
            _cancelRead.Visible = false;
            btn("Export CSV...", (s, e) => Guard(ExportCsv));
            btn("Report...", (s, e) => Guard(SaveReport));
            _more = btn("Keep more history", async (s, e) => await GuardAsync(async () =>
            {
                if (_enlarging || _enlarge == null) return;
                _enlarging = true; _more.Enabled = false;
                try { if (await _enlarge() && !IsDisposed) { _more.Visible = false; _summary.Text += " The event log keeps " + Ui.Bytes(Transfers.WantedLogBytes) + " from now on."; } }
                finally { _enlarging = false; if (!IsDisposed) _more.Enabled = true; }
            }));
            _more.Visible = _enlarge != null;
            var close = btn("Close", (s, e) => Close());
            root.Controls.Add(bar, 0, 3);
            Controls.Add(root);
            CancelButton = close;
            _period.SelectedIndexChanged += async (s, e) => await GuardAsync(Reload);
            _account.SelectedIndexChanged += (s, e) => Fill();
            _changes.CheckedChanged += (s, e) => Fill();
            Shown += async (s, e) => await GuardAsync(Reload);
            FormClosing += (s, e) => { if (_enlarging) e.Cancel = true; else { _loadGeneration++; if (_readCancellation != null) _readCancellation.Cancel(); } };
        }

        private async Task GuardAsync(Func<Task> work)
        {
            try { await work(); }
            catch (OperationCanceledException) { if (!IsDisposed && _readCancellation == null) _summary.Text = "Reading cancelled; the previously displayed history is unchanged."; }
            catch (Exception ex) { Log.Error(Text, ex, false); if (!IsDisposed && !Program.Unattended) MessageBox.Show(this, ex.Message, Program.AppName, MessageBoxButtons.OK, MessageBoxIcon.Warning); }
        }

        private void Guard(Action a)
        {
            try { a(); }
            catch (Exception ex) { Log.Error(Text, ex, false); MessageBox.Show(this, ex.Message, Program.AppName, MessageBoxButtons.OK, MessageBoxIcon.Warning); }
        }

        /// <summary>The first moment and the moment after the last one of a period chosen by name.</summary>
        public static void Range(string period, DateTime now, out DateTime from, out DateTime to)
        {
            var today = now.Date; var month = new DateTime(today.Year, today.Month, 1);
            to = now;
            switch (period)
            {
                case "Today": from = today; break;
                case "Yesterday": from = today.AddDays(-1); to = today; break;
                case "Last 7 days": from = today.AddDays(-6); break;
                case "This month": from = month; break;
                case "Last month": from = month.AddMonths(-1); to = month; break;
                case "Last 30 days": from = today.AddDays(-29); break;
                default: from = today.AddDays(-364); break;
            }
        }

        private async Task Reload()
        {
            int generation = ++_loadGeneration;
            if (_readCancellation != null) _readCancellation.Cancel();
            var cancellation = new CancellationTokenSource(); _readCancellation = cancellation;
            DateTime from, to; Range((string)_period.SelectedItem, DateTime.Now, out from, out to);
            UseWaitCursor = true; _cancelRead.Visible = true;
            try
            {
                var records = await _load(from, to, cancellation.Token);
                cancellation.Token.ThrowIfCancellationRequested();
                if (IsDisposed || generation != _loadGeneration) return;
                _records = records; _from = from; _to = to;
            }
            finally
            {
                if (_readCancellation == cancellation) _readCancellation = null;
                cancellation.Dispose();
                if (!IsDisposed && generation == _loadGeneration) { UseWaitCursor = false; _cancelRead.Visible = false; }
            }
            foreach (var u in _records.Select(r => r.User).Distinct(StringComparer.OrdinalIgnoreCase)) if (!_account.Items.Contains(u)) _account.Items.Add(u);
            Fill();
        }

        private List<TransferRecord> Filtered()
        {
            var who = _account.SelectedIndex > 0 ? (string)_account.SelectedItem : null;
            return _records.Where(r => (who == null || r.User.Equals(who, StringComparison.OrdinalIgnoreCase)) && (_changes.Checked || r.IsTransfer)).ToList();
        }

        private void Fill()
        {
            var shown = Filtered();
            _list.BeginUpdate(); _list.Items.Clear();
            foreach (var r in Enumerable.Reverse(shown).Take(5000))
            {
                var item = new ListViewItem(new[] { r.Time.ToString("yyyy-MM-dd HH:mm:ss"), r.User, r.Address, r.Action, r.File, r.IsTransfer ? Ui.Bytes(r.Bytes) : "", r.Detail }) { Tag = r };
                if (r.Action == TransferRecord.Refused) item.ForeColor = Theme.Warn;
                _list.Items.Add(item);
            }
            _list.EndUpdate();
            var t = Transfers.Totals(shown);
            _summary.Text = shown.Count == 0 ? "No transfers in this period." + (Transfers.LogSize() < Transfers.WantedLogBytes ? " The OpenSSH event log keeps only " + Ui.Bytes(Transfers.LogSize()) + ": older transfers may be gone." : "")
                : t.Sum(x => x.Uploads) + " upload(s), " + Ui.Bytes(t.Sum(x => x.UploadBytes)) + "; " + t.Sum(x => x.Downloads) + " download(s), " + Ui.Bytes(t.Sum(x => x.DownloadBytes)) + "; by " + t.Count + " account(s)" +
                  (shown.Count > 5000 ? ". The newest 5,000 are listed; Export CSV has all " + shown.Count + "." : ".");
        }

        private void ExportCsv()
        {
            using (var d = new SaveFileDialog { Title = "Export the transfers", Filter = "CSV (*.csv)|*.csv", FileName = "sftp-transfers-" + _from.ToString("yyyy-MM-dd") + ".csv" })
            {
                if (d.ShowDialog(this) != DialogResult.OK) return;
                var lines = new[] { string.Join(",", Transfers.CsvHeader) }.Concat(Filtered().Select(Transfers.CsvLine));
                File.WriteAllLines(d.FileName, lines, new System.Text.UTF8Encoding(true)); // with a BOM, so that Excel reads UTF-8
            }
        }

        private void SaveReport()
        {
            using (var d = new SaveFileDialog { Title = "Save the report", Filter = "Web page (*.html)|*.html", FileName = "sftp-report-" + _from.ToString("yyyy-MM-dd") + ".html" })
            {
                if (d.ShowDialog(this) != DialogResult.OK) return;
                File.WriteAllText(d.FileName, Transfers.ReportHtml(Filtered(), _from, _to, Environment.MachineName, _companies), new System.Text.UTF8Encoding(false));
                Proc.OpenExternal(d.FileName);
            }
        }
    }

    /// <summary>The one-time setup of partner accounts: the folder under which partners get theirs, and what changes.</summary>
    internal sealed class PartnerSetupDialog : KeyTaskDialog
    {
        private readonly TextBox _root;
        private readonly Func<PartnerSetupDialog, Task> _run;
        public string Root
        {
            get
            {
                var root = _root.Text.Trim().TrimEnd('\\');
                // Keep drive roots absolute; Path.Combine("C:", name) is relative to that drive's current directory.
                return root.Length == 2 && root[1] == ':' ? root + "\\" : root;
            }
        }

        public PartnerSetupDialog(PartnerSetupState st, PartnerGroups g, Action<PartnerSetupDialog> run) : this(st, g, d => { run(d); return Task.FromResult(0); }) { }
        public PartnerSetupDialog(PartnerSetupState st, PartnerGroups g, Func<PartnerSetupDialog, Task> run) : base("Set up SFTP partners", "Set up")
        {
            _run = run;
            Body.Controls.Add(Caption("Once this is set up, adding, changing or removing a partner no longer changes sshd_config or restarts sshd.", true));
            Body.Controls.Add(Caption("Each partner gets a folder of its own under:"));
            _root = new TextBox { Width = Ui.Px(430), AccessibleName = "Folder of the partners' folders", Margin = new Padding(12, 2, 3, 2), Text = st.Root ?? PartnerSetup.DefaultRoot };
            var browse = new Button { Text = "Browse...", AutoSize = true, MinimumSize = new Size(Ui.Px(90), Ui.Px(28)), Margin = new Padding(3, 0, 3, 2) };
            browse.Click += (s, e) =>
            {
                using (var d = new FolderBrowserDialog { Description = "The folder under which each partner gets a folder of its own", ShowNewFolderButton = true })
                {
                    if (Directory.Exists(Root)) d.SelectedPath = Root;
                    if (d.ShowDialog(this) == DialogResult.OK) _root.Text = d.SelectedPath;
                }
            };
            Body.Controls.Add(Row(_root, browse));
            var steps = new List<string>();
            if (st.MissingGroups.Count > 0) steps.Add("Create the local groups " + string.Join(", ", st.MissingGroups) + ".");
            steps.AddRange(st.Missing.Select(m => "sshd_config: " + m + "."));
            steps.Add("sshd_config is shown before it is saved, backed up, and sshd restarts once; you confirm the result.");
            Body.Controls.Add(Caption("What happens:"));
            Body.Controls.Add(new Label { Text = string.Join("\n", steps.Select(x => "- " + x)), AutoSize = true, MaximumSize = new Size(Ui.Px(Wide), 0), Margin = new Padding(12, 2, 3, 2) });
            if (st.Problems.Count > 0)
                Body.Controls.Add(new Label { Text = "Note: " + string.Join("; ", st.Problems) + ".", AutoSize = true, MaximumSize = new Size(Ui.Px(Wide), 0), ForeColor = Theme.Warn, Margin = new Padding(3, 10, 3, 2) });
            Body.Controls.Add(Note("Partners are in " + g.Full + " (upload and download) or " + g.ReadOnly + " (download only), and also in " + g.KeyOnly + " when they log in with a key only. Their keys are in " + g.KeysDir + ", which only administrators change."));
        }

        protected override async Task WorkAsync()
        {
            var e = SftpConfig.FolderError(Root + "\\%u");
            if (e != null) { _root.Focus(); throw new ConfigException(e.Replace("%u", "<account>")); }
            await _run(this);
        }
    }

    /// <summary>Confirms the removal of a partner, with the choice to keep its folder (the default) or delete its files as well.</summary>
    internal sealed class PartnerDeleteDialog : KeyTaskDialog
    {
        private readonly CheckBox _files;
        private readonly Func<PartnerDeleteDialog, Task> _run;
        public bool DeleteFiles { get { return _files.Checked; } }

        public PartnerDeleteDialog(PartnerAccount p, string folder, string folderSize, Action<PartnerDeleteDialog> run) : this(p, folder, folderSize, d => { run(d); return Task.FromResult(0); }) { }
        public PartnerDeleteDialog(PartnerAccount p, string folder, string folderSize, Func<PartnerDeleteDialog, Task> run) : base("Delete SFTP partner " + p.Name, "Delete partner")
        {
            _run = run;
            Body.Controls.Add(Caption("Delete the account " + p.Name + (p.Company.Length > 0 ? " (" + p.Company + ")" : "") + "? Its open sessions end, and it can no longer log in. Its keys are removed.", true));
            _files = new CheckBox { Text = "Also delete its folder " + folder + (folderSize == null ? "" : " (" + folderSize + ")"), AutoSize = true, Margin = new Padding(3, 10, 3, 2), Enabled = folderSize != null };
            Body.Controls.Add(_files);
            Body.Controls.Add(Note("Without the tick, the folder stays with its files, for administrators only; a partner created again with the same name gets it back."));
        }

        protected override async Task WorkAsync()
        {
            if (_files.Checked && !Program.Unattended && MessageBox.Show(this, "Delete the folder and every file in it? This cannot be undone.", Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes)
                throw new OperationCanceledException();
            await _run(this);
        }
    }
}

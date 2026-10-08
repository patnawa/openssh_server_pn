// OpenSSH Server PN Manager: key dialogs

using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace OpenSSHServerPNManager
{
    // ------------------------------------------------------------------------------------------
    // Dialogs of the Key generator tab and the setup wizard: change a passphrase, export a key, create a key
    // ------------------------------------------------------------------------------------------

    /// <summary>
    /// A dialog whose OK button does the work itself (through the callback the main window gives it). A wrong passphrase or
    /// another refusal is shown and the dialog stays open with what was typed, so the user can correct it.
    /// </summary>
    internal abstract class KeyTaskDialog : ThemedForm
    {
        protected readonly FlowLayoutPanel Body = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoSize = true, Dock = DockStyle.Fill };
        private readonly FlowLayoutPanel _bar = new FlowLayoutPanel { FlowDirection = FlowDirection.RightToLeft, AutoSize = true, Width = Ui.Px(560), Margin = new Padding(3, 12, 3, 3) };
        protected const int Wide = 540;
        private bool _working;

        protected KeyTaskDialog(string title, string okText)
        {
            Text = title; StartPosition = FormStartPosition.CenterParent; FormBorderStyle = FormBorderStyle.FixedDialog; if (Ui.AppIcon != null) Icon = Ui.AppIcon;
            MinimizeBox = MaximizeBox = false; ShowInTaskbar = false; AutoSize = true; AutoSizeMode = AutoSizeMode.GrowAndShrink;
            Padding = new Padding(Ui.Px(10)); Font = new Font("Segoe UI", Ui.Pt(9.5f));
            var ok = new Button { Text = okText, AutoSize = true, MinimumSize = new Size(Ui.Px(110), Ui.Px(30)) };
            var cancel = new Button { Text = "Cancel", DialogResult = DialogResult.Cancel, AutoSize = true, MinimumSize = new Size(Ui.Px(100), Ui.Px(30)) };
            _bar.Controls.Add(cancel); _bar.Controls.Add(ok);
            Controls.Add(Body);
            AcceptButton = ok; CancelButton = cancel;
            ok.Click += async (s, e) => await RunOkAsync();
            FormClosing += (s, e) => { if (_working) e.Cancel = true; };
        }

        protected override void OnLoad(EventArgs e)
        {
            Body.Controls.Add(_bar); // last, after what the dialog added
            base.OnLoad(e);
        }

        /// <summary>Checks the input and does the work; a ConfigException is shown and keeps the dialog open.</summary>
        protected abstract Task WorkAsync();

        private async Task RunOkAsync()
        {
            if (_working) return;
            _working = true;
            Enabled = false; UseWaitCursor = true; LastError = null;
            try { await WorkAsync(); _working = false; if (!IsDisposed) DialogResult = DialogResult.OK; }
            catch (OperationCanceledException) { } // the user said no to a question: the dialog stays open
            catch (ConfigException ex) { UseWaitCursor = false; Refuse(ex.Message, MessageBoxIcon.Warning); }
            catch (Exception ex) { UseWaitCursor = false; Log.Error(Text, ex, false); Refuse(ex.Message, MessageBoxIcon.Error); }
            finally { _working = false; if (!IsDisposed) { Enabled = true; UseWaitCursor = false; } }
        }

        private void Refuse(string message, MessageBoxIcon icon)
        {
            LastError = message;
            if (!Program.Unattended) MessageBox.Show(this, message, Program.AppName, MessageBoxButtons.OK, icon);
        }

        // ---------------- test hooks (--selftest): the dialog filled in and confirmed as a user would ----------------
        /// <summary>The message of the last refusal (a wrong passphrase, an input error), or null.</summary>
        internal string LastError;
        internal void OkForTest() { AsyncUiTest.Wait(() => RunOkAsync()); }
        internal void TypeForTest(string accessibleName, string value) { Controls.Cast<Control>().SelectMany(All).OfType<TextBox>().First(t => t.AccessibleName == accessibleName).Text = value; }
        internal void TickForTest(string textStart) { var b = Controls.Cast<Control>().SelectMany(All).OfType<ButtonBase>().First(c => c.Text.StartsWith(textStart, StringComparison.Ordinal)); if (b is RadioButton) ((RadioButton)b).Checked = true; else ((CheckBox)b).Checked = true; }

        protected Label Caption(string text, bool bold = false)
        {
            var l = new Label { Text = text, AutoSize = true, MaximumSize = new Size(Ui.Px(Wide), 0), Margin = new Padding(3, 8, 3, 2) };
            if (bold) l.Font = new Font("Segoe UI", Ui.Pt(9.5f), FontStyle.Bold);
            return l;
        }
        protected static Label Note(string text) { return new Label { Text = text, AutoSize = true, ForeColor = Theme.Muted, MaximumSize = new Size(Ui.Px(Wide), 0), Margin = new Padding(3, 10, 3, 2) }; }
        protected static TextBox Secret(string name, int indent = 3) { return new TextBox { UseSystemPasswordChar = true, Width = Ui.Px(300), AccessibleName = name, Margin = new Padding(indent, 2, 3, 4) }; }

        /// <summary>A row of controls side by side.</summary>
        protected static FlowLayoutPanel Row(params Control[] controls)
        {
            var p = new FlowLayoutPanel { FlowDirection = FlowDirection.LeftToRight, WrapContents = false, AutoSize = true, Margin = new Padding(0) };
            p.Controls.AddRange(controls);
            return p;
        }

        protected override void Dispose(bool disposing)
        {
            // Passphrases do not stay in text boxes of a closed dialog.
            if (disposing) foreach (var t in Controls.Cast<Control>().SelectMany(All).OfType<TextBox>().Where(t => t.UseSystemPasswordChar)) t.Text = "";
            base.Dispose(disposing);
        }
        private static IEnumerable<Control> All(Control c) { yield return c; foreach (Control d in c.Controls) foreach (var x in All(d)) yield return x; }
    }

    /// <summary>Changes, adds or removes the passphrase of a private key (ssh-keygen -p).</summary>
    internal sealed class PassphraseChangeDialog : KeyTaskDialog
    {
        private readonly KeyFileInfo _key;
        private readonly TextBox _old, _new, _confirm;
        private readonly CheckBox _none;
        private readonly Func<PassphraseChangeDialog, Task> _run;

        public string OldPassphrase { get { return _key.Encrypted ? _old.Text : null; } }
        public string NewPassphrase { get { return _none.Checked ? null : _new.Text; } }

        public PassphraseChangeDialog(KeyFileInfo key, Action<PassphraseChangeDialog> run) : this(key, d => { run(d); return Task.FromResult(0); }) { }
        public PassphraseChangeDialog(KeyFileInfo key, Func<PassphraseChangeDialog, Task> run) : base("Passphrase of " + key.FileName, key.Encrypted ? "Change passphrase" : "Set passphrase")
        {
            _key = key; _run = run;
            Body.Controls.Add(Caption(key.Description + ", " + (key.Encrypted ? "protected by a passphrase" : "no passphrase") + "\n" + key.Path, true));
            _old = Secret("Current passphrase");
            if (key.Encrypted) { Body.Controls.Add(Caption("Current passphrase:")); Body.Controls.Add(_old); }
            _new = Secret("New passphrase"); _confirm = Secret("Confirm the new passphrase");
            Body.Controls.Add(Caption("New passphrase (at least " + KeyGen.MinPassphraseLength + " characters):")); Body.Controls.Add(_new);
            Body.Controls.Add(Caption("Confirm the new passphrase:")); Body.Controls.Add(_confirm);
            _none = new CheckBox { Text = "No passphrase: anyone who copies the file can use the key", AutoSize = true, Margin = new Padding(3, 8, 3, 2), Enabled = key.Encrypted };
            _none.CheckedChanged += (s, e) => _new.Enabled = _confirm.Enabled = !_none.Checked;
            Body.Controls.Add(_none);
            Body.Controls.Add(Note("ssh-keygen saves the key again, protected by the new passphrase; the key itself stays the same, so servers that accept it still do. " +
                                   "The passphrases go to ssh-keygen through SSH_ASKPASS, never on a command line." +
                                   (key.Format.StartsWith("PEM") ? " The file is saved in the OpenSSH format." : "")));
        }

        protected override async Task WorkAsync()
        {
            if (_key.Encrypted && _old.Text.Length == 0) { _old.Focus(); throw new ConfigException("Enter the current passphrase of the key."); }
            KeyGen.ValidatePassphrase(_new.Text, _confirm.Text, _none.Checked);
            if (_key.Encrypted && !_none.Checked && _new.Text == _old.Text) throw new ConfigException("The new passphrase is the same as the current one.");
            await _run(this);
        }
    }

    /// <summary>Saves a copy of a key in another format: OpenSSH or PuTTY private keys, OpenSSH or RFC 4716 public keys.</summary>
    internal sealed class KeyExportDialog : KeyTaskDialog
    {
        private readonly KeyFileInfo _key;
        private readonly Func<KeyExportDialog, Task> _run;
        private readonly Dictionary<KeyExportFormat, RadioButton> _formats = new Dictionary<KeyExportFormat, RadioButton>();
        private readonly Panel _private;
        private readonly TextBox _current, _new, _confirm, _path;
        private readonly RadioButton _same, _newPass, _nopass;
        private string _suggested;

        public KeyExportFormat Format { get { return _formats.First(kv => kv.Value.Checked).Key; } }
        public bool IsPrivate { get { var f = Format; return f == KeyExportFormat.OpenSshPrivate || f == KeyExportFormat.PuttyV3 || f == KeyExportFormat.PuttyV2; } }
        public string Target { get { return _path.Text.Trim(); } }
        public string CurrentPassphrase { get { return _key.Encrypted && IsPrivate ? _current.Text : null; } }
        public string NewPassphrase { get { return !IsPrivate ? null : _same.Checked ? CurrentPassphrase : _newPass.Checked ? _new.Text : null; } }

        public KeyExportDialog(KeyFileInfo key, Action<KeyExportDialog> run) : this(key, d => { run(d); return Task.FromResult(0); }) { }
        public KeyExportDialog(KeyFileInfo key, Func<KeyExportDialog, Task> run) : base("Export " + key.FileName, "Export")
        {
            _key = key; _run = run;
            bool putty = KeyFormats.PuttyCanUse(key.Type);
            Body.Controls.Add(Caption(key.Description + ", " + key.Format + " format, " + (key.Encrypted ? "protected by a passphrase" : "no passphrase") + "\n" + key.Path, true));
            Body.Controls.Add(Caption("Format:"));
            Action<KeyExportFormat, string, bool> format = (f, text, enabled) =>
            {
                var r = new RadioButton { Text = text + (enabled ? "" : " (not for this key type)"), AutoSize = true, Enabled = enabled, Margin = new Padding(12, 2, 3, 2) };
                r.CheckedChanged += (s, e) => { if (r.Checked) FormatChanged(); };
                _formats[f] = r; Body.Controls.Add(r);
            };
            format(KeyExportFormat.PuttyV3, "PuTTY private key, .ppk version 3 (PuTTY 0.75 and later, WinSCP, FileZilla)", putty);
            format(KeyExportFormat.PuttyV2, "PuTTY private key, .ppk version 2 (older versions of these programs)", putty);
            format(KeyExportFormat.OpenSshPrivate, "OpenSSH private key (ssh, scp and sftp on Windows, Linux and macOS)", true);
            format(KeyExportFormat.OpenSshPublic, "OpenSSH public key (.pub), for the authorized_keys file of a server", true);
            format(KeyExportFormat.Rfc4716Public, "Public key in RFC 4716 (SSH2) format, for servers that ask for it", true);

            var p = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoSize = true, Margin = new Padding(0) };
            _current = Secret("Current passphrase of the key", 12);
            if (key.Encrypted) { p.Controls.Add(Caption("Current passphrase of the key:")); p.Controls.Add(_current); }
            p.Controls.Add(Caption("Passphrase of the exported file:"));
            _same = new RadioButton { Text = "The same as the key's", AutoSize = true, Margin = new Padding(12, 2, 3, 2), Visible = key.Encrypted };
            _newPass = new RadioButton { Text = "A new passphrase (at least " + KeyGen.MinPassphraseLength + " characters):", AutoSize = true, Margin = new Padding(12, 2, 3, 2) };
            _nopass = new RadioButton { Text = "None: anyone who gets the file can use the key", AutoSize = true, Margin = new Padding(12, 2, 3, 2) };
            _new = Secret("New passphrase of the exported file", 30); _confirm = Secret("Confirm the new passphrase", 30);
            p.Controls.Add(_same); p.Controls.Add(_newPass); p.Controls.Add(_new); p.Controls.Add(_confirm); p.Controls.Add(_nopass);
            _private = p; Body.Controls.Add(p);
            (key.Encrypted ? _same : _newPass).Checked = true;
            EventHandler passChanged = (s, e) => { _new.Enabled = _confirm.Enabled = _newPass.Checked; };
            _same.CheckedChanged += passChanged; _newPass.CheckedChanged += passChanged; _nopass.CheckedChanged += passChanged;

            Body.Controls.Add(Caption("Save as:"));
            _path = new TextBox { Width = Ui.Px(430), AccessibleName = "File to export to", Margin = new Padding(12, 2, 3, 2) };
            var browse = new Button { Text = "Browse...", AutoSize = true, MinimumSize = new Size(Ui.Px(90), Ui.Px(28)), Margin = new Padding(3, 0, 3, 2) };
            browse.Click += (s, e) => Browse();
            Body.Controls.Add(Row(_path, browse));
            Body.Controls.Add(Note("Give a private key only to computers and people you trust, and copy it in a safe way (not by e-mail). With a passphrase, the file is of no use without it."));
            _formats[putty ? KeyExportFormat.PuttyV3 : KeyExportFormat.OpenSshPrivate].Checked = true;
            FormatChanged(); passChanged(null, EventArgs.Empty);
        }

        private void FormatChanged()
        {
            if (_path == null) return; // while the radio buttons are made
            _private.Visible = IsPrivate;
            var suggestion = Path.Combine(Path.GetDirectoryName(_key.Path) ?? KeyGen.SshDir, KeyGen.ExportFileName(_key, Format));
            if (_path.Text.Trim().Length == 0 || string.Equals(_path.Text.Trim(), _suggested, StringComparison.OrdinalIgnoreCase)) _path.Text = suggestion;
            _suggested = suggestion;
        }

        private void Browse()
        {
            var f = Format;
            var filter = f == KeyExportFormat.PuttyV2 || f == KeyExportFormat.PuttyV3 ? "PuTTY private key (*.ppk)|*.ppk" : f == KeyExportFormat.OpenSshPrivate ? "Private key (no extension)|*.*" : "Public key (*.pub)|*.pub|All files (*.*)|*.*";
            using (var d = new SaveFileDialog { Title = "Export to", Filter = filter, OverwritePrompt = true, AddExtension = f != KeyExportFormat.OpenSshPrivate })
            {
                try { var cur = Target; d.InitialDirectory = Directory.Exists(Path.GetDirectoryName(cur)) ? Path.GetDirectoryName(cur) : KeyGen.SshDir; d.FileName = Path.GetFileName(cur); } catch { }
                if (d.ShowDialog(this) == DialogResult.OK) _path.Text = d.FileName;
            }
        }

        protected override async Task WorkAsync()
        {
            var target = Target;
            if (target.Length == 0 || !Path.IsPathRooted(target) || target.IndexOfAny(Path.GetInvalidPathChars()) >= 0) { _path.Focus(); throw new ConfigException("Enter the full path of the file to export to."); }
            if (Directory.Exists(target)) throw new ConfigException("The path is a folder. Enter a file name.");
            if (IsPrivate)
            {
                if (_key.Encrypted && _current.Text.Length == 0) { _current.Focus(); throw new ConfigException("Enter the current passphrase of the key: it is needed to write the key in another format."); }
                if (_newPass.Checked) KeyGen.ValidatePassphrase(_new.Text, _confirm.Text, false);
            }
            var existing = File.Exists(target) || Format == KeyExportFormat.OpenSshPrivate && File.Exists(target + ".pub");
            if (existing && !Program.Unattended && MessageBox.Show(this, "A file with this name exists. It is kept as a backup (.bak-<date>) and the export takes its place. Go on?", Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Question, MessageBoxDefaultButton.Button2) != DialogResult.Yes)
                throw new OperationCanceledException();
            await _run(this);
        }
    }

    /// <summary>Creates a key pair for the account running this program (the setup wizard's "Create a key for me").</summary>
    internal sealed class NewKeyDialog : KeyTaskDialog
    {
        private readonly ComboBox _type;
        private readonly TextBox _path, _comment, _pass1, _pass2;
        private readonly CheckBox _none;
        private readonly Func<NewKeyDialog, Task> _run;
        private string _suggested;

        public KeyTypeChoice KeyType { get { return (KeyTypeChoice)_type.SelectedItem; } }
        public string PrivatePath { get { return Path.GetFullPath(_path.Text.Trim()); } }
        public string Comment { get { return _comment.Text.Trim(); } }
        public string Passphrase { get { return _none.Checked ? null : _pass1.Text; } }

        public NewKeyDialog(Action<NewKeyDialog> run) : this(d => { run(d); return Task.FromResult(0); }) { }
        public NewKeyDialog(Func<NewKeyDialog, Task> run) : base("Create a key for you", "Create key")
        {
            _run = run;
            var me = KeyGen.LoginName();
            Body.Controls.Add(Caption("A new key pair for " + me + ". The private key is saved in the file below; its public key is allowed to log in to this server as " + me + "."));
            Body.Controls.Add(Caption("Key type:"));
            _type = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = Ui.Px(Wide - 10), AccessibleName = "Key type", Margin = new Padding(12, 2, 3, 2) };
            foreach (var t in KeyGen.Types.Where(x => !x.Experimental)) _type.Items.Add(t); // ML-DSA stays on the Key generator tab: clients need extra settings
            Body.Controls.Add(_type);
            Body.Controls.Add(Caption("Save the private key as:"));
            _path = new TextBox { Width = Ui.Px(430), AccessibleName = "Private key file", Margin = new Padding(12, 2, 3, 2) };
            var browse = new Button { Text = "Browse...", AutoSize = true, MinimumSize = new Size(Ui.Px(90), Ui.Px(28)), Margin = new Padding(3, 0, 3, 2) };
            browse.Click += (s, e) =>
            {
                using (var d = new SaveFileDialog { Title = "Private key file", OverwritePrompt = false, AddExtension = false, Filter = "Private key (no extension)|*.*" })
                {
                    try { var cur = _path.Text.Trim(); d.InitialDirectory = Directory.Exists(Path.GetDirectoryName(cur)) ? Path.GetDirectoryName(cur) : KeyGen.SshDir; d.FileName = Path.GetFileName(cur); } catch { }
                    if (d.ShowDialog(this) == DialogResult.OK) _path.Text = d.FileName;
                }
            };
            Body.Controls.Add(Row(_path, browse));
            Body.Controls.Add(Caption("Comment (shown next to the key in authorized_keys):"));
            _comment = new TextBox { Width = Ui.Px(430), AccessibleName = "Comment", Text = me.Replace('\\', '_') + "@" + Environment.MachineName, Margin = new Padding(12, 2, 3, 2) };
            Body.Controls.Add(_comment);
            _pass1 = Secret("Passphrase", 12); _pass2 = Secret("Confirm passphrase", 12);
            Body.Controls.Add(Caption("Passphrase (at least " + KeyGen.MinPassphraseLength + " characters):")); Body.Controls.Add(_pass1);
            Body.Controls.Add(Caption("Confirm the passphrase:")); Body.Controls.Add(_pass2);
            _none = new CheckBox { Text = "No passphrase: only for keys used by unattended scripts", AutoSize = true, Margin = new Padding(12, 6, 3, 2) };
            _none.CheckedChanged += (s, e) => _pass1.Enabled = _pass2.Enabled = !_none.Checked;
            Body.Controls.Add(_none);
            Body.Controls.Add(Note("To log in from another computer, that computer needs the private key: copy it there, or export it for PuTTY, WinSCP or FileZilla (offered when the key is made, and on the Key generator tab). Keep the private key to yourself."));
            _type.SelectedIndexChanged += (s, e) =>
            {
                var suggestion = FreeName(KeyGen.DefaultPath(KeyType));
                if (_path.Text.Trim().Length == 0 || string.Equals(_path.Text.Trim(), _suggested, StringComparison.OrdinalIgnoreCase)) _path.Text = suggestion;
                _suggested = suggestion;
            };
            _type.SelectedIndex = 0;
        }

        /// <summary>The default file name, or with _2, _3 ... when a key is there already: the wizard never suggests replacing a key.</summary>
        internal static string FreeName(string path)
        {
            if (!File.Exists(path) && !File.Exists(path + ".pub")) return path;
            for (int n = 2; ; n++) { var p = path + "_" + n; if (!File.Exists(p) && !File.Exists(p + ".pub")) return p; }
        }

        protected override async Task WorkAsync()
        {
            KeyGen.Validate(KeyType, _path.Text, Comment, _pass1.Text, _pass2.Text, _none.Checked);
            var path = PrivatePath;
            if ((File.Exists(path) || File.Exists(path + ".pub")) && !Program.Unattended && MessageBox.Show(this, "A key already exists at\n" + path + "\n\nReplace it? The existing files are kept with .bak-<date> added to their names.", Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes)
                throw new OperationCanceledException();
            await _run(this);
        }
    }
}

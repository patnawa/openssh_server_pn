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
    internal sealed class RuleDialog : Form
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
    internal sealed class PasswordDialog : Form
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

    internal sealed class TextDialog : Form
    {
        private readonly TextBox _txt = new TextBox { AccessibleName = "Text", Multiline = true, ScrollBars = ScrollBars.Both, Dock = DockStyle.Fill, Font = new Font("Consolas", Ui.Pt(9.5f)), WordWrap = false };
        public string Value { get { return _txt.Text; } }
        public TextDialog(string title)
        {
            Text = title; _txt.AccessibleName = title; StartPosition = FormStartPosition.CenterParent; if (Ui.AppIcon != null) Icon = Ui.AppIcon; Size = new Size(Ui.Px(760), Ui.Px(300)); MinimizeBox = MaximizeBox = false; ShowInTaskbar = false;
            var ok = new Button { Text = "OK", DialogResult = DialogResult.OK, Width = Ui.Px(100), Height = Ui.Px(30) };
            var cancel = new Button { Text = "Cancel", DialogResult = DialogResult.Cancel, Width = Ui.Px(100), Height = Ui.Px(30) };
            var bar = new FlowLayoutPanel { Dock = DockStyle.Bottom, FlowDirection = FlowDirection.RightToLeft, Height = Ui.Px(44), Padding = new Padding(6) };
            bar.Controls.Add(cancel); bar.Controls.Add(ok);
            Controls.Add(_txt); Controls.Add(bar);
            AcceptButton = null; CancelButton = cancel;
        }
    }
}

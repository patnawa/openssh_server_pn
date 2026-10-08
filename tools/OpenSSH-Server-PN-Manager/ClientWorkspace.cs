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
    internal sealed partial class MainForm
    {
        // ---------------- Client (the ssh client of this account) ----------------
        private ListView _lvKnownHosts, _lvClientHosts, _lvAgentKeys; private Label _lblAgent2; private bool _clientLoaded;
        private List<ClientHost> _clientHosts = new List<ClientHost>();
        private ClientFileSnapshot _clientConfigSnapshot;
        private TextBox _clientSearch;

        private TabPage BuildClient()
        {
            var page = new TabPage("Client");
            if (!Program.Unattended && Elevation.IsAdministrator())
            {
                var panel = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown, WrapContents = false, Padding = new Padding(Ui.Px(20)) };
                panel.Controls.Add(new Label { Text = "Manage your connections in the standard-user Client workspace.", AutoSize = true, Font = new Font(Font, FontStyle.Bold), Margin = new Padding(4, 4, 4, 12) });
                panel.Controls.Add(new Label { Text = "It uses the signed-in user's SSH configuration, known hosts and agent. SSH configuration can run local commands, so client files and connection previews are opened without administrator rights.", AutoSize = true, MaximumSize = new Size(Ui.Px(760), 0), Margin = new Padding(4, 4, 4, 12) });
                panel.Controls.Add(Btn("Open user Client workspace", (s, e) => Proc.OpenUnelevated(Application.ExecutablePath, "--client"), 230));
                page.Controls.Add(panel);
                return page;
            }
            var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 4, Padding = new Padding(4) };
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize)); root.RowStyles.Add(new RowStyle(SizeType.Percent, 36)); root.RowStyles.Add(new RowStyle(SizeType.Percent, 34)); root.RowStyles.Add(new RowStyle(SizeType.Percent, 30));
            root.Controls.Add(new Label { AutoSize = true, ForeColor = Theme.Muted, MaximumSize = new Size(Ui.Px(980), 0), Margin = new Padding(6, 6, 4, 4), Text = "The ssh client of " + KeyGen.LoginName() + " (you), for connections from this computer to other servers: the hosts ssh knows, the host names of %USERPROFILE%\\.ssh\\config, and the keys in ssh-agent." }, 0, 0);

            var hostsBox = new GroupBox { Text = "Known hosts (" + SshClient.KnownHostsPath + ")", Dock = DockStyle.Fill, Padding = new Padding(6) };
            var hostsRoot = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2 };
            hostsRoot.RowStyles.Add(new RowStyle(SizeType.Percent, 100)); hostsRoot.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            _lvKnownHosts = Lv("Hosts|300", "Type|200", "SHA256 fingerprint|420", "Marker|110"); _lvKnownHosts.AccessibleName = "Known hosts"; _lvKnownHosts.MultiSelect = true;
            _lvKnownHosts.KeyDown += async (s, e) => { if (e.KeyCode == System.Windows.Forms.Keys.Delete) { e.Handled = true; await SafeAsync(RemoveKnownHosts); } };
            hostsRoot.Controls.Add(_lvKnownHosts, 0, 0);
            var hb = Flow();
            hb.Controls.Add(Btn("Add a server's keys...", async (s, e) => await SafeAsync(AddKnownHost), 180));
            hb.Controls.Add(Btn("Remove selected", async (s, e) => await SafeAsync(RemoveKnownHosts), 140));
            hb.Controls.Add(Btn("Open in Notepad", (s, e) => Proc.OpenExternal("notepad.exe", "\"" + SshClient.KnownHostsPath + "\""), 140));
            _tips.SetToolTip(hb.Controls[0], "Reads the host keys a server offers (ssh-keyscan) and adds them after you compared the fingerprints, so the first connection is not a blind trust-on-first-use.");
            hostsRoot.Controls.Add(hb, 0, 1);
            hostsBox.Controls.Add(hostsRoot);
            root.Controls.Add(hostsBox, 0, 1);

            var cfgBox = new GroupBox { Text = "Hosts in " + SshClient.ConfigPath, Dock = DockStyle.Fill, Padding = new Padding(6) };
            var cfgRoot = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 3 };
            cfgRoot.RowStyles.Add(new RowStyle(SizeType.AutoSize)); cfgRoot.RowStyles.Add(new RowStyle(SizeType.Percent, 100)); cfgRoot.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            var searchRow = Flow(); searchRow.Controls.Add(Lbl("Search profiles:"));
            _clientSearch = new TextBox { Width = Ui.Px(260), AccessibleName = "Search client profiles", Margin = new Padding(4, 4, 4, 4) };
            _clientSearch.TextChanged += (s, e) => FilterClientHosts(); searchRow.Controls.Add(_clientSearch);
            searchRow.Controls.Add(new Label { Text = "Stored values; use Effective settings for the resolved connection.", AutoSize = true, ForeColor = Theme.Muted, Margin = new Padding(4, 6, 4, 4) });
            cfgRoot.Controls.Add(searchRow, 0, 0);
            _lvClientHosts = Lv("Host|180", "Host name|220", "User|140", "Port|60", "Key file|260", "Jump host|140"); _lvClientHosts.AccessibleName = "Hosts of the ssh client configuration";
            ListSorter.Disable(_lvClientHosts); // ssh takes the first matching block: the order matters
            _lvClientHosts.ItemActivate += async (s, e) => await SafeAsync(EditClientHost);
            _lvClientHosts.KeyDown += async (s, e) => { if (e.KeyCode == System.Windows.Forms.Keys.Delete) { e.Handled = true; await SafeAsync(RemoveClientHost); } };
            cfgRoot.Controls.Add(_lvClientHosts, 0, 1);
            var cb = Flow();
            cb.Controls.Add(Btn("Add...", async (s, e) => await SafeAsync(AddClientHost), 90));
            cb.Controls.Add(Btn("Edit...", async (s, e) => await SafeAsync(EditClientHost), 90));
            cb.Controls.Add(Btn("Remove", async (s, e) => await SafeAsync(RemoveClientHost), 90));
            cb.Controls.Add(Btn("Connect", (s, e) => Safe(() => ConnectClientHost(false)), 100));
            cb.Controls.Add(Btn("SFTP", (s, e) => Safe(() => ConnectClientHost(true)), 80));
            cb.Controls.Add(Btn("Effective settings", async (s, e) => await SafeAsync(PreviewClientHost), 145));
            cb.Controls.Add(Btn("Open in Notepad", (s, e) => Proc.OpenExternal("notepad.exe", "\"" + SshClient.ConfigPath + "\""), 140));
            cfgRoot.Controls.Add(cb, 0, 2);
            cfgBox.Controls.Add(cfgRoot);
            root.Controls.Add(cfgBox, 0, 2);

            var agentBox = new GroupBox { Text = "ssh-agent (keys it holds for your connections)", Dock = DockStyle.Fill, Padding = new Padding(6) };
            var agentRoot = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 3 };
            agentRoot.RowStyles.Add(new RowStyle(SizeType.AutoSize)); agentRoot.RowStyles.Add(new RowStyle(SizeType.Percent, 100)); agentRoot.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            _lblAgent2 = new Label { AutoSize = true, Margin = new Padding(4, 4, 4, 4) };
            agentRoot.Controls.Add(_lblAgent2, 0, 0);
            _lvAgentKeys = Lv("Type|230", "Comment|260", "SHA256 fingerprint|420"); _lvAgentKeys.AccessibleName = "Keys in ssh-agent";
            _lvAgentKeys.KeyDown += async (s, e) => { if (e.KeyCode == System.Windows.Forms.Keys.Delete) { e.Handled = true; await SafeAsync(RemoveAgentKey); } };
            agentRoot.Controls.Add(_lvAgentKeys, 0, 1);
            var ab = Flow();
            ab.Controls.Add(Btn("Add a key...", async (s, e) => await SafeAsync(AddAgentKey), 110));
            ab.Controls.Add(Btn("Remove selected", async (s, e) => await SafeAsync(RemoveAgentKey), 140));
            ab.Controls.Add(Btn("Start the agent", async (s, e) => await SafeAsync(async () =>
            {
                if (MessageBox.Show(this, "Set the ssh-agent service to start automatically and start it now?", Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
                if (!Elevation.IsAdministrator())
                {
                    if (!Elevation.Relaunch("--start-client-agent")) throw new ConfigException("The agent service was not started. Administrator approval was cancelled or unavailable.");
                    Status("Agent start requested. Refresh after approving the administrator prompt.");
                }
                else { await BgAsync("Starting ssh-agent...", () => { Services.SetStartMode("ssh-agent", "auto"); Services.Start("ssh-agent"); }); await LoadClient(); }
            }), 130));
            ab.Controls.Add(Btn("Refresh", async (s, e) => await SafeAsync(LoadClient), 100));
            agentRoot.Controls.Add(ab, 0, 2);
            agentBox.Controls.Add(agentRoot);
            root.Controls.Add(agentBox, 0, 3);
            page.Controls.Add(root);
            return page;
        }

        private async Task LoadClient()
        {
            if (_lvClientHosts == null) return; // Elevated server console only shows the client-workspace launcher.
            string agentMessage = null; var errors = new List<string>();
            // Each part on its own: a file that cannot be read leaves the other parts of the tab usable.
            var data = await BgAsync("Reading the ssh client files and the agent...", () => new
            {
                Known = ClientPart(SshClient.KnownHostsPath, () => SshClient.ReadKnownHosts(SshClient.KnownHostsPath), errors),
                Config = ClientPart(SshClient.ConfigPath, () => ClientFileSnapshot.Read(SshClient.ConfigPath), errors),
                Agent = ClientPart("ssh-agent service", () => Services.Status("ssh-agent"), errors),
                Keys = ClientPart("ssh-agent keys", () => SshClient.AgentKeys(out agentMessage).Select(Keys.Parse).ToList(), errors),
            });
            var known = data.Known ?? new List<KnownHost>();
            _lvKnownHosts.BeginUpdate(); _lvKnownHosts.Items.Clear();
            foreach (var k in known) _lvKnownHosts.Items.Add(new ListViewItem(new[] { k.Hashed ? "(hashed name)" : k.Hosts, k.Type, k.Fingerprint ?? "", k.Marker }) { Tag = k });
            _lvKnownHosts.EndUpdate();
            _clientConfigSnapshot = data.Config;
            _clientHosts = data.Config == null ? new List<ClientHost>() : SshClient.ParseConfig(data.Config.Lines);
            FilterClientHosts();
            _lblAgent2.Text = data.Agent == null ? "ssh-agent service: could not be checked" : "ssh-agent service: " + data.Agent.Status + ", start " + data.Agent.StartMode + (agentMessage != null && data.Agent.Status == "Running" ? ". " + agentMessage : "");
            _lblAgent2.ForeColor = data.Agent != null && data.Agent.Status == "Running" ? Green : Orange;
            var keys = data.Keys ?? new List<KeyEntry>();
            _lvAgentKeys.BeginUpdate(); _lvAgentKeys.Items.Clear();
            foreach (var k in keys) _lvAgentKeys.Items.Add(new ListViewItem(new[] { k.Type, k.Comment, k.Fingerprint }) { Tag = k.Line });
            _lvAgentKeys.EndUpdate();
            Status(known.Count + " known host key(s), " + _clientHosts.Count + " host block(s), " + keys.Count + " key(s) in the agent" +
                (data.Config != null && data.Config.NotUtf8 ? "; the config file is not UTF-8, so non-ASCII text shows one character per byte" : ""));
            _clientLoaded = true;
            if (errors.Count > 0)
            {
                Status("Could not read " + string.Join("; ", errors));
                if (!Program.Unattended) MessageBox.Show(this, "These parts of the Client tab could not be read:\n\n" + string.Join("\n\n", errors) + "\n\nThe other parts are shown. Use Refresh after fixing the cause.", Program.AppName, MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        private static T ClientPart<T>(string what, Func<T> read, List<string> errors) where T : class
        {
            try { return read(); }
            catch (Exception ex) { errors.Add(what + ": " + ex.Message); return null; }
        }

        private async Task RemoveKnownHosts()
        {
            var sel = _lvKnownHosts.SelectedItems.Cast<ListViewItem>().Select(i => (KnownHost)i.Tag).ToList();
            if (sel.Count == 0) { Status("Select one or more known hosts first"); return; }
            if (MessageBox.Show(this, "Remove " + sel.Count + " known host key(s)?\n\n" + string.Join("\n", sel.Take(10).Select(k => (k.Hashed ? "(hashed name)" : k.Hosts) + "  " + k.Type)) + "\n\nssh asks again the next time it connects to such a host. The previous file is kept as known_hosts.old.", Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
            int n = await BgAsync("Removing known host keys...", () => SshClient.RemoveKnownHosts(SshClient.KnownHostsPath, sel));
            await LoadClient(); Status(n + " known host key(s) removed");
        }

        private async Task AddKnownHost()
        {
            string input;
            using (var d = new InputDialog("Add a server's host keys", "Server name or address, optionally with :port (for example server.example.com or 192.168.1.10:2222):", "")) { if (d.ShowDialog(this) != DialogResult.OK) return; input = d.Value; }
            // name, name:port, IPv6 address, [IPv6 address]:port
            int port = 22; var host = input;
            var m = input.StartsWith("[") ? Regex.Match(input, @"^\[([^\]]+)\](?::(\d{1,5}))?$") : input.Count(c => c == ':') == 1 ? Regex.Match(input, @"^([^:]+):(\d{1,5})$") : Match.Empty;
            if (m.Success) { host = m.Groups[1].Value; if (m.Groups[2].Success) port = int.Parse(m.Groups[2].Value); }
            host = SshClient.CheckHostName(host);
            if (host == null || port < 1 || port > 65535) throw new ConfigException("\"" + input + "\" is not a host name or address.");
            var r = await BgAsync("Asking " + host + " for its host keys (ssh-keyscan)...", () => SshClient.Scan(host, port));
            var lines = r.StdOut.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).Where(l => !l.StartsWith("#") && SshClient.ParseKnownHost(l) != null).ToList();
            if (lines.Count == 0) throw new ConfigException("No host keys from " + host + " port " + port + ".\n\n" + r.Output);
            var snapshot = await BgAsync("Reading known host keys...", () => ClientFileSnapshot.Read(SshClient.KnownHostsPath));
            var fps = await BgAsync("Working out the fingerprints...", () => lines.Select(l => { var k = SshClient.ParseKnownHost(l); var parts = l.Split(' '); return k.Type + "  " + Keys.Fingerprint(k.Type + " " + parts[2]); }).ToList());
            if (MessageBox.Show(this, host + " port " + port + " offers these host keys:\n\n" + string.Join("\n", fps) +
                "\n\n" + SshClient.TrustChanges(snapshot, lines) + "\n\nCompare them with the fingerprints the server's administrator gives you (on that server: ssh-keygen -lf on its host keys, or the Dashboard of OpenSSH Server PN Manager). Add them to your known_hosts only when they match.\n\nAdd them?",
                Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Question, MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;
            int added = await BgAsync("Saving known host keys...", () => SshClient.AddKnownHosts(snapshot, lines));
            await LoadClient(); Status(added == 0 ? "The host keys of " + host + " were already in known_hosts" : added + " host key(s) of " + host + " added to known_hosts");
        }

        private void FilterClientHosts()
        {
            if (_lvClientHosts == null) return;
            var query = _clientSearch == null ? "" : _clientSearch.Text.Trim();
            _lvClientHosts.BeginUpdate(); _lvClientHosts.Items.Clear();
            foreach (var h in _clientHosts)
            {
                var fields = new[] { h.Pattern, h.Get("HostName"), h.Get("User"), h.Get("Port"), string.Join("; ", h.GetAll("IdentityFile")), h.Get("ProxyJump") };
                if (query.Length == 0 || fields.Any(value => value.IndexOf(query, StringComparison.OrdinalIgnoreCase) >= 0)) _lvClientHosts.Items.Add(new ListViewItem(fields) { Tag = h });
            }
            _lvClientHosts.EndUpdate();
        }

        private ClientHost SelectedConnection()
        {
            var host = _lvClientHosts.SelectedItems.Count == 0 ? null : (ClientHost)_lvClientHosts.SelectedItems[0].Tag;
            var problem = SshClient.ConnectProblem(host);
            if (problem != null) throw new ConfigException(problem);
            return host;
        }

        private void ConnectClientHost(bool sftp)
        {
            var host = SelectedConnection();
            Proc.OpenUnelevated(Ssh.Exe(sftp ? "sftp.exe" : "ssh.exe"), "-- " + host.Pattern, true);
        }

        private async Task PreviewClientHost()
        {
            var host = SelectedConnection();
            var text = await BgAsync("Resolving client connection settings...", () => SshClient.EffectivePreview(host.Pattern));
            MessageBox.Show(this, text, "Connection to " + host.Pattern, MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        private async Task AddClientHost()
        {
            var snapshot = await BgAsync("Reading the client configuration...", () => ClientFileSnapshot.Read(SshClient.ConfigPath));
            using (var d = new ClientHostDialog(null))
            {
                if (d.ShowDialog(this) != DialogResult.OK) return;
                var lines = SshClient.WithHost(snapshot.Lines, null, d.Pattern, d.Values);
                await BgAsync("Saving the client configuration...", () => SshClient.WriteConfig(snapshot, lines));
            }
            await LoadClient(); Status("Host added to " + SshClient.ConfigPath);
        }

        private async Task EditClientHost()
        {
            if (_lvClientHosts.SelectedItems.Count == 0) { Status("Select a host first"); return; }
            var h = (ClientHost)_lvClientHosts.SelectedItems[0].Tag;
            if (h.IsMatch) { Status("Match blocks are edited in Notepad"); return; }
            var snapshot = _clientConfigSnapshot;
            await BgAsync("Checking the client configuration...", snapshot.RequireUnchanged);
            using (var d = new ClientHostDialog(h))
            {
                if (d.ShowDialog(this) != DialogResult.OK) return;
                var lines = SshClient.WithHost(snapshot.Lines, h, d.Pattern, d.Values);
                await BgAsync("Saving the client configuration...", () => SshClient.WriteConfig(snapshot, lines));
            }
            await LoadClient(); Status("Host saved in " + SshClient.ConfigPath);
        }

        private async Task RemoveClientHost()
        {
            if (_lvClientHosts.SelectedItems.Count == 0) { Status("Select a host first"); return; }
            var h = (ClientHost)_lvClientHosts.SelectedItems[0].Tag;
            var snapshot = _clientConfigSnapshot;
            await BgAsync("Checking the client configuration...", snapshot.RequireUnchanged);
            if (MessageBox.Show(this, "Remove \"" + h.Pattern + "\" and its settings from " + SshClient.ConfigPath + "? The previous file is kept as config.bak.", Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
            await BgAsync("Saving the client configuration...", () => SshClient.WriteConfig(snapshot, SshClient.WithoutHost(snapshot.Lines, h)));
            await LoadClient(); Status("Host removed");
        }

        private async Task AddAgentKey()
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
            try { r = await BgAsync("Adding the key to ssh-agent...", () => SshClient.AgentAdd(path, pass)); }
            finally { pass = null; }
            await LoadClient();
            if (!r.Ok) throw new ConfigException("ssh-add did not add the key:\n\n" + r.Output);
            Status("Key added to ssh-agent");
        }

        private async Task RemoveAgentKey()
        {
            if (_lvAgentKeys.SelectedItems.Count == 0) { Status("Select a key first"); return; }
            var line = (string)_lvAgentKeys.SelectedItems[0].Tag;
            var r = await BgAsync("Removing the key from ssh-agent...", () => SshClient.AgentRemove(line));
            await LoadClient();
            if (!r.Ok) throw new ConfigException("ssh-add -d did not remove the key:\n\n" + r.Output);
            Status("Key removed from ssh-agent");
        }

    }
}

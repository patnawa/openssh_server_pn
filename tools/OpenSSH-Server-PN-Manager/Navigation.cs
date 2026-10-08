using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Windows.Forms;

namespace OpenSSHServerPNManager
{
    internal sealed partial class MainForm
    {
        private TreeView _navigation;
        private ComboBox _compactNavigation;
        private readonly Dictionary<TabPage, TreeNode> _navigationNodes = new Dictionary<TabPage, TreeNode>();
        private sealed class NavigationChoice
        {
            internal string Group; internal TabPage Page;
            public override string ToString() { return Group + " / " + Page.Text; }
        }

        private Control BuildNavigation()
        {
            var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, Margin = Padding.Empty };
            layout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, Ui.Px(180)));
            layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            _navigation = new TreeView { Dock = DockStyle.Fill, HideSelection = false, ShowLines = false, ShowRootLines = false,
                FullRowSelect = true, BorderStyle = BorderStyle.None, AccessibleName = "Task navigation", Indent = Ui.Px(12), ItemHeight = Ui.Px(30) };
            _compactNavigation = new ComboBox { Dock = DockStyle.Top, DropDownStyle = ComboBoxStyle.DropDownList, AccessibleName = "Task navigation", Visible = false };
            Action<string, TabPage[]> group = (name, pages) =>
            {
                var parent = new TreeNode(name);
                foreach (var page in pages.Where(p => p != null))
                {
                    var node = new TreeNode(page.Text) { Tag = page }; parent.Nodes.Add(node); _navigationNodes.Add(page, node);
                    _compactNavigation.Items.Add(new NavigationChoice { Group = name, Page = page });
                }
                if (parent.Nodes.Count > 0) _navigation.Nodes.Add(parent);
            };
            if (_clientOnly) group("Client", new[] { _pgClient, _pgAbout });
            else
            {
                group("Server", new[] { _pgDashboard, _pgSessions, _pgSettings, _pgRaw, _pgFirewall });
                group("Access", new[] { _pgAuth, _pgKeys, _pgKeyGen });
                group("File exchange", new[] { _pgSftp, _pgPartners });
                group("Client", new[] { _pgClient });
                group("Diagnostics", new[] { _pgAlerts, _pgLogs, _pgHardening, _pgAbout });
            }
            _navigation.ExpandAll();
            _navigation.HandleCreated += (s, e) => _navigation.BeginInvoke((Action)SyncNavigation);
            _navigation.AfterSelect += (s, e) =>
            {
                var page = e.Node.Tag as TabPage;
                if (page != null && _tabs.SelectedTab != page) _tabs.SelectedTab = page;
            };
            _navigation.KeyDown += (s, e) =>
            {
                if (e.KeyCode == System.Windows.Forms.Keys.Enter && _navigation.SelectedNode != null && _navigation.SelectedNode.Tag == null && _navigation.SelectedNode.Nodes.Count > 0)
                { _navigation.SelectedNode.Expand(); _navigation.SelectedNode = _navigation.SelectedNode.Nodes[0]; e.Handled = true; }
            };
            _tabs.HideHeaders = true;
            _compactNavigation.SelectedIndexChanged += (s, e) =>
            {
                var choice = _compactNavigation.SelectedItem as NavigationChoice;
                if (choice != null && _tabs.SelectedTab != choice.Page) _tabs.SelectedTab = choice.Page;
            };
            _tabs.SelectedIndexChanged += (s, e) => SyncNavigation();
            var content = new Panel { Dock = DockStyle.Fill, Margin = Padding.Empty };
            content.Controls.Add(_tabs); content.Controls.Add(_compactNavigation);
            layout.Controls.Add(_navigation, 0, 0); layout.Controls.Add(content, 1, 0);
            layout.SizeChanged += (s, e) =>
            {
                bool compact = layout.ClientSize.Width < Ui.Px(1100);
                _navigation.Visible = !compact; _compactNavigation.Visible = compact;
                layout.ColumnStyles[0].Width = compact ? 0 : Ui.Px(180);
            };
            SyncNavigation();
            return layout;
        }

        private void SyncNavigation()
        {
            if (_navigation == null || _tabs.SelectedTab == null) return;
            TreeNode node;
            if (_navigationNodes.TryGetValue(_tabs.SelectedTab, out node) && _navigation.SelectedNode != node) _navigation.SelectedNode = node;
            for (int i = 0; i < _compactNavigation.Items.Count; i++)
                if (((NavigationChoice)_compactNavigation.Items[i]).Page == _tabs.SelectedTab && _compactNavigation.SelectedIndex != i) { _compactNavigation.SelectedIndex = i; break; }
            _compactNavigation.Refresh();
        }
    }
}

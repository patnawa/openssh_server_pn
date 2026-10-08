using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Windows.Forms;

namespace OpenSSHServerPNManager
{
    /// <summary>Off-screen UI checks with scratch configuration; no service, account, firewall or client-file writes.</summary>
    internal static class UiRegressionTests
    {
        internal static int Run(string output)
        {
            if (!Program.Unattended) throw new InvalidOperationException("UI tests require unattended mode.");
            Directory.CreateDirectory(output);
            var scratch = Path.Combine(Path.GetTempPath(), "pn-ui-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(scratch);
            var oldDir = Ssh.ConfigDirOverride; var oldScale = Ui.Scale; var oldTheme = Theme.Current;
            var report = new StringBuilder(); int failed = 0, passed = 0;
            Action<string, Action> check = (name, body) =>
            {
                try { body(); report.AppendLine("PASS " + name); passed++; }
                catch (Exception ex) { report.AppendLine("FAIL " + name + ": " + ex); failed++; }
            };
            try
            {
                Ssh.ConfigDirOverride = scratch;
                File.WriteAllText(Ssh.ConfigPath, "Port 2222\nSubsystem sftp sftp-server.exe\n", new UTF8Encoding(false));
                foreach (float scale in new[] { 1f, 1.5f, 2f })
                foreach (string palette in new[] { "light", "dark", "contrast" })
                {
                    Ui.Scale = scale;
                    Theme.Current = Theme.Make(palette == "dark", palette == "contrast");
                    var prefix = ((int)(scale * 100)) + "-" + palette;
                    using (var form = Window(false))
                    {
                        check(prefix + " grouped navigation and keyboard", () => Navigation(form));
                        check(prefix + " alert footer remains visible after scrolling", () => AlertFooter(form));
                        check(prefix + " agent health contains gaps and failures", Health);
                        Capture(form, output, prefix + "-alerts");
                        check(prefix + " compact navigation", () => Compact(form));
                        check(prefix + " all-page text layout", () =>
                        {
                            var issues = form.ClippedTextForTest(); form.WaitForIdleForTest();
                            if (issues.Count > 0) throw new Exception(string.Join(" | ", issues.Take(20)));
                        });
                        if (palette == "contrast") check(prefix + " high contrast semantic and link colours", () => Contrast(form));
                        Capture(form, output, prefix + "-compact");
                        form.Close();
                    }
                }
                Ui.Scale = 1; Theme.Current = Theme.Make(false, false);
                using (var form = Window(true))
                {
                    check("client workspace has no server pages or service notification preferences", () =>
                    {
                        if (form.TabCount != 2 || !form.TabName(0).StartsWith("Client") || form.TabName(1) != "About") throw new Exception("Unexpected client pages");
                        form.SelectTabForTest(1); form.WaitForIdleForTest();
                        if (All(form).OfType<CheckBox>().Any(c => c.Text.Contains("sshd stops"))) throw new Exception("Server tray preference leaked into client workspace");
                        typeof(MainForm).GetMethod("ApplyTheme", BindingFlags.Instance | BindingFlags.NonPublic).Invoke(form, null);
                    });
                    form.SelectTabForTest(0); form.WaitForIdleForTest(); Capture(form, output, "client-workspace"); form.Close();
                }
            }
            catch (Exception ex) { failed++; report.AppendLine("FAIL UI fixture: " + ex); }
            finally
            {
                Ssh.ConfigDirOverride = oldDir; Ui.Scale = oldScale; Theme.Current = oldTheme;
                try { Directory.Delete(scratch, true); } catch { }
            }
            report.AppendLine("RESULT: " + passed + " passed, " + failed + " failed. Mixed-monitor and screen-reader acceptance require a desktop session.");
            File.WriteAllText(Path.Combine(output, "ui-report.txt"), report.ToString());
            return failed == 0 ? 0 : 1;
        }

        private static MainForm Window(bool client)
        {
            var form = new MainForm(client) { StartPosition = FormStartPosition.Manual, Location = new Point(-20000, -20000), ShowInTaskbar = false };
            form.Show(); form.WaitForIdleForTest();
            form.MinimumSize = Size.Empty; form.Size = new Size(Ui.Px(1220), Ui.Px(760)); form.PerformLayout(); Application.DoEvents();
            Theme.Apply(form, Theme.Make(false, false));
            form.WaitForIdleForTest(); Application.DoEvents();
            return form;
        }

        private static IEnumerable<Control> All(Control root)
        {
            foreach (Control control in root.Controls) { yield return control; foreach (var child in All(control)) yield return child; }
        }

        private static void Navigation(MainForm form)
        {
            var tree = All(form).OfType<TreeView>().Single(); var tabs = All(form).OfType<ThemedTabControl>().Single();
            if (!tree.Visible || tree.Nodes.Count != 5 || tree.Nodes.Cast<TreeNode>().Sum(n => n.Nodes.Count) != form.TabCount) throw new Exception("Missing grouped pages");
            if (tree.AccessibilityObject.Name != "Task navigation") throw new Exception("Navigation has no accessible name");
            foreach (var key in new[] { System.Windows.Forms.Keys.D1, System.Windows.Forms.Keys.D9 })
            {
                var message = new Message();
                var handled = typeof(MainForm).GetMethod("ProcessCmdKey", BindingFlags.Instance | BindingFlags.NonPublic).Invoke(form,
                    new object[] { message, System.Windows.Forms.Keys.Control | key });
                form.WaitForIdleForTest();
                if (!(bool)handled || tabs.SelectedIndex != key - System.Windows.Forms.Keys.D1 || tree.SelectedNode.Tag != tabs.SelectedTab)
                    throw new Exception("Keyboard and navigation disagree for " + key + ": handled=" + handled + ", tab=" + tabs.SelectedIndex + ", node=" + tree.SelectedNode.Text + ", busy=" + typeof(MainForm).GetField("_busyDepth", BindingFlags.Instance | BindingFlags.NonPublic).GetValue(form));
            }
            if (tabs.SelectedTab.Top > Ui.Px(3)) throw new Exception("Hidden tab headers still consume vertical space");
        }

        private static void AlertFooter(MainForm form)
        {
            var tabs = All(form).OfType<ThemedTabControl>().Single();
            int index = Enumerable.Range(0, form.TabCount).First(i => form.TabName(i).StartsWith("Alerts"));
            form.SelectTabForTest(index); form.WaitForIdleForTest();
            var page = tabs.SelectedTab; var save = All(page).OfType<Button>().Single(b => b.Text == "Save");
            var scrolling = All(page).OfType<FlowLayoutPanel>().First(p => p.AutoScroll);
            var before = save.PointToScreen(Point.Empty);
            scrolling.AutoScrollPosition = new Point(0, 100000); form.PerformLayout(); Application.DoEvents();
            var after = save.PointToScreen(Point.Empty);
            if (before != after || !page.RectangleToScreen(page.ClientRectangle).Contains(new Rectangle(after, save.Size))) throw new Exception("Save is clipped or moves with the form contents");
            if (!save.TabStop || save.AccessibilityObject.Role != AccessibleRole.PushButton) throw new Exception("Save is not keyboard/accessibility reachable");
            scrolling.AutoScrollPosition = Point.Empty;
        }

        private static void Compact(MainForm form)
        {
            form.Size = new Size(1024, 768); form.PerformLayout(); Application.DoEvents();
            var tree = All(form).OfType<TreeView>().Single();
            var combo = All(form).OfType<ComboBox>().Single(c => c.AccessibleName == "Task navigation");
            if (tree.Visible || !combo.Visible || combo.Items.Count != form.TabCount) throw new Exception("Compact task selector unavailable");
            combo.SelectedIndex = combo.Items.Count - 1; form.WaitForIdleForTest();
            if (All(form).OfType<ThemedTabControl>().Single().SelectedTab.Text != "About") throw new Exception("Compact selection does not open its page");
        }

        private static void Contrast(MainForm form)
        {
            if (Theme.Good != SystemColors.ControlText || Theme.Bad != SystemColors.ControlText) throw new Exception("Semantic colours override high contrast");
            foreach (var link in All(form).OfType<LinkLabel>())
                if (link.LinkColor != SystemColors.HotTrack || link.VisitedLinkColor != SystemColors.HotTrack) throw new Exception("Link overrides system contrast colours");
        }

        private static void Health()
        {
            var now = DateTime.UtcNow;
            var text = MainForm.AgentHealthText(new AgentHealth { LastWatchSuccessUtc = now.AddMinutes(-7), Backlog = 24,
                JournalGap = "wrapped", LastDeliveryError = "SMTP unavailable", BlockingDegradedReason = "peer inspection unavailable", ExhaustedNotifications = 2 }, now);
            foreach (var expected in new[] { "7 min ago", "backlog 24", "wrapped", "SMTP unavailable", "peer inspection unavailable", "2 awaiting explicit retry" })
                if (!text.Contains(expected)) throw new Exception("Missing health information: " + expected);
        }

        private static void Capture(Form form, string output, string name)
        {
            using (var bitmap = new Bitmap(form.Width, form.Height))
            { form.DrawToBitmap(bitmap, new Rectangle(Point.Empty, form.Size)); bitmap.Save(Path.Combine(output, name + ".png")); }
        }
    }
}

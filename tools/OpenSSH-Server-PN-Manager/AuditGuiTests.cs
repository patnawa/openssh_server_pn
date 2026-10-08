using System;
using System.IO;
using System.Reflection;
using System.Windows.Forms;

namespace OpenSSHServerPNManager
{
    internal static class AuditGuiTests
    {
        internal static void Run(Action<string, Func<string>> test, string tmpDir)
        {
            test("GUI: dark group headings use readable text", () =>
            {
                var saved = Theme.Current;
                try
                {
                    using (var form = new Form())
                    using (var group = new GroupBox { Text = "Host keys" })
                    {
                        form.Controls.Add(group); Theme.Current = Theme.Make(true, false);
                        Theme.Apply(form, Theme.Make(false, false));
                        if (group.ForeColor.ToArgb() != Theme.Current.Text.ToArgb())
                            throw new Exception("group caption kept the system light-mode foreground");
                        using (var bitmap = new System.Drawing.Bitmap(group.Width, group.Height))
                        {
                            group.DrawToBitmap(bitmap, group.ClientRectangle);
                            int readable = 0;
                            for (int y = 0; y < group.Font.Height; y++)
                                for (int x = 8; x < 58; x++)
                                {
                                    var pixel = bitmap.GetPixel(x, y);
                                    if (pixel.R > 200 && pixel.G > 200 && pixel.B > 200) readable++;
                                }
                            if (readable < 10) throw new Exception("rendered group caption is dark on a dark background");
                        }
                    }
                }
                finally { Theme.Current = saved; }
                return null;
            });
            test("GUI: dark tabs measure their actual scaled font", () =>
            {
                var saved = Theme.Current;
                try
                {
                    using (var tabs = new ThemedTabControl { Size = new System.Drawing.Size(1500, 300), Font = new System.Drawing.Font("Segoe UI", 14.25f) })
                    {
                        tabs.TabPages.Add("Authentication"); tabs.TabPages.Add("Key generator");
                        var handle = tabs.Handle;
                        Theme.Current = Theme.Make(true, false); tabs.UpdateTheme();
                        for (int i = 0; i < tabs.TabCount; i++)
                        {
                            var size = TextRenderer.MeasureText(tabs.TabPages[i].Text, tabs.Font);
                            var rect = tabs.GetTabRect(i);
                            if (rect.Width < size.Width || rect.Height < size.Height)
                                throw new Exception("scaled tab text exceeds its native tab bounds: " + tabs.TabPages[i].Text);
                        }
                    }
                }
                finally { Theme.Current = saved; }
                return null;
            });
            test("GUI: light-to-high-contrast updates semantic label colors", () =>
            {
                var saved = Theme.Current;
                try
                {
                    var light = Theme.Make(false, false);
                    using (var form = new Form())
                    using (var label = new Label { Text = "Stopped", ForeColor = light.Bad })
                    {
                        form.Controls.Add(label);
                        Theme.Current = Theme.Make(false, true);
                        Theme.Apply(form, light);
                        if (label.ForeColor.ToArgb() != Theme.Current.Bad.ToArgb())
                            throw new Exception("status label retained its light-palette color in high contrast");
                    }
                }
                finally { Theme.Current = saved; }
                return null;
            });
            test("GUI: unsaved alert edits warn on close and Undo clears them", () =>
            {
                var old = Ssh.ConfigDirOverride;
                Ssh.ConfigDirOverride = Path.Combine(tmpDir, "gui-alerts");
                Directory.CreateDirectory(Ssh.ConfigDirOverride);
                try
                {
                    using (var f = new MainForm())
                    {
                        var handle = f.Handle;
                        var load = typeof(MainForm).GetMethod("LoadAlerts", BindingFlags.Instance | BindingFlags.NonPublic);
                        AsyncUiTest.Wait(() => (System.Threading.Tasks.Task)load.Invoke(f, null));
                        var host = (TextBox)typeof(MainForm).GetField("_alHost", BindingFlags.Instance | BindingFlags.NonPublic).GetValue(f);
                        host.Text = "unsaved.example.invalid";
                        if (!f.UnsavedTabsForTest().Contains("the Alerts tab") || !f.TabNamesForTest().Contains("Alerts *"))
                            throw new Exception("editing SMTP host is absent from the close warning and tab marker");
                        AsyncUiTest.Wait(() => (System.Threading.Tasks.Task)load.Invoke(f, null));
                        if (f.UnsavedTabsForTest().Contains("the Alerts tab") || f.TabNamesForTest().Contains("Alerts *"))
                            throw new Exception("Undo left an unsaved alert marker");
                    }
                }
                finally { Ssh.ConfigDirOverride = old; }
                return null;
            });
        }
    }
}

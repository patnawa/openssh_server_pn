using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Threading;
using System.Windows.Forms;

namespace OpenSSHServerPNManager
{
    internal static class AuditStateTests
    {
        private const BindingFlags Private = BindingFlags.Instance | BindingFlags.NonPublic;
        private static void Set(MainForm f, string name, object value) { typeof(MainForm).GetField(name, Private).SetValue(f, value); }
        private static bool Start(MainForm f, Func<SshdConfig, int> collect, Action<int> show)
        {
            return (bool)typeof(MainForm).GetMethod("RefreshInBackground", Private).MakeGenericMethod(typeof(int)).Invoke(f, new object[] { collect, show });
        }
        private static void Pump(int milliseconds)
        {
            var sw = Stopwatch.StartNew();
            while (sw.ElapsedMilliseconds < milliseconds) { Application.DoEvents(); Thread.Sleep(1); }
        }
        private static void WithWindow(Action<MainForm> test)
        {
            bool old = Program.Unattended; Program.Unattended = true;
            try
            {
                using (var f = new MainForm())
                {
                    var handle = f.Handle; // No Show: no service, registry-write, or live configuration operations.
                    Set(f, "_cfg", new SshdConfig());
                    try { test(f); }
                    finally { f.Close(); }
                }
            }
            finally { Program.Unattended = old; }
        }
        internal static void Run(Action<string, Func<string>> test, string tmpDir)
        {
            test("GUI settings: save retains the edited shell option across config reload", () =>
            {
                var dir = Path.Combine(tmpDir, "shell-save-" + Guid.NewGuid().ToString("N"));
                Directory.CreateDirectory(dir);
                var executable = Path.Combine(dir, "sshd.exe");
                using (var compiler = new Microsoft.CSharp.CSharpCodeProvider())
                {
                    var options = new System.CodeDom.Compiler.CompilerParameters { GenerateExecutable = true, OutputAssembly = executable };
                    var result = compiler.CompileAssemblyFromSource(options, "class Fixture { static int Main() { return 0; } }");
                    if (result.Errors.HasErrors) throw new Exception("Could not compile isolated sshd validator fixture");
                }
                var install = typeof(Ssh).GetField("_installDir", BindingFlags.Static | BindingFlags.NonPublic);
                var oldInstall = install.GetValue(null); var oldConfig = Ssh.ConfigDirOverride;
                try
                {
                    install.SetValue(null, dir); Ssh.ConfigDirOverride = dir;
                    File.WriteAllText(Ssh.ConfigPath, "Port 22\r\n");
                    WithWindow(f =>
                    {
                        Set(f, "_cfg", SshdConfig.Load());
                        typeof(MainForm).GetMethod("LoadSettings", Private).Invoke(f, new object[] { false });
                        string actual = null;
                        Set(f, "_writeDefaultShell", (Action<string, string>)((shell, option) => actual = option));
                        var optionBox = (TextBox)typeof(MainForm).GetField("_txtShellOption", Private).GetValue(f);
                        var wanted = optionBox.Text == "-audit-option" ? "-other-audit-option" : "-audit-option";
                        optionBox.Text = wanted;
                        var error = f.SaveSettingsForTest();
                        if (error != null) throw new Exception(error);
                        if (actual != wanted) throw new Exception("shell option writer received " + (actual == null ? "no call" : "a replaced value"));
                    });
                }
                finally
                {
                    install.SetValue(null, oldInstall); Ssh.ConfigDirOverride = oldConfig;
                    try { Directory.Delete(dir, true); } catch { }
                }
                return null;
            });
            test("GUI firewall: unsaved port edits are included in close warnings", () =>
            {
                WithWindow(f =>
                {
                    // Read-only query; ApplyFirewall is never called.
                    typeof(MainForm).GetMethod("LoadFirewall", Private).Invoke(f, null);
                    var port = (NumericUpDown)typeof(MainForm).GetField("_fwPort", Private).GetValue(f);
                    var before = port.Value;
                    port.Value = before == 2222 ? 2223 : 2222;
                    if (!f.UnsavedTabsForTest().Contains("the Firewall tab")) throw new Exception("edited firewall port is omitted from the close warning");
                    port.Value = before;
                    if (f.UnsavedTabsForTest().Contains("the Firewall tab")) throw new Exception("restoring the loaded port still reports unsaved firewall changes");
                });
                return null;
            });
            test("GUI firewall: tab navigation preserves edited port", () =>
            {
                WithWindow(f =>
                {
                    var tabs = (TabControl)typeof(MainForm).GetField("_tabs", Private).GetValue(f);
                    var firewall = (TabPage)typeof(MainForm).GetField("_pgFirewall", Private).GetValue(f);
                    var settings = (TabPage)typeof(MainForm).GetField("_pgSettings", Private).GetValue(f);
                    tabs.SelectedTab = firewall;
                    var port = (NumericUpDown)typeof(MainForm).GetField("_fwPort", Private).GetValue(f);
                    port.Value = 2222;
                    tabs.SelectedTab = settings;
                    tabs.SelectedTab = firewall;
                    if (port.Value != 2222) throw new Exception("tab navigation discarded the edited firewall port");
                });
                return null;
            });
            test("GUI refresh: timed-out completion cannot unlock a running replacement", () =>
            {
                WithWindow(f =>
                {
                    using (var first = new ManualResetEvent(false))
                    using (var second = new ManualResetEvent(false))
                    using (var done = new ManualResetEvent(false))
                    {
                        try
                        {
                            Start(f, c => { first.WaitOne(5000); done.Set(); return 1; }, value => { });
                            Set(f, "_refreshStarted", DateTime.UtcNow.AddMinutes(-2));
                            Start(f, c => { second.WaitOne(5000); return 2; }, value => { });
                            first.Set(); done.WaitOne(5000); Pump(150);
                            if (Start(f, c => 3, value => { })) throw new Exception("obsolete completion allowed a third concurrent refresh");
                        }
                        finally { first.Set(); second.Set(); Pump(150); }
                    }
                });
                return null;
            });
            test("GUI refresh: timed-out completion cannot overwrite a replacement", () =>
            {
                WithWindow(f =>
                {
                    var shown = new List<int>();
                    using (var release = new ManualResetEvent(false))
                    using (var done = new ManualResetEvent(false))
                    {
                        Start(f, c => { release.WaitOne(5000); done.Set(); return 1; }, shown.Add);
                        Set(f, "_refreshStarted", DateTime.UtcNow.AddMinutes(-2));
                        if (!Start(f, c => 2, shown.Add)) throw new Exception("replacement refresh did not start");
                        Pump(150);
                        release.Set(); done.WaitOne(5000); Pump(150);
                        if (shown.Count != 1 || shown[0] != 2) throw new Exception("stale completion painted over replacement: " + string.Join(",", shown));
                    }
                });
                return null;
            });
            test("GUI refresh: foreground work invalidates older background results", () =>
            {
                WithWindow(f =>
                {
                    var shown = new List<int>();
                    using (var release = new ManualResetEvent(false))
                    using (var done = new ManualResetEvent(false))
                    {
                        Start(f, c => { release.WaitOne(5000); done.Set(); return 1; }, shown.Add);
                        typeof(MainForm).GetMethod("BeginBusy", Private).Invoke(f, new object[] { "fixture" });
                        typeof(MainForm).GetMethod("EndBusy", Private).Invoke(f, null);
                        release.Set(); done.WaitOne(5000); Pump(150);
                        if (shown.Count != 0) throw new Exception("pre-operation data was shown after foreground work completed");
                    }
                });
                return null;
            });
        }
    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Windows.Forms;

namespace OpenSSHServerPNManager
{
    /// <summary>Configuration syntax exercised through the same readers and edits as the server window.</summary>
    internal static class SftpConfigurationTests
    {
        private static SshdConfig Config(params string[] lines) { return new SshdConfig { Lines = lines.ToList() }; }
        private static void Equal(string actual, string expected)
        { if (actual != expected) throw new Exception("Expected [" + expected + "], got [" + actual + "]"); }

        internal static void Run(Action<string, Func<string>> test)
        {
            test("subsystems: quoted names are recognized without rewriting an unchanged command", () =>
            {
                const string command = "'C:/Program Files/OpenSSH/sftp-server.exe'  -l INFO";
                var cfg = Config("Subsystem \"sftp\" " + command + " # keep this note");
                Equal(cfg.GetSubsystem("sftp"), command);
                var before = cfg.Text;
                SftpConfig.Apply(cfg, true, true, new List<SftpRule>());
                Equal(cfg.Text, before);
                return null;
            });
            test("subsystems: names are case-sensitive as in sshd", () =>
            {
                var cfg = Config("Subsystem SFTP custom-server.exe", "Subsystem sftp sftp-server.exe");
                Equal(cfg.GetSubsystem("sftp"), "sftp-server.exe");
                cfg.SetSubsystem("sftp", "sftp-server.exe -l INFO");
                Equal(cfg.GetSubsystem("SFTP"), "custom-server.exe");
                cfg.SetSubsystem("sftp", null);
                if (SftpConfig.Read(cfg).Enabled) throw new Exception("Uppercase SFTP was treated as the sftp subsystem");
                Equal(cfg.GetSubsystem("SFTP"), "custom-server.exe");
                return null;
            });
            test("subsystems: disabling removes duplicate definitions instead of activating the next one", () =>
            {
                var cfg = Config("Subsystem sftp sftp-server.exe -l INFO", "Subsystem sftp sftp-server.exe -R",
                    "Subsystem \"sftp\" internal-sftp", "Subsystem powershell pwsh.exe -sshs");
                SftpConfig.Apply(cfg, false, false, new List<SftpRule>());
                if (SftpConfig.Read(cfg).Enabled) throw new Exception("Disabling SFTP activated a duplicate definition");
                Equal(cfg.GetSubsystem("powershell"), "pwsh.exe -sshs");
                return null;
            });
            test("subsystems: an edit preserves the inline comment and unrelated subsystems", () =>
            {
                var cfg = Config("Subsystem \"sftp\" sftp-server.exe # transfer audit", "Subsystem powershell pwsh.exe -sshs");
                cfg.SetSubsystem("sftp", "sftp-server.exe -l INFO");
                Equal(cfg.GetSubsystem("sftp"), "sftp-server.exe -l INFO");
                if (cfg.GetAll("Subsystem").Count != 2 || !cfg.Lines[0].EndsWith("# transfer audit")) throw new Exception("The edit added a duplicate or lost the comment");
                Equal(cfg.GetSubsystem("powershell"), "pwsh.exe -sshs");
                return null;
            });
            test("SFTP logging: grouped flags and repeated log levels follow getopt", () =>
            {
                Equal(SftpConfig.LogLevel("sftp-server.exe -RelDEBUG3"), "DEBUG3");
                Equal(SftpConfig.WithLogging("sftp-server.exe -RelDEBUG3", false), "sftp-server.exe -Re");
                Equal(SftpConfig.WithLogging("sftp-server.exe -Rl ERROR -lINFO", false), "sftp-server.exe -R");
                Equal(SftpConfig.LogLevel("sftp-server.exe -l INFO -RelERROR"), "ERROR");
                return null;
            });
            test("SFTP logging: option operands that begin with -l survive the toggle", () =>
            {
                Equal(SftpConfig.LogLevel("sftp-server.exe -d -lINFO"), null);
                Equal(SftpConfig.WithLogging("sftp-server.exe -d -landing -l INFO", false), "sftp-server.exe -d -landing");
                Equal(SftpConfig.WithLogging("sftp-server.exe -Rd -lINFO", true), "sftp-server.exe -Rd -lINFO -l INFO");
                Equal(SftpConfig.WithLogging("sftp-server.exe -d-landing -u 0022", true), "sftp-server.exe -d-landing -u 0022 -l INFO");
                return null;
            });
            test("SFTP logging: new options precede terminators and ignored arguments stay unchanged", () =>
            {
                foreach (var tail in new[] { "-- -l DEBUG3", "operand -l DEBUG3", "- -l DEBUG3", "-c -l DEBUG3", "-Rc -l DEBUG3" })
                {
                    var command = "sftp-server.exe " + tail;
                    Equal(SftpConfig.LogLevel(command), null);
                    Equal(SftpConfig.WithLogging(command, true), "sftp-server.exe -l INFO " + tail);
                    Equal(SftpConfig.WithLogging(command, false), command);
                }
                return null;
            });
            test("SFTP logging: incomplete and unsupported options are refused without rewriting", () =>
            {
                foreach (var command in new[] { "sftp-server.exe -d", "sftp-server.exe -l", "sftp-server.exe -x custom" })
                {
                    try { SftpConfig.WithLogging(command, true); }
                    catch (ConfigException) { continue; }
                    throw new Exception("Unsafe rewrite accepted: " + command);
                }
                return null;
            });
            test("SFTP rules: an unchanged custom subsystem command remains editable", () =>
            {
                const string command = "custom-sftp.exe --storage example";
                var cfg = Config("Subsystem sftp " + command);
                SftpConfig.Apply(cfg, true, false, new List<SftpRule> { new SftpRule { Name = "partner" } });
                Equal(cfg.GetSubsystem("sftp"), command);
                if (SftpConfig.Read(cfg).Rules.Count != 1) throw new Exception("The SFTP rule was not added");
                return null;
            });
            test("GUI SFTP: quoted subsystem and grouped logging load cleanly and the toggle builds the right command", () =>
            {
                WithWindow(Config("Subsystem \"sftp\" sftp-server.exe -RlINFO"), f =>
                {
                    Call(f, "LoadSftp");
                    if (!((CheckBox)Get(f, "_sfEnabled")).Checked || !((CheckBox)Get(f, "_sfLog")).Checked)
                        throw new Exception("The SFTP checkboxes do not describe the configured server");
                    if (f.UnsavedTabsForTest().Contains("the SFTP tab")) throw new Exception("Loading SFTP created pending edits");
                    ((CheckBox)Get(f, "_sfLog")).Checked = false;
                    Equal(f.SftpCandidateForTest().GetSubsystem("sftp"), "sftp-server.exe -R");
                });
                return null;
            });
            test("GUI settings: quoted numeric and choice values display normally and preserve source text", () =>
            {
                WithWindow(Config("Port \"2222\" # listener", "LogLevel 'verbose'", "MaxAuthTries \"4\""), f =>
                {
                    Call(f, "LoadSettingsFields", new Dictionary<string, string>(), false);
                    Equal(f.FieldTextForTest("Port"), "2222");
                    Equal(f.FieldTextForTest("LogLevel"), "VERBOSE");
                    Equal(f.FieldTextForTest("MaxAuthTries"), "4");
                    if ((bool)Call(f, "SettingsEdited")) throw new Exception("Displaying quoted settings created pending edits");
                    Equal(((SshdConfig)Get(f, "_cfg")).Lines[0], "Port \"2222\" # listener");
                });
                return null;
            });
        }

        private const BindingFlags Members = BindingFlags.Instance | BindingFlags.NonPublic;
        private static object Get(object value, string name) { return value.GetType().GetField(name, Members).GetValue(value); }
        private static object Call(object value, string name, params object[] args) { return value.GetType().GetMethod(name, Members).Invoke(value, args); }

        private static void WithWindow(SshdConfig config, Action<MainForm> body)
        {
            bool old = Program.Unattended;
            Program.Unattended = true;
            try
            {
                AsyncUiTest.EnsureContext();
                using (var f = new MainForm())
                {
                    var handle = f.Handle;
                    typeof(MainForm).GetField("_cfg", Members).SetValue(f, config);
                    try { body(f); }
                    finally { f.Close(); }
                }
            }
            finally { Program.Unattended = old; }
        }
    }
}

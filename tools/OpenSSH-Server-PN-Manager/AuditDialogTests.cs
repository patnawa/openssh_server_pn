using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Windows.Forms;

namespace OpenSSHServerPNManager
{
    internal static class AuditDialogTests
    {
        internal static void Run(Action<string, Func<string>> test, string tmpDir)
        {
            test("GUI: partner access choices are exclusive and reversible", PartnerAccess);
            test("GUI: partner login choices are exclusive and reversible", PartnerLogin);
            test("GUI: partner setup preserves an absolute drive root", PartnerRoot);
            test("GUI: wizard summary discloses enabling a disabled firewall rule", WizardFirewall);
            test("GUI: wizard preserves a disabled firewall rule", WizardKeepsDisabledFirewall);
        }

        private static IEnumerable<Control> All(Control control)
        {
            foreach (Control child in control.Controls) { yield return child; foreach (var c in All(child)) yield return c; }
        }

        public static string PartnerAccess()
        {
            using (var dialog = new PartnerDialog(null, @"C:\SFTP", "", d => { }))
            {
                var full = All(dialog).OfType<RadioButton>().Single(r => r.Text == "Upload and download");
                var read = All(dialog).OfType<RadioButton>().Single(r => r.Text.StartsWith("Download only"));
                read.Checked = true;
                if (full.Checked || !dialog.ReadOnlyAccess) throw new Exception("Download only leaves Upload and download selected.");
                full.Checked = true;
                if (read.Checked || dialog.ReadOnlyAccess) throw new Exception("Cannot switch a partner back to upload and download.");
            }
            return null;
        }

        public static string PartnerLogin()
        {
            using (var dialog = new PartnerDialog(null, @"C:\SFTP", "", d => { }))
            {
                var password = All(dialog).OfType<RadioButton>().Single(r => r.Text.StartsWith("Password ("));
                var key = All(dialog).OfType<RadioButton>().Single(r => r.Text.StartsWith("Public key only"));
                key.Checked = true;
                if (password.Checked || !dialog.KeyOnly) throw new Exception("Public key only leaves Password selected.");
                password.Checked = true;
                if (key.Checked || dialog.KeyOnly) throw new Exception("Cannot switch a partner back to password login.");
                if (!All(dialog).OfType<RadioButton>().Single(r => r.Text == "Upload and download").Checked)
                    throw new Exception("Changing login altered the independent access choice.");
            }
            return null;
        }

        public static string PartnerRoot()
        {
            using (var dialog = new PartnerSetupDialog(new PartnerSetupState { Root = @"C:\" }, new PartnerGroups(), d => { }))
            {
                if (dialog.Root != @"C:\" || Partners.FolderOf(dialog.Root, "auditpartner") != @"C:\auditpartner")
                    throw new Exception("Setup converts C:\\ into a drive-relative root.");
            }
            return null;
        }

        public static string WizardFirewall()
        {
            using (var dialog = new SetupWizard(22, new FirewallRule { Enabled = false, Profiles = 3, Ports = "22" }, null, () => 0, () => { }, owner => null))
            {
                All(dialog).OfType<CheckBox>().Single(c => c.Text.StartsWith("Apply the recommended")).Checked = false;
                var enable = All(dialog).OfType<CheckBox>().SingleOrDefault(c => c.Text.StartsWith("Enable the inbound"));
                if (enable != null) enable.Checked = true;
                dialog.ShowPageForTest(4);
                if (!All(dialog).OfType<Label>().Any(c => c.Text.IndexOf("firewall", StringComparison.OrdinalIgnoreCase) >= 0 && c.Text.IndexOf("enable", StringComparison.OrdinalIgnoreCase) >= 0))
                    throw new Exception("Summary does not disclose that Apply enables the disabled firewall rule.");
            }
            return null;
        }

        public static string WizardKeepsDisabledFirewall()
        {
            using (var dialog = new SetupWizard(22, new FirewallRule { Enabled = false, Profiles = 3, Ports = "22" }, null, () => 0, () => { }, owner => null))
            {
                var plan = (WizardPlan)typeof(SetupWizard).GetMethod("BuildPlan", BindingFlags.NonPublic | BindingFlags.Instance).Invoke(dialog, null);
                if (plan.FirewallEnabled || plan.Profiles != 3) throw new Exception("Wizard silently enables the firewall or discards its saved profile selection.");
            }
            return null;
        }
    }
}

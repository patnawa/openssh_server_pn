// OpenSSH Server Manager for Windows: Hardening

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
    // Hardening checks
    // ------------------------------------------------------------------------------------------
    internal sealed class CheckResult { public string Name; public string Status; public string Detail; }

    // ------------------------------------------------------------------------------------------
    // Security audit: permissions that would let someone other than an administrator take over the server
    // ------------------------------------------------------------------------------------------
    internal static class SecurityAudit
    {
        private static readonly SecurityIdentifier Admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        private static readonly SecurityIdentifier LocalSystem = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        private static readonly SecurityIdentifier CreatorOwner = new SecurityIdentifier(WellKnownSidType.CreatorOwnerSid, null);
        private static readonly SecurityIdentifier TrustedInstaller = new SecurityIdentifier("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");
        // write data, append, write EA, delete child, write attributes, DELETE, WRITE_DAC, WRITE_OWNER, GENERIC_ALL, GENERIC_WRITE
        private const int FileWriteMask = 0x2 | 0x4 | 0x10 | 0x40 | 0x100 | 0x10000 | 0x40000 | 0x80000 | 0x10000000 | 0x40000000;
        // KEY_SET_VALUE, KEY_CREATE_SUB_KEY, KEY_CREATE_LINK, DELETE, WRITE_DAC, WRITE_OWNER, GENERIC_ALL, GENERIC_WRITE
        private const int KeyWriteMask = 0x2 | 0x4 | 0x20 | 0x10000 | 0x40000 | 0x80000 | 0x10000000 | 0x40000000;
        // SERVICE_CHANGE_CONFIG, DELETE, WRITE_DAC, WRITE_OWNER, GENERIC_ALL, GENERIC_WRITE
        private const int ServiceWriteMask = 0x2 | 0x10000 | 0x40000 | 0x80000 | 0x10000000 | 0x40000000;

        private static bool Trusted(SecurityIdentifier sid) { return sid == Admins || sid == LocalSystem || sid == CreatorOwner || sid == TrustedInstaller; }
        private static string Name(SecurityIdentifier sid) { try { return sid.Translate(typeof(NTAccount)).Value; } catch { return sid.Value; } }

        /// <summary>Accounts other than SYSTEM, Administrators and TrustedInstaller that can change (or, with anyAccess, read) a file or folder.</summary>
        public static List<string> FileAccess(string path, bool anyAccess)
        {
            var l = new List<string>();
            FileSystemSecurity fs = Directory.Exists(path) ? (FileSystemSecurity)Directory.GetAccessControl(path) : File.GetAccessControl(path);
            foreach (FileSystemAccessRule r in fs.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            {
                if (r.AccessControlType != AccessControlType.Allow || (r.PropagationFlags & PropagationFlags.InheritOnly) != 0) continue;
                var sid = (SecurityIdentifier)r.IdentityReference;
                if (Trusted(sid)) continue;
                bool write = ((int)r.FileSystemRights & FileWriteMask) != 0;
                if (write || anyAccess) l.Add(Path.GetFileName(path.TrimEnd('\\')) + ": " + Name(sid) + (write ? " can modify" : " can read"));
            }
            return l;
        }

        /// <summary>Install folder and the programs and scripts in it: they run as SYSTEM, so only administrators may change them.</summary>
        public static List<string> InstallFolder()
        {
            var l = FileAccess(Ssh.InstallDir, false);
            foreach (var f in Directory.GetFiles(Ssh.InstallDir))
            {
                var ext = Path.GetExtension(f).ToLowerInvariant();
                if (ext == ".exe" || ext == ".dll" || ext == ".ps1" || ext == ".psm1" || ext == ".psd1") l.AddRange(FileAccess(f, false));
            }
            return l;
        }

        /// <summary>%ProgramData%\ssh, sshd_config and the logs folder may be changed by administrators only; private host keys may not even be read by others.</summary>
        public static List<string> ConfigFolder()
        {
            var l = new List<string>();
            if (!Directory.Exists(Ssh.ConfigDir)) return l;
            l.AddRange(FileAccess(Ssh.ConfigDir, false));
            if (File.Exists(Ssh.ConfigPath)) l.AddRange(FileAccess(Ssh.ConfigPath, false));
            if (Directory.Exists(Ssh.LogDir)) l.AddRange(FileAccess(Ssh.LogDir, false));
            foreach (var k in Directory.GetFiles(Ssh.ConfigDir, "ssh_host_*_key")) l.AddRange(FileAccess(k, true));
            return l;
        }

        public static List<string> RegistryKey(string subKey)
        {
            var l = new List<string>();
            using (var baseKey = Microsoft.Win32.RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, Environment.Is64BitOperatingSystem ? RegistryView.Registry64 : RegistryView.Default))
            using (var k = baseKey.OpenSubKey(subKey))
            {
                if (k == null) return l;
                foreach (RegistryAccessRule r in k.GetAccessControl().GetAccessRules(true, true, typeof(SecurityIdentifier)))
                {
                    if (r.AccessControlType != AccessControlType.Allow || (r.PropagationFlags & PropagationFlags.InheritOnly) != 0) continue;
                    var sid = (SecurityIdentifier)r.IdentityReference;
                    if (!Trusted(sid) && ((int)r.RegistryRights & KeyWriteMask) != 0) l.Add(Name(sid) + " can modify HKLM\\" + subKey);
                }
            }
            return l;
        }

        /// <summary>Accounts other than SYSTEM and Administrators that can reconfigure, delete or re-permission a service.</summary>
        public static List<string> Service(string name)
        {
            var l = new List<string>();
            var r = Proc.Run(Path.Combine(Environment.SystemDirectory, "sc.exe"), "sdshow " + name, 10000);
            var sddl = r.StdOut.Trim();
            if (!r.Ok || !sddl.StartsWith("D:")) return l;
            var sd = new RawSecurityDescriptor(sddl);
            foreach (var ace in sd.DiscretionaryAcl)
            {
                var ca = ace as CommonAce;
                if (ca == null || ca.AceQualifier != AceQualifier.AccessAllowed || Trusted(ca.SecurityIdentifier)) continue;
                if ((ca.AccessMask & ServiceWriteMask) != 0) l.Add(Name(ca.SecurityIdentifier) + " can reconfigure " + name + " (0x" + ca.AccessMask.ToString("X") + ")");
            }
            return l;
        }

        /// <summary>Connected networks whose category is Public (Network List Manager).</summary>
        public static List<string> PublicNetworks()
        {
            var l = new List<string>();
            dynamic nlm = Activator.CreateInstance(Type.GetTypeFromCLSID(new Guid("DCB00C01-570F-4A9B-8D69-199FDBA5723B")));
            foreach (dynamic net in nlm.GetNetworks(1)) // NLM_ENUM_NETWORK_CONNECTED
                if ((int)net.GetCategory() == 0) l.Add((string)net.GetName()); // NLM_NETWORK_CATEGORY_PUBLIC
            return l;
        }
    }

    internal static class Hardening
    {
        public static List<CheckResult> Run(SshdConfig cfg)
        {
            var l = new List<CheckResult>();
            Dictionary<string, string> eff; string effError = null;
            try { eff = Ssh.EffectiveSettings(out effError); } catch (Exception ex) { eff = new Dictionary<string, string>(); effError = ex.Message; }
            Func<string, string> E = k => { string v; return eff.TryGetValue(k, out v) ? v : ""; };
            Action<string, bool, string, string> add = (name, ok, okText, warnText) => l.Add(new CheckResult { Name = name, Status = ok ? "OK" : "WARN", Detail = ok ? okText : warnText });

            var sshd = Services.Status("sshd");
            add("sshd service", sshd.Status == "Running" && sshd.StartMode.StartsWith("Auto"), "running, automatic start", "status " + sshd.Status + ", start mode " + sshd.StartMode);
            var fw = Firewall.Get();
            add("Firewall rule", fw != null && fw.Enabled, fw == null ? "" : "enabled for " + fw.ProfilesText, fw == null ? "no inbound rule for sshd; remote clients cannot connect" : "rule disabled");
            var hk = HostKeys.List();
            add("Host keys", hk.Count >= 1 && hk.All(k => k.Fingerprint != null && k.Fingerprint.StartsWith("SHA256:")), hk.Count + " host key(s) present", "host keys missing or unreadable; use 'Generate missing host keys'");
            // Windows servicing of an in-box OpenSSH capability (adding it, or an update to it) points the sshd or
            // ssh-agent service back at %SystemRoot%\System32\OpenSSH, silently replacing the installed package.
            var inboxDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), @"System32\OpenSSH");
            Func<string, string> ver = p => { try { return File.Exists(p) ? "(" + FileVersionInfo.GetVersionInfo(p).FileVersion + ")" : "(missing)"; } catch { return ""; } };
            foreach (var svcName in new[] { "sshd", "ssh-agent" })
            {
                var img = Services.ImagePath(svcName);
                if (img == null) continue;
                var pkg = Services.PackageExe(Path.GetFileName(img));
                bool hijacked = pkg != null && string.Equals(Path.GetDirectoryName(img).TrimEnd('\\'), inboxDir, StringComparison.OrdinalIgnoreCase);
                add("Service binary (" + svcName + ")", !hijacked, img + " " + ver(img),
                    svcName + " runs the in-box " + img + " " + ver(img) + " instead of the installed " + pkg + " " + ver(pkg) + ". Repair the package (msiexec /fa <package.msi>); remove the in-box capability (Remove-WindowsCapability) so it does not happen again.");
            }
            // Permissions: whoever can change these can run code as SYSTEM or in every administrator's session.
            Action<string, Func<List<string>>, string, string> perm = (name, probe, okText, risk) =>
            {
                try { var w = probe(); add(name, w.Count == 0, okText, risk + ": " + string.Join("; ", w)); }
                catch (Exception ex) { l.Add(new CheckResult { Name = name, Status = "INFO", Detail = "not checked: " + ex.Message }); }
            };
            perm("Install folder permissions", SecurityAudit.InstallFolder, "only administrators can change " + Ssh.InstallDir, "programs that run as SYSTEM can be replaced");
            perm("Configuration permissions", SecurityAudit.ConfigFolder, "sshd_config, logs and host keys are protected; private host keys readable by SYSTEM and Administrators only", "server configuration or host keys are exposed");
            perm("Registry permissions", () => SecurityAudit.RegistryKey(@"SOFTWARE\OpenSSH"), "HKLM\\SOFTWARE\\OpenSSH (DefaultShell) can be changed by administrators only", "the shell of every SSH session can be changed");
            perm("Service permissions", () => SecurityAudit.Service("sshd").Concat(SecurityAudit.Service("ssh-agent")).ToList(), "only administrators can reconfigure sshd and ssh-agent", "a service that runs as SYSTEM can be reconfigured");
            try
            {
                var pub = SecurityAudit.PublicNetworks();
                bool exposed = fw != null && fw.Enabled && (fw.Profiles & 4) != 0 && pub.Count > 0;
                add("Public network exposure", !exposed, pub.Count == 0 ? "no connected network is public" : "the sshd rule does not apply to the public network " + string.Join(", ", pub),
                    "SSH is reachable on the public network " + string.Join(", ", pub) + "; untick Public on the Firewall tab unless the server must be reachable there");
            }
            catch (Exception ex) { l.Add(new CheckResult { Name = "Public network exposure", Status = "INFO", Detail = "not checked: " + ex.Message }); }
            bool adminKeys = File.Exists(Ssh.AdminKeysPath);
            if (adminKeys) { var acl = Acl.Describe(Ssh.AdminKeysPath); add("administrators_authorized_keys ACL", acl == "ACL OK", "restricted to SYSTEM and Administrators", acl.StartsWith("ACL TOO OPEN") ? acl + "; sshd will reject the file (fix on the Keys tab)" : acl); }
            if (eff.Count == 0)
            {
                // Without sshd -T every value-based check below would be judged on empty strings.
                add("Effective settings", false, "", "sshd -T did not report the effective configuration; the checks below use empty values. " + (effError ?? ""));
            }
            // A Windows password alone is enough when password authentication is on and no AuthenticationMethods list pairs it with a key.
            bool pw = E("passwordauthentication") != "no";
            var am = E("authenticationmethods").ToLowerInvariant();
            bool pwAlone = pw && (am.Length == 0 || am == "any" || am.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries).Any(list => list.Split(',').Contains("password") && !list.Split(',').Contains("publickey")));
            add("Password authentication", !pwAlone || !adminKeys,
                !pw ? "Windows authentication (password) off, key-based login only" : !pwAlone ? "the Windows password only together with a public key (AuthenticationMethods " + am + ")" : "Windows authentication on (no administrator keys configured yet, keep it until keys work)",
                "a Windows password alone is enough although administrator keys exist; on the Authentication tab untick Windows authentication or require both");
            add("Keyboard-interactive", E("kbdinteractiveauthentication") == "no", "off",
                "offered, but OpenSSH for Windows has no back end for it: it never logs anyone in, and each client attempt counts against MaxAuthTries. Apply on the Authentication tab, or Apply recommended settings, turns it off");
            add("Empty passwords", E("permitemptypasswords") != "yes", "not permitted", "PermitEmptyPasswords yes is dangerous");
            int tries; int.TryParse(E("maxauthtries"), out tries);
            add("MaxAuthTries", tries > 0 && tries <= 6, tries + " attempts per connection", "value " + E("maxauthtries") + "; 6 or fewer recommended");
            add("Per-source penalties", E("persourcepenalties").StartsWith("crash") || E("persourcepenalties").Contains("authfail"), "automatic temporary blocking of abusive sources is active", "PerSourcePenalties disabled; brute-force sources are not slowed down");
            add("MaxStartups throttling", E("maxstartups").Contains(":"), "random early drop configured (" + E("maxstartups") + ")", "no connection throttling configured");
            int cai; int.TryParse(E("clientaliveinterval"), out cai);
            add("Idle session timeout", cai > 0, "ClientAliveInterval " + cai + " s", "ClientAliveInterval 0: dead sessions are never detected; 300 recommended");
            int lgt; int.TryParse(E("logingracetime"), out lgt);
            add("Login grace time", lgt > 0 && lgt <= 60, "LoginGraceTime " + lgt + " s", "LoginGraceTime " + E("logingracetime") + ": unauthenticated connections stay open long; 60 s or less recommended");
            int rsa; int.TryParse(E("requiredrsasize"), out rsa);
            add("Minimum RSA key size", rsa >= 2048, "RequiredRSASize " + rsa, "RequiredRSASize " + E("requiredrsasize") + ": RSA keys shorter than 2048 bits are accepted; 2048 recommended");
            var lvl = E("loglevel").ToUpperInvariant();
            add("Log level", lvl == "INFO" || lvl == "VERBOSE", lvl + (lvl == "VERBOSE" ? " (logs key fingerprints per login)" : ""), "LogLevel " + lvl + "; INFO or VERBOSE recommended for auditing");
            var kex = E("kexalgorithms");
            add("Key exchange", !kex.Contains("sha1"), kex.Contains("mlkem") || kex.Contains("sntrup") ? "modern set with post-quantum hybrid" : "modern set", "SHA-1 key exchange enabled");
            var hka = E("hostkeyalgorithms");
            add("Host key algorithms", !Regex.IsMatch(hka, @"(^|,)ssh-rsa(,|$)"), "SHA-1 RSA signatures disabled", "ssh-rsa (SHA-1) enabled");
            var ciph = E("ciphers");
            add("Ciphers", !ciph.Contains("cbc") && !ciph.Contains("3des"), "AEAD and CTR ciphers only", "legacy CBC or 3DES ciphers enabled");
            var allow = cfg.Get("AllowGroups") ?? cfg.Get("AllowUsers");
            if (string.IsNullOrEmpty(allow)) { var ea = E("allowgroups"); if (ea.Length == 0) ea = E("allowusers"); if (ea.Length > 0) allow = ea; }
            add("Login restriction", !string.IsNullOrEmpty(allow), "restricted with AllowGroups/AllowUsers: " + allow, "every Windows account with a password may log in; set AllowGroups or AllowUsers");
            var lvlBanner = cfg.Get("Banner");
            l.Add(new CheckResult { Name = "Login banner", Status = string.IsNullOrEmpty(lvlBanner) ? "INFO" : "OK", Detail = string.IsNullOrEmpty(lvlBanner) ? "no legal notice banner configured (optional)" : "Banner " + lvlBanner });
            l.Add(new CheckResult { Name = "Agent forwarding", Status = "INFO", Detail = "AllowAgentForwarding " + E("allowagentforwarding") + "; set 'no' unless clients need to forward their agent" });
            l.Add(new CheckResult { Name = "TCP forwarding", Status = "INFO", Detail = "AllowTcpForwarding " + E("allowtcpforwarding") + ", GatewayPorts " + E("gatewayports") + "; set 'no' for file-transfer-only servers" });
            return l;
        }
    }
}

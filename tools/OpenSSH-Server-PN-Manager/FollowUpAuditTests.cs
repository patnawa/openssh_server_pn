using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Principal;
using System.ServiceProcess;

namespace OpenSSHServerPNManager
{
    /// <summary>Regressions for the follow-up review of the 10.5.7.0 / Manager 2.3.1 sources.</summary>
    internal static class FollowUpAuditTests
    {
        /// <summary>A scripted service: each status read returns the next scripted value (the last one repeats).</summary>
        private sealed class FakeService
        {
            private readonly Queue<ServiceControllerStatus> _reads;
            private ServiceControllerStatus _last;
            public int Controls;
            public Func<ServiceControllerStatus, Exception> OnControl = s => null;
            public FakeService(params ServiceControllerStatus[] reads) { _reads = new Queue<ServiceControllerStatus>(reads); _last = reads[0]; }
            public ServiceControllerStatus Read() { if (_reads.Count > 0) _last = _reads.Dequeue(); return _last; }
            public void Control() { Controls++; var ex = OnControl(_last); if (ex != null) throw ex; }
        }

        private static Exception Move(FakeService svc, ServiceControllerStatus target, int timeoutMs = 2000)
        {
            try { Services.MoveTo("fixture", target, svc.Read, svc.Control, TimeSpan.FromMilliseconds(timeoutMs), ms => { }); return null; }
            catch (Exception ex) { return ex; }
        }

        internal static void Run(Action<string, Func<string>> test, string tmpDir)
        {
            test("services: a refused stop is success when the service is already stopping", () =>
            {
                // Read Running, then the SCM's recovery or another console stops it before our control arrives.
                var svc = new FakeService(ServiceControllerStatus.Running, ServiceControllerStatus.StopPending, ServiceControllerStatus.Stopped);
                svc.OnControl = s => new InvalidOperationException("Cannot stop fixture service on computer '.'.");
                var ex = Move(svc, ServiceControllerStatus.Stopped);
                if (ex != null) throw new Exception("The race failed the stop: " + ex.Message);
                return null;
            });
            test("services: a refused stop of a running service still fails", () =>
            {
                var svc = new FakeService(ServiceControllerStatus.Running);
                svc.OnControl = s => new InvalidOperationException("Cannot stop fixture service on computer '.'.");
                if (!(Move(svc, ServiceControllerStatus.Stopped) is InvalidOperationException)) throw new Exception("A genuine refusal was hidden");
                return null;
            });
            test("services: a refused start is success when the service is already starting", () =>
            {
                var svc = new FakeService(ServiceControllerStatus.Stopped, ServiceControllerStatus.StartPending, ServiceControllerStatus.Running);
                svc.OnControl = s => new InvalidOperationException("An instance of the service is already running.");
                var ex = Move(svc, ServiceControllerStatus.Running);
                if (ex != null) throw new Exception("The race failed the start: " + ex.Message);
                return null;
            });
            test("services: stopping waits for a pending start instead of sending a refused control", () =>
            {
                var svc = new FakeService(ServiceControllerStatus.StartPending, ServiceControllerStatus.StartPending, ServiceControllerStatus.Running, ServiceControllerStatus.Running, ServiceControllerStatus.StopPending, ServiceControllerStatus.Stopped);
                svc.OnControl = s => s == ServiceControllerStatus.StartPending ? new InvalidOperationException("cannot accept control") : null;
                var ex = Move(svc, ServiceControllerStatus.Stopped);
                if (ex != null) throw new Exception(ex.Message);
                if (svc.Controls != 1) throw new Exception("Expected one stop control after the start finished, got " + svc.Controls);
                return null;
            });
            test("services: a service that stops while starting fails at once, not at the timeout", () =>
            {
                var svc = new FakeService(ServiceControllerStatus.Stopped, ServiceControllerStatus.StartPending, ServiceControllerStatus.Stopped);
                var ex = Move(svc, ServiceControllerStatus.Running, 60000);
                if (!(ex is InvalidOperationException) || !ex.Message.Contains("stopped while starting")) throw new Exception("Expected an immediate start failure, got " + (ex == null ? "success" : ex.GetType().Name + ": " + ex.Message));
                return null;
            });
            test("sessions: a logged-in peer is found through its monitor's login, not the TCP owner", () =>
            {
                // As observed on Windows: every connection belongs to the listening sshd.exe (PID 100). Monitor 200 (SYSTEM)
                // logged alice's login; its child 201 is alice's session. 300 is a monitor still at the login prompt.
                var t0 = new DateTime(2026, 10, 8, 6, 0, 0, DateTimeKind.Utc);
                var tcp = new List<TcpConnection>
                {
                    new TcpConnection { Pid = 100, State = 5, LocalPort = 22, RemoteAddress = "192.0.2.7", RemotePort = 50022 },
                    new TcpConnection { Pid = 100, State = 5, LocalPort = 22, RemoteAddress = "198.51.100.9", RemotePort = 40000 },
                };
                var users = new[] { new Sessions.ProcessEntry { Pid = 201, ParentPid = 200, Name = "sshd-session.exe" } };
                var starts = new Dictionary<int, DateTime?> { { 200, t0 }, { 201, t0.AddSeconds(3) } };
                Func<int, DateTime?> start = pid => starts.ContainsKey(pid) ? starts[pid] : null;
                var logins = new List<Sessions.SessionLogin>
                {
                    Sessions.ParseAccepted(200, t0.AddSeconds(2), "Accepted publickey for alice from 192.0.2.7 port 50022 ssh2: ED25519 SHA256:abc"),
                    // The same process id, reused: a login from before this monitor started is not its own.
                    Sessions.ParseAccepted(200, t0.AddHours(-3), "Accepted password for bob from 203.0.113.5 port 1234 ssh2"),
                };
                var known = new Dictionary<string, Sessions.SessionLogin>();
                var found = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                var problem = Sessions.MatchLoggedIn(tcp, users, start, logins, known, found);
                if (problem != null) throw new Exception(problem);
                if (found.Count != 1 || !found.Contains("192.0.2.7")) throw new Exception("found: " + string.Join(", ", found));
                // Later, the circular log no longer has the login: the kept one still identifies the session.
                found.Clear();
                if (Sessions.MatchLoggedIn(tcp, users, start, new List<Sessions.SessionLogin>(), known, found) != null || !found.Contains("192.0.2.7")) throw new Exception("the kept login was not used");
                // Without either, the address is unknown and the caller must not guess.
                if (Sessions.MatchLoggedIn(tcp, users, start, new List<Sessions.SessionLogin>(), new Dictionary<string, Sessions.SessionLogin>(), new HashSet<string>()) == null) throw new Exception("an unknown session was accepted");
                // A session whose connection is gone protects nothing.
                found.Clear();
                if (Sessions.MatchLoggedIn(tcp.Skip(1).ToList(), users, start, logins, new Dictionary<string, Sessions.SessionLogin>(), found) != null || found.Count != 0) throw new Exception("a closed connection was kept");
                return null;
            });
            test("sessions: login lines with spaces, IPv6 and IPv4-mapped addresses", () =>
            {
                var l = Sessions.ParseAccepted(1, DateTime.UtcNow, "Accepted password for contoso\\jane doe from ::1 port 21408 ssh2");
                if (l == null || l.Address != "::1" || l.Port != 21408) throw new Exception("IPv6 login not parsed");
                if (Sessions.ParseAccepted(1, DateTime.UtcNow, "Accepted key ED25519 SHA256:x found at __PROGRAMDATA__/ssh/administrators_authorized_keys:1") != null) throw new Exception("a key-match line was taken for a login");
                if (Sessions.ParseAccepted(1, DateTime.UtcNow, "Failed password for root from 192.0.2.1 port 22 ssh2") != null) throw new Exception("a failure was taken for a login");
                if (Sessions.CanonicalAddress("::ffff:192.0.2.7") != "192.0.2.7" || Sessions.CanonicalAddress("2001:DB8::1") != "2001:db8::1") throw new Exception("addresses not canonical");
                return null;
            });
            test("authorized_keys: a key type inside a quoted option is never taken for the key", () =>
            {
                const string a = "AAAAC3NzaC1lZDI1NTE5AAAAIGVkMjU1MTlzZWxmdGVzdGtleTAwMDAwMDAwMDAwMDAwMDA";
                const string b = "AAAAC3NzaC1lZDI1NTE5AAAAIHNlY29uZGtleWZvcnRoZWZvbGxvd3VwYXVkaXQwMDAwMDA";
                var l1 = "command=\"exec ssh-agent bash -l\" ssh-ed25519 " + a + " u@a";
                var l2 = "command=\"exec ssh-agent bash -l\",no-pty ssh-ed25519 " + b + " u@b";
                if (Keys.Blob(l1) != a || Keys.Blob(l2) != b) throw new Exception("blobs: " + Keys.Blob(l1) + " / " + Keys.Blob(l2));
                if (Keys.Blob("command=\"echo \\\"ssh-rsa AAAAB3NzaC1yc2EAAAADAQAB x\\\"\" ssh-ed25519 " + a + " c") != a) throw new Exception("an escaped quote ended the option");
                if (Keys.Blob("  \tssh-ed25519 " + a + " leading blanks") != a) throw new Exception("leading blanks");
                if (Keys.LooksLikePublicKey("command=\"unterminated ssh-ed25519 " + a)) throw new Exception("sshd refuses an unterminated quote");
                if (Keys.LooksLikePublicKey("from=\"x\" junk ssh-ed25519 " + a)) throw new Exception("text between the options and the key");
                var dir = Path.Combine(tmpDir, "quoted-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(dir);
                var file = Path.Combine(dir, "authorized_keys"); var me = WindowsIdentity.GetCurrent().User;
                File.WriteAllText(file, "# keep\n" + l1 + "\n" + l2 + "\n");
                if (Keys.RemoveKey(file, l1, me) != 1) throw new Exception("not exactly one line removed");
                var left = File.ReadAllText(file);
                if (left.Contains(" u@a") || !left.Contains(l2) || !left.Contains("# keep")) throw new Exception("removed the wrong lines: " + left);
                if (Directory.GetFiles(dir, "*.new-*").Length != 0) throw new Exception("a temporary file was left");
                return null;
            });
            test("PuTTY keys: an Ed25519 private integer shorter than 32 bytes is padded, not refused", () =>
            {
                var pk = Enumerable.Range(1, 32).Select(i => (byte)i).ToArray();
                var stored = Enumerable.Range(100, 31).Select(i => (byte)i).ToArray(); // seed[31] == 0: PuTTY writes 31 bytes
                var pub = new SshWriter().String("ssh-ed25519").String(pk).ToArray();
                var r = new SshReader(KeyFormats.FromPutty("ssh-ed25519", pub, new SshWriter().String(stored).ToArray()));
                if (!r.String().SequenceEqual(pk)) throw new Exception("public key");
                var sk = r.String();
                if (sk.Length != 64 || !sk.Take(31).SequenceEqual(stored) || sk[31] != 0 || !sk.Skip(32).SequenceEqual(pk)) throw new Exception("private key layout");
                try { KeyFormats.FromPutty("ssh-ed25519", pub, new SshWriter().String(new byte[33]).ToArray()); throw new Exception("a 33-byte integer was accepted"); }
                catch (FormatException) { }
                return null;
            });
            test("webhooks: names chosen by clients cannot act as links, Slack controls or mentions", () =>
            {
                var hostile = "accounts tried: [Unlock your account](https://evil.example) <!channel> <https://evil.example|Unlock> @all";
                var slack = Agent.HookBody(false, "Blocked 192.0.2.7", hostile);
                if (slack.Contains("](") || slack.Contains("<!") || slack.Contains("<https") || slack.Contains("@all")) throw new Exception("Slack body: " + slack);
                var teams = Agent.HookBody(true, "Blocked 192.0.2.7", hostile);
                if (teams.Contains("](") || teams.Contains("@all")) throw new Exception("Teams body: " + teams);
                return null;
            });
            test("dates: a Buddhist-calendar culture writes Gregorian years", () =>
            {
                var thread = System.Threading.Thread.CurrentThread; var oldCulture = thread.CurrentCulture; var oldDefault = System.Globalization.CultureInfo.DefaultThreadCurrentCulture;
                try
                {
                    thread.CurrentCulture = new System.Globalization.CultureInfo("th-TH");
                    if (new DateTime(2026, 10, 8).ToString("yyyy-MM-dd") != "2569-10-08") return "th-TH has no Buddhist calendar here; nothing to check";
                    Program.UseGregorianCalendar();
                    var shown = new DateTime(2026, 10, 8).ToString("yyyy-MM-dd");
                    if (shown != "2026-10-08") throw new Exception("th-TH still writes " + shown);
                    if (thread.CurrentCulture.Name != "th-TH") throw new Exception("the culture itself changed to " + thread.CurrentCulture.Name);
                }
                finally { thread.CurrentCulture = oldCulture; System.Globalization.CultureInfo.DefaultThreadCurrentCulture = oldDefault; }
                return null;
            });
            test("partners: setup writes rules only, never the login methods of every account", () =>
            {
                // Values from an included file: global lines written above the Include would override them.
                var cfg = new SshdConfig { Lines = new List<string> { "Include sshd_config.d/*.conf", "Subsystem sftp sftp-server.exe" } };
                PartnerSetup.Apply(cfg, new PartnerGroups(), @"D:\Partners");
                var global = cfg.Lines.TakeWhile(l => !l.TrimStart().StartsWith("Match", StringComparison.OrdinalIgnoreCase)).ToList();
                foreach (var k in new[] { "PasswordAuthentication", "PubkeyAuthentication", "AuthenticationMethods", "GSSAPIAuthentication" })
                    if (global.Any(l => l.TrimStart().StartsWith(k, StringComparison.OrdinalIgnoreCase))) throw new Exception(k + " was written for all accounts:\n" + string.Join("\n", global));
                if (!cfg.Lines.Any(l => l.TrimStart().StartsWith("Match Group", StringComparison.OrdinalIgnoreCase))) throw new Exception("no partner rules were written");
                return null;
            });
            test("partners: names ending in .bak are refused (they would read another partner's key backup)", () =>
            {
                if (Partners.NameError("acme.bak") == null || Partners.NameError("ACME.BAK") == null) throw new Exception(".bak accepted");
                if (Partners.NameError("acme.backup") != null) throw new Exception("refused acme.backup: " + Partners.NameError("acme.backup"));
                return null;
            });
            test("services: a stop that never completes times out", () =>
            {
                var svc = new FakeService(ServiceControllerStatus.Running, ServiceControllerStatus.StopPending);
                var ex = Move(svc, ServiceControllerStatus.Stopped, 50);
                if (!(ex is System.ServiceProcess.TimeoutException)) throw new Exception("Expected a timeout, got " + (ex == null ? "success" : ex.GetType().Name));
                return null;
            });
        }
    }
}

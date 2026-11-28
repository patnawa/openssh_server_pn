using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace OpenSSHServerPNManager
{
    internal static class RemainingAreaTests
    {
        internal static void Run(Action<string, Func<string>> test, string tmpDir)
        {
            test("sorting: mixed numeric and text cells have a transitive order", () =>
            {
                var values = new[] { "2", "10", "1a", "", "NaN", "Infinity", "-3", "2026-10-13 12:00:00", "A", "a", "1e100" };
                foreach (var a in values) foreach (var b in values) foreach (var c in values)
                    if (ListSorter.CompareText(a, b) < 0 && ListSorter.CompareText(b, c) < 0 && ListSorter.CompareText(a, c) >= 0)
                        throw new Exception("comparison cycle: " + a + " < " + b + " < " + c);
                return null;
            });
            test("failed logins: text a client sends at the end of a message cannot name the address to block", () =>
            {
                string user;
                foreach (var spoof in new[]
                {
                    "sshd-session: Received disconnect from 198.51.100.1 port 5000:11: Invalid user x from 192.0.2.99 port 22 [preauth]",
                    "Received disconnect from 198.51.100.1 port 5000:11: Failed password for root from 192.0.2.99 port 22 ssh2 [preauth]",
                    "sshd-session: Unable to negotiate with 198.51.100.1 port 5000: no matching key exchange method found. Their offer: Invalid user x from 192.0.2.99 port 22 [preauth]",
                    "sshd: Disconnected from 198.51.100.1 port 5000: Connection closed by invalid user x 192.0.2.99 port 22 [preauth]",
                })
                    if (EventLogs.FailedLoginAddress(spoof, out user) != null) throw new Exception("a client-chosen address was counted: " + spoof);
                // Real failures, with their process and level prefixes, are still read.
                if (EventLogs.FailedLoginAddress("sshd-session: error: maximum authentication attempts exceeded for root from 192.0.2.11 port 1 ssh2 [preauth]", out user) != "192.0.2.11") throw new Exception("process and level prefixes");
                if (EventLogs.FailedLoginAddress("Invalid user x from 10.1.2.3 port 22 from 203.0.113.5 port 5555", out user) != "203.0.113.5") throw new Exception("no prefix");
                return null;
            });
            test("failed logins: only events sshd can have written count, not one an ordinary account wrote", () =>
            {
                foreach (var sid in new[] { "S-1-5-18", "S-1-5-111-3847866527-469524349-687026318-516638107-1125189541-4242", "S-1-5-80-1-2-3-4-5", "S-1-5-19", "S-1-5-20" })
                    if (!EventLogs.TrustedFailureWriter(new System.Security.Principal.SecurityIdentifier(sid))) throw new Exception("refused sshd's own writer " + sid);
                if (!EventLogs.TrustedFailureWriter(null)) throw new Exception("refused an event that names no account");
                foreach (var sid in new[] { "S-1-5-21-1004336348-1177238915-682003330-1001", "S-1-5-32-545", "S-1-5-7", "S-1-1-0", "S-1-5-11", "S-1-12-1-1-2-3-4" })
                    if (EventLogs.TrustedFailureWriter(new System.Security.Principal.SecurityIdentifier(sid))) throw new Exception("counted an event written by " + sid);
                return null;
            });
            test("locks: a lock another account created is not waited for", () =>
            {
                var me = System.Security.Principal.WindowsIdentity.GetCurrent().User;
                var admins = new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid, null);
                var system = new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.LocalSystemSid, null);
                var other = new System.Security.Principal.SecurityIdentifier("S-1-5-21-1004336348-1177238915-682003330-1001");
                if (!Acl.TrustedLockOwner(me, me) || !Acl.TrustedLockOwner(admins, me) || !Acl.TrustedLockOwner(system, me)) throw new Exception("refused its own, Administrators' or SYSTEM's lock");
                if (Acl.TrustedLockOwner(other, me) || Acl.TrustedLockOwner(null, me) || Acl.TrustedLockOwner(other, null)) throw new Exception("trusted another account's lock");
                // The same lock taken twice in one process: the second opens the first one's mutex and must still be let in.
                var name = "Local\\OpenSSHServerPNManager.Test." + Guid.NewGuid().ToString("N");
                bool inner = false;
                if (!Agent.WithStateLock(name, 1000, () => { var t = new System.Threading.Thread(() => { inner = !Agent.WithStateLock(name, 0, () => { }); }); t.Start(); t.Join(); })) throw new Exception("the lock was not taken");
                if (!inner) throw new Exception("a held lock of this account was refused or taken twice");
                return null;
            });
            test("sorting: adjacent large byte counts remain distinct", () =>
            {
                if (ListSorter.CompareText("9007199254740992", "9007199254740993") >= 0 || ListSorter.CompareText("9223372036854775807", "9223372036854775806") <= 0)
                    throw new Exception("integer precision was lost");
                return null;
            });
            test("transfers: literal apostrophes and formula escapes round-trip independently", () =>
            {
                foreach (var value in new[] { "'=invoice", "'@supplier", "''quoted", "'plain", "=SUM(A1)", "+name", "-path", "@name", "-12", "comma,\"quote\"", "\u0e44\u0e17\u0e22" })
                {
                    var record = Record(value); record.User = record.Address = record.Detail = value;
                    var decoded = Transfers.FromCsv(Transfers.CsvLine(record));
                    if (decoded == null || decoded.File != value || decoded.User != value || decoded.Address != value || decoded.Detail != value)
                        throw new Exception("text changed: " + value);
                }
                return null;
            });
            test("transfers: legacy seven and eleven column archives still decode", () =>
            {
                var seven = Transfers.FromCsv("2026-10-13 12:00:00,acme,,upload,'=invoice,42,ok");
                var eleven = Transfers.FromCsv("2026-10-13T12:00:00.0000000,acme,,upload,'=invoice,42,ok,OpenSSH/Operational,generation,9,identity");
                if (seven == null || seven.File != "=invoice" || eleven == null || eleven.File != "=invoice" || eleven.EventRecordId != 9 || eleven.EventIdentity != "identity")
                    throw new Exception("legacy archive compatibility lost");
                return null;
            });
            test("transfers: torn quotes and trailing quote garbage are rejected", () =>
            {
                foreach (var detail in new[] { "\"partial", "un\"quoted", "\"closed\"junk", "\"escaped\"\"" })
                    if (Transfers.FromCsv("2026-10-13 12:00:00,acme,,upload,/invoice,42," + detail) != null)
                        throw new Exception("accepted malformed CSV: " + detail);
                return null;
            });
            test("transfers: incomplete identity columns and invalid record IDs are rejected", () =>
            {
                foreach (var suffix in new[] { ",channel", ",channel,generation", ",channel,generation,9", ",channel,generation,broken,identity", ",channel,generation,9,identity,unknown" })
                    if (Transfers.FromCsv("2026-10-13 12:00:00,acme,,upload,/invoice,42,ok" + suffix) != null)
                        throw new Exception("accepted incomplete or unsupported metadata: " + suffix);
                return null;
            });
            test("archive: missing and damaged headers cannot discard the first transfer", () => WithArchive(tmpDir, () =>
            {
                var record = Record("/first"); var next = Record("/next");
                foreach (var header in new[] { "", Transfers.CsvLine(record), "Time,Account,Address,Action,WRONG,Bytes,Detail" })
                {
                    var file = TransferArchive.FileOf(record.Time); Directory.CreateDirectory(TransferArchive.Dir);
                    File.WriteAllText(file, header + "\r\n" + Transfers.CsvLine(record) + "\r\n");
                    var before = File.ReadAllBytes(file); var problems = new List<string>();
                    TransferArchive.Read(record.Time.Date, record.Time.Date.AddDays(1), problems);
                    bool refused = false; try { Agent.Archive(new List<TransferRecord> { next }); } catch (InvalidDataException) { refused = true; }
                    if (!refused || problems.Count == 0 || !File.ReadAllBytes(file).SequenceEqual(before)) throw new Exception("damaged header was read or overwritten");
                }
                return null;
            }));
            test("archive: torn rows leave the existing file untouched", () => WithArchive(tmpDir, () =>
            {
                var record = Record("/next"); var file = TransferArchive.FileOf(record.Time); Directory.CreateDirectory(TransferArchive.Dir);
                File.WriteAllText(file, string.Join(",", Transfers.CsvHeader) + "\r\n2026-10-13 12:00:00,acme,,upload,/invoice,42,\"partial\r\n");
                var before = File.ReadAllBytes(file);
                bool refused = false; try { Agent.Archive(new List<TransferRecord> { record }); } catch (InvalidDataException) { refused = true; }
                if (!refused || !File.ReadAllBytes(file).SequenceEqual(before)) throw new Exception("torn archive was overwritten");
                return null;
            }));
            test("archive: apostrophe names survive append and replay without duplicates", () => WithArchive(tmpDir, () =>
            {
                var first = Record("'=invoice"); var second = Record("/second");
                if (Agent.Archive(new List<TransferRecord> { first }) != 1 || Agent.Archive(new List<TransferRecord> { second }) != 1 || Agent.Archive(new List<TransferRecord> { first, second }) != 0)
                    throw new Exception("archive replay added duplicates");
                var problems = new List<string>(); var read = TransferArchive.Read(first.Time.Date, first.Time.Date.AddDays(1), problems);
                if (problems.Count != 0 || read.Count != 2 || read[0].File != first.File) throw new Exception("append changed an archived name");
                return null;
            }));
            test("archive: legacy headers and records migrate together without changing text", () => WithArchive(tmpDir, () =>
            {
                var record = Record("/next"); var file = TransferArchive.FileOf(record.Time); Directory.CreateDirectory(TransferArchive.Dir);
                foreach (int columns in new[] { 7, 11 })
                {
                    var legacy = "2026-10-13 12:00:00,acme,,upload,'=invoice,42,ok" + (columns == 11 ? ",channel,generation,9,identity" : "");
                    File.WriteAllText(file, string.Join(",", Transfers.CsvHeader.Take(columns)) + "\r\n" + legacy + "\r\n");
                    if (Agent.Archive(new List<TransferRecord> { record }) != 1) throw new Exception("legacy record was not retained");
                    var problems = new List<string>(); var read = TransferArchive.Read(record.Time.Date, record.Time.Date.AddDays(1), problems);
                    if (problems.Count != 0 || read.Count != 2 || read[0].File != "=invoice" || Agent.Archive(new List<TransferRecord> { record }) != 0)
                        throw new Exception("legacy migration changed text or replayed an event");
                }
                return null;
            }));
            test("archive: a missing text encoding column cannot be mistaken for a legacy row", () => WithArchive(tmpDir, () =>
            {
                var record = Record("/next"); var file = TransferArchive.FileOf(record.Time); Directory.CreateDirectory(TransferArchive.Dir);
                File.WriteAllText(file, string.Join(",", Transfers.CsvHeader) + "\r\n2026-10-13 12:00:00,acme,,upload,''=invoice,42,ok,channel,generation,9,identity\r\n");
                var before = File.ReadAllBytes(file);
                bool refused = false; try { Agent.Archive(new List<TransferRecord> { record }); } catch (InvalidDataException) { refused = true; }
                if (!refused || !File.ReadAllBytes(file).SequenceEqual(before)) throw new Exception("truncated encoding was accepted");
                return null;
            }));
            test("client: malformed and empty Host arguments cannot be saved", () =>
            {
                foreach (var pattern in new[] { "\"unclosed", "# comment", "\"\"", "web \"\"", "web\nHost *" })
                {
                    bool refused = false;
                    try { SshClient.WithHost(new string[0], null, pattern, new Dictionary<string, string>()); } catch (ConfigException) { refused = true; }
                    if (!refused) throw new Exception("invalid Host pattern was written: " + pattern);
                }
                return null;
            });
            test("client: Host wildcards, negation, quotes and comments keep their syntax", () =>
            {
                foreach (var pattern in new[] { "web *.example !private.example", "\"quoted\" alias", "web # note" })
                    if (SshClient.WithHost(new string[0], null, pattern, new Dictionary<string, string>())[0] != "Host " + pattern)
                        throw new Exception("valid Host syntax was changed");
                return null;
            });
            test("backups: overflowing counters and invalid dates are ignored and never pruned", () =>
            {
                var directory = Path.Combine(tmpDir, "backup-names"); Directory.CreateDirectory(directory); var path = Path.Combine(directory, "sshd_config");
                var valid = new[] { path + ".bak.20261013-120000-2", path + ".bak.20261013-120000" };
                var other = new[] { path + ".bak.20261013-120000-99999999999999999999", path + ".bak.99999999-999999", path + ".bak.20260230-120000", path + ".bak.20261013-120000-0" };
                foreach (var file in valid.Concat(other)) File.WriteAllText(file, "Port 22\r\n");
                if (!SshdConfig.ListBackups(path).SequenceEqual(valid)) throw new Exception("backup recognition or order is wrong");
                if (SshdConfig.PruneBackups(path, 1) != 1 || !File.Exists(valid[0]) || other.Any(file => !File.Exists(file))) throw new Exception("pruning removed an unrelated file");
                return null;
            });
        }

        private static TransferRecord Record(string file)
        {
            return new TransferRecord { Time = new DateTime(2026, 10, 13, 12, 0, 0), User = "acme", Action = TransferRecord.Upload, File = file, Bytes = 42 };
        }

        private static string WithArchive(string tmpDir, Func<string> body)
        {
            var previous = AgentStorage.RootOverride;
            try
            {
                AgentStorage.RootOverride = Path.Combine(tmpDir, "archive-" + Guid.NewGuid().ToString("N"));
                using (new AuditAgentTests.ScratchStorage(tmpDir)) return body();
            }
            finally { AgentStorage.RootOverride = previous; }
        }
    }
}

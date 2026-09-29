using System;
using System.Linq;

namespace OpenSSHServerPNManager
{
    internal static class AuditTransferTests
    {
        internal static void Run(Action<string, Func<string>> test, string tmpDir)
        {
            test("transfers: verbose and debug explanations preserve open refusals", () =>
            {
                var records = Transfers.Parse(new[] {
                    E("open \"/a\" flags WRITE,CREATE,TRUNCATE mode 0666"),
                    E("Refusing open request in read-only mode"),
                    E("request 3: sent status 3"), E("sent status Permission denied") });
                if (records.Count != 1 || records[0].Action != TransferRecord.Refused || records[0].File != "/a")
                    throw new Exception("verbose open refusal missing");
                return null;
            });
            test("transfers: concurrent empty uploads keep their own open flags", () =>
            {
                var records = Transfers.Parse(new[] {
                    E("open \"/a\" flags WRITE,CREATE,TRUNCATE mode 0666"),
                    E("open \"/b\" flags WRITE,CREATE,TRUNCATE mode 0666"),
                    E("close \"/a\" bytes read 0 written 0"),
                    E("close \"/b\" bytes read 0 written 0") });
                if (records.Count != 2 || records.Any(r => r.Action != TransferRecord.Upload))
                    throw new Exception("expected two empty uploads; got " + records.Count);
                return null;
            });
            test("transfers: interrupted sessions retain forced-close byte counts", () =>
            {
                var records = Transfers.Parse(new[] { E("forced close \"/partial\" bytes read 0 written 8192") });
                if (records.Count != 1 || records[0].Bytes != 8192 || records[0].Action != TransferRecord.Upload)
                    throw new Exception("forced-close upload missing");
                return null;
            });
            test("transfers: a refused directory operation is not an upload refusal", () =>
            {
                var records = Transfers.Parse(new[] {
                    E("open \"/a\" flags WRITE,CREATE,TRUNCATE mode 0666"),
                    E("opendir \"/private\""), E("sent status Permission denied"),
                    E("close \"/a\" bytes read 0 written 0") });
                if (records.Count != 1 || records[0].Action != TransferRecord.Upload)
                    throw new Exception("unrelated refusal consumed the active upload: " + string.Join(",", records.Select(r => r.Action)));
                return null;
            });
        }

        private static Transfers.SftpEvent E(string text)
        {
            return new Transfers.SftpEvent { Time = new DateTime(2026, 9, 29), Pid = 123, Text = "user: acme: " + text + " [postauth]" };
        }
    }
}

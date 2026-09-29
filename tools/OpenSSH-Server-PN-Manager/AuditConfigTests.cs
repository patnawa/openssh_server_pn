using System;
using System.Collections.Generic;
using System.Linq;

namespace OpenSSHServerPNManager
{
    internal static class AuditConfigTests
    {
        public static void Run(Action<string, Func<string>> test, string tmpDir)
        {
            test("config audit: edited scalar takes precedence over Include", () =>
            {
                var cfg = new SshdConfig { Lines = new List<string> { "Include overrides.conf", "PasswordAuthentication yes # local choice", "PasswordAuthentication yes", "Port 22", "Port 2222" } };
                cfg.Set("PasswordAuthentication", "no");
                var settings = cfg.GetAll("PasswordAuthentication");
                if (settings.Count != 1 || settings[0].Key >= cfg.GetAll("Include")[0].Key || settings[0].Value != "no")
                    throw new Exception("included PasswordAuthentication still wins over the edited value");
                if (!cfg.Text.Contains("no # local choice")) throw new Exception("the original comment was lost");
                cfg.SetFirst("Port", "2200");
                if (!cfg.GetAll("Port").Select(x => x.Value).SequenceEqual(new[] { "2200", "2222" })) throw new Exception("repeatable ports were lost");
                return null;
            });
            test("config audit: any authentication overrides included requirements", () =>
            {
                var cfg = new SshdConfig { Lines = new List<string> { "Include overrides.conf", "AuthenticationMethods publickey,password" } };
                AuthConfig.Apply(cfg, new AuthMethods(), null);
                if (cfg.Get("AuthenticationMethods") != "any" || cfg.GetAll("AuthenticationMethods")[0].Key >= cfg.GetAll("Include")[0].Key)
                    throw new Exception("included multifactor requirement survives choosing any authentication method");
                return null;
            });
            test("config audit: escaped home tokens are literal folder names", () =>
            {
                const string folder = @"C:\SFTP\%%h\%u";
                var problem = SftpConfig.FolderError(folder);
                if (problem != null) throw new Exception("valid literal %h rejected: " + problem);
                if (SftpConfig.ExpandFolder(folder, "alice", null) != @"C:\SFTP\%h\alice")
                    throw new Exception("literal %h incorrectly requires an account profile");
                if (SftpConfig.ExpandFolder(@"C:\SFTP\%%%h", "alice", null) != null) throw new Exception("real home token did not require a profile");
                if (SftpConfig.FolderError(@"C:\SFTP\%h") == null) throw new Exception("embedded real home token was allowed");
                return null;
            });
        }
    }
}

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace OpenSSHServerPNManager
{
    /// <summary>
    /// A client file as shown to the user. Edits carry this snapshot through the entire dialog:
    /// a changed file is a conflict, and a replacement failure never falls back to truncating it.
    /// </summary>
    internal sealed class ClientFileSnapshot
    {
        public string Path { get; private set; }
        public bool Exists { get; private set; }
        public string Text { get; private set; }
        public List<string> Lines { get; private set; }
        private byte[] _digest;
        private Encoding _encoding;
        private string _newline;

        public static ClientFileSnapshot Read(string path)
        {
            var result = new ClientFileSnapshot { Path = System.IO.Path.GetFullPath(path), Exists = File.Exists(path), _encoding = new UTF8Encoding(false), Text = "", Lines = new List<string>(), _newline = "\r\n" };
            if (!result.Exists) return result;
            var bytes = File.ReadAllBytes(path);
            using (var hash = SHA256.Create()) result._digest = hash.ComputeHash(bytes);
            using (var reader = new StreamReader(new MemoryStream(bytes), new UTF8Encoding(false, true), true))
            {
                result.Text = reader.ReadToEnd(); result._encoding = reader.CurrentEncoding;
            }
            // A BOM-free UTF-8 source stays BOM-free.
            if (result._encoding.CodePage == 65001) result._encoding = new UTF8Encoding(bytes.Length >= 3 && bytes[0] == 0xef && bytes[1] == 0xbb && bytes[2] == 0xbf, true);
            result._newline = result.Text.Contains("\r\n") ? "\r\n" : "\n";
            using (var reader = new StringReader(result.Text)) { string line; while ((line = reader.ReadLine()) != null) result.Lines.Add(line); }
            return result;
        }

        public void RequireUnchanged()
        {
            if (File.Exists(Path) != Exists) throw Conflict();
            if (!Exists) return;
            using (var hash = SHA256.Create())
                if (!hash.ComputeHash(File.ReadAllBytes(Path)).SequenceEqual(_digest)) throw Conflict();
        }

        private ConfigException Conflict()
        {
            return new ConfigException("The file changed after it was displayed: " + Path + ". No changes were saved. Refresh the Client tab and review the current file before trying again.");
        }

        public void Write(IList<string> lines, string backupSuffix, bool privateFile)
        {
            ConfigurationTransaction.Locked(Path, () =>
            {
                RequireUnchanged();
                var directory = System.IO.Path.GetDirectoryName(Path);
                Directory.CreateDirectory(directory);
                var temp = System.IO.Path.Combine(directory, ".pn-client-" + Guid.NewGuid().ToString("N") + ".tmp");
                try
                {
                    using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                    using (var writer = new StreamWriter(stream, _encoding))
                    {
                        writer.Write(string.Join(_newline, lines));
                        if (lines.Count > 0) writer.Write(_newline);
                        writer.Flush(); stream.Flush(true);
                    }
                    if (privateFile) KeyGen.EnsurePrivateKeyAcl(temp);
                    RequireUnchanged();
                    if (Exists) File.Replace(temp, Path, Path + backupSuffix);
                    else File.Move(temp, Path); // Fails if another writer created the destination.
                    if (privateFile) KeyGen.EnsurePrivateKeyAcl(Path);
                }
                finally { if (File.Exists(temp)) File.Delete(temp); }
                return true;
            });
        }
    }
}

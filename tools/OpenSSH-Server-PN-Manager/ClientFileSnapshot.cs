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
        /// <summary>The file is not UTF-8 (an ANSI file saved by Notepad): it is read and written as Latin-1, one character per byte.</summary>
        public bool NotUtf8 { get; private set; }
        /// <summary>Test hook: runs after the last check, just before the file is replaced.</summary>
        internal Action BeforeReplace;
        private byte[] _digest;
        private Encoding _encoding;
        private byte[] _preamble = new byte[0];
        private string _newline;

        private static readonly Encoding Latin1 = Encoding.GetEncoding(28591, EncoderFallback.ExceptionFallback, DecoderFallback.ExceptionFallback);

        public static ClientFileSnapshot Read(string path)
        {
            var result = new ClientFileSnapshot { Path = System.IO.Path.GetFullPath(path), Exists = File.Exists(path), _encoding = new UTF8Encoding(false, true), Text = "", Lines = new List<string>(), _newline = "\r\n" };
            if (!result.Exists) return result;
            var bytes = File.ReadAllBytes(path);
            using (var hash = SHA256.Create()) result._digest = hash.ComputeHash(bytes);
            int bom = bytes.Length >= 3 && bytes[0] == 0xef && bytes[1] == 0xbb && bytes[2] == 0xbf ? 3 : 0;
            if (bom == 0 && bytes.Length >= 2 && ((bytes[0] == 0xff && bytes[1] == 0xfe) || (bytes[0] == 0xfe && bytes[1] == 0xff) || (bytes.Length >= 4 && bytes[0] == 0 && bytes[1] == 0 && bytes[2] == 0xfe && bytes[3] == 0xff)))
            {
                // UTF-16 or UTF-32 with its byte order mark, written back the same way.
                using (var reader = new StreamReader(new MemoryStream(bytes), true)) { result.Text = reader.ReadToEnd(); result._encoding = reader.CurrentEncoding; }
                result._preamble = result._encoding.GetPreamble();
            }
            else
            {
                // A BOM-free UTF-8 source stays BOM-free.
                if (bom > 0) result._preamble = new byte[] { 0xef, 0xbb, 0xbf };
                try { result.Text = result._encoding.GetString(bytes, bom, bytes.Length - bom); }
                catch (DecoderFallbackException)
                {
                    // Latin-1 maps each byte to one character and back, so the lines an edit does not change keep their bytes.
                    result.NotUtf8 = true; result._encoding = Latin1;
                    result.Text = Latin1.GetString(bytes, bom, bytes.Length - bom);
                }
            }
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

        private bool Matches(byte[] bytes)
        {
            using (var hash = SHA256.Create()) return hash.ComputeHash(bytes).SequenceEqual(_digest);
        }

        /// <summary>Whether a file holds exactly the displayed bytes; false when it is missing or cannot be read.</summary>
        private bool Holds(string file)
        {
            try { return Matches(File.ReadAllBytes(file)); }
            catch (IOException) { return false; }
            catch (UnauthorizedAccessException) { return false; }
        }

        private ConfigException Conflict()
        {
            return new ConfigException("The file changed after it was displayed: " + Path + ". No changes were saved. Refresh the Client tab and review the current file before trying again.");
        }

        public void Write(IList<string> lines, string backupSuffix, bool privateFile)
        {
            byte[] data;
            try { data = _encoding.GetBytes(string.Join(_newline, lines) + (lines.Count > 0 ? _newline : "")); }
            catch (EncoderFallbackException ex)
            {
                if (!NotUtf8) throw;
                throw new ConfigException(Path + " is not UTF-8 text (probably saved as ANSI by Notepad). Its bytes are kept as they are, so characters such as \"" + ex.CharUnknown + "\" cannot be added to it. Nothing was saved.\n\nOpen the file in Notepad, save it with the encoding UTF-8, then Refresh the Client tab.");
            }
            ConfigurationTransaction.Locked(Path, () =>
            {
                RequireUnchanged();
                var directory = System.IO.Path.GetDirectoryName(Path);
                Directory.CreateDirectory(directory);
                var temp = System.IO.Path.Combine(directory, ".pn-client-" + Guid.NewGuid().ToString("N") + ".tmp");
                bool keepTemp = false;
                try
                {
                    using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                    {
                        stream.Write(_preamble, 0, _preamble.Length); stream.Write(data, 0, data.Length);
                        stream.Flush(true);
                    }
                    if (privateFile) KeyGen.EnsurePrivateKeyAcl(temp);
                    RequireUnchanged();
                    if (BeforeReplace != null) BeforeReplace();
                    if (!Exists) File.Move(temp, Path); // Fails if another writer created the destination.
                    else
                    {
                        var backup = Path + backupSuffix;
                        try { File.Replace(temp, Path, backup); }
                        catch (IOException ex)
                        {
                            // ssh appends to known_hosts without the manager's lock. When it does so during the replace, the
                            // replace can stop half-way: the backup then holds the displayed file and only the temporary file
                            // holds the edit.
                            byte[] current = null; bool open = false;
                            if (File.Exists(Path))
                                try { current = File.ReadAllBytes(Path); }
                                catch (IOException) { open = true; }
                                catch (UnauthorizedAccessException) { open = true; }
                            if (current != null && Matches(current)) throw;
                            // A backup left by an earlier save is not the displayed version: only its bytes tell.
                            bool backupHolds = Holds(backup);
                            // A writer that keeps the file open (ssh appending a host key) blocks both the replace and the read:
                            // the file is still there and was not replaced.
                            if (open && !backupHolds)
                                throw new ConfigException("Another program has " + Path + " open, so it was not replaced (" + ex.Message.Trim() + "). No changes were saved.\n\nWait until that program closes the file, then Refresh the Client tab and try again.");
                            keepTemp = true;
                            var unsaved = Path + ".unsaved";
                            try { if (File.Exists(unsaved)) File.Delete(unsaved); File.Move(temp, unsaved); }
                            catch (IOException) { unsaved = temp; }
                            catch (UnauthorizedAccessException) { unsaved = temp; }
                            throw new ConfigException("Saving " + Path + " failed (" + ex.Message.Trim() + "). Another program changed the file at the same moment.\n\nYour edit is kept in " + unsaved +
                                (backupHolds ? "\nThe version you saw is kept in " + backup : current != null ? "\n" + Path + " was not replaced: it holds the other program's version." : "") +
                                "\n\nCompare your edit with the current file, then Refresh the Client tab.");
                        }
                        if (privateFile) KeyGen.EnsurePrivateKeyAcl(Path);
                        // The last check and the replace are separate steps: an append in between lands in the backup.
                        if (!Holds(backup))
                            throw new ConfigException("Your edit was saved in " + Path + ", but another program changed the file while it was being saved. Its version is kept in " + backup + ": compare the two before saving again.");
                        return true;
                    }
                    if (privateFile) KeyGen.EnsurePrivateKeyAcl(Path);
                }
                finally { if (!keepTemp && File.Exists(temp)) File.Delete(temp); }
                return true;
            });
        }
    }
}

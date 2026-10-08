// OpenSSH Server PN Manager: key files

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace OpenSSHServerPNManager
{
    // ------------------------------------------------------------------------------------------
    // Private key files in the OpenSSH format and in PuTTY's .ppk format (versions 2 and 3), read and written in memory:
    // the key material never goes to a temporary file. What is written here is checked with ssh-keygen by the callers.
    // ------------------------------------------------------------------------------------------

    /// <summary>A wrong passphrase, or none given for an encrypted key.</summary>
    internal sealed class WrongPassphraseException : ConfigException { public WrongPassphraseException(string m) : base(m) { } }

    /// <summary>Reads the SSH wire encoding (RFC 4251): uint32, string, and mpint as a string of its bytes.</summary>
    internal sealed class SshReader
    {
        private readonly byte[] _b; private int _p;
        public SshReader(byte[] b) { _b = b ?? new byte[0]; }
        public int Position { get { return _p; } }
        public int Remaining { get { return _b.Length - _p; } }
        public byte Byte() { Need(1); return _b[_p++]; }
        public uint UInt32() { Need(4); uint v = (uint)_b[_p] << 24 | (uint)_b[_p + 1] << 16 | (uint)_b[_p + 2] << 8 | _b[_p + 3]; _p += 4; return v; }
        public byte[] Bytes(int n) { Need(n); var r = new byte[n]; Buffer.BlockCopy(_b, _p, r, 0, n); _p += n; return r; }
        public byte[] String() { uint n = UInt32(); if (n > (uint)Remaining) throw Short(); return Bytes((int)n); }
        public string Text() { return Encoding.UTF8.GetString(String()); }
        private void Need(int n) { if (n < 0 || n > Remaining) throw Short(); }
        private static Exception Short() { return new FormatException("The key file is damaged: it ends in the middle of a value."); }
    }

    /// <summary>Writes the SSH wire encoding. Clear() wipes the buffer when it held private key material.</summary>
    internal sealed class SshWriter
    {
        private readonly MemoryStream _m = new MemoryStream();
        public int Length { get { return (int)_m.Length; } }
        public SshWriter Byte(byte b) { _m.WriteByte(b); return this; }
        public SshWriter UInt32(uint v) { _m.WriteByte((byte)(v >> 24)); _m.WriteByte((byte)(v >> 16)); _m.WriteByte((byte)(v >> 8)); _m.WriteByte((byte)v); return this; }
        public SshWriter Raw(byte[] b) { _m.Write(b, 0, b.Length); return this; }
        public SshWriter String(byte[] b) { UInt32((uint)b.Length); return Raw(b); }
        public SshWriter String(string s) { return String(Encoding.UTF8.GetBytes(s ?? "")); }
        public byte[] ToArray() { return _m.ToArray(); }
        public void Clear() { var b = _m.GetBuffer(); Array.Clear(b, 0, b.Length); _m.SetLength(0); }
    }

    /// <summary>A private key in memory: the public key blob, the private fields in the order of OpenSSH's format, and the comment.</summary>
    internal sealed class PrivateKeyData
    {
        public string Type; public byte[] PublicBlob; public byte[] Private; public string Comment = "";
        public string PublicLine { get { return Type + " " + Convert.ToBase64String(PublicBlob) + (string.IsNullOrEmpty(Comment) ? "" : " " + Comment); } }
        public void Clear() { if (Private != null) Array.Clear(Private, 0, Private.Length); }
    }

    internal static class KeyFormats
    {
        /// <summary>The key types that PuTTY, WinSCP and FileZilla use, and so the ones a .ppk file can hold.</summary>
        public static readonly string[] PuttyTypes = { "ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "ssh-rsa" };
        public static bool PuttyCanUse(string type) { return PuttyTypes.Contains(type); }

        /// <summary>Number of fields a key type has in OpenSSH's private section, or -1 for a type this program does not convert.</summary>
        public static int PrivateFieldCount(string type) { return type == "ssh-ed25519" ? 2 : type == "ssh-rsa" ? 6 : PuttyCanUse(type) ? 3 : -1; }

        /// <summary>A readable name of a key type with its size, from the public key blob: "Ed25519", "RSA 3072", "ECDSA P-256".</summary>
        public static string Describe(byte[] publicBlob)
        {
            try
            {
                var r = new SshReader(publicBlob); var type = r.Text();
                switch (type)
                {
                    case "ssh-ed25519": return "Ed25519";
                    case "ssh-rsa": { r.String(); var n = r.String(); int i = 0; while (i < n.Length && n[i] == 0) i++; int bits = (n.Length - i) * 8; if (i < n.Length) for (int b = 0x80; b > 0 && (n[i] & b) == 0; b >>= 1) bits--; return "RSA " + bits; }
                    case "ecdsa-sha2-nistp256": return "ECDSA P-256";
                    case "ecdsa-sha2-nistp384": return "ECDSA P-384";
                    case "ecdsa-sha2-nistp521": return "ECDSA P-521";
                    case "ssh-mldsa44-ed25519@openssh.com": return "ML-DSA-44 + Ed25519 (post-quantum, experimental)";
                    case "sk-ssh-ed25519@openssh.com": return "Ed25519 on a FIDO security key";
                    case "sk-ecdsa-sha2-nistp256@openssh.com": return "ECDSA P-256 on a FIDO security key";
                    case "ssh-dss": return "DSA (no longer supported by OpenSSH)";
                    default: return type;
                }
            }
            catch (FormatException) { return "?"; }
        }

        /// <summary>PuTTY's private blob of a key: Ed25519 the 32-byte seed; ECDSA the exponent; RSA d, p, q, iqmp.</summary>
        public static byte[] ToPutty(PrivateKeyData k)
        {
            if (!PuttyCanUse(k.Type)) throw new ConfigException("PuTTY, WinSCP and FileZilla cannot use keys of type " + k.Type + ".");
            var r = new SshReader(k.Private); var w = new SshWriter();
            switch (k.Type)
            {
                case "ssh-ed25519": { r.String(); var sk = r.String(); w.String(Sub(sk, 0, 32)); Array.Clear(sk, 0, sk.Length); break; }
                case "ssh-rsa": { r.String(); r.String(); var d = r.String(); var iqmp = r.String(); var p = r.String(); var q = r.String(); w.String(d).String(p).String(q).String(iqmp); Wipe(d, iqmp, p, q); break; }
                default: { r.String(); r.String(); var d = r.String(); w.String(d); Wipe(d); break; }
            }
            try { return w.ToArray(); } finally { w.Clear(); }
        }

        /// <summary>The private fields in OpenSSH's order from PuTTY's public and private blobs.</summary>
        public static byte[] FromPutty(string type, byte[] publicBlob, byte[] puttyPrivate)
        {
            if (!PuttyCanUse(type)) throw new ConfigException("Keys of type " + type + " cannot be converted.");
            var pub = new SshReader(publicBlob);
            if (pub.Text() != type) throw new FormatException("The key file is damaged: the key type in its header differs from the key's.");
            var r = new SshReader(puttyPrivate); var w = new SshWriter();
            switch (type)
            {
                case "ssh-ed25519":
                {
                    // PuTTY writes the private key as a minimal little-endian integer (put_mp_le_unsigned): one key in 256
                    // ends in a zero byte and is stored shorter. Zeros on the right restore the 32-byte seed.
                    var pk = pub.String(); var stored = r.String();
                    if (pk.Length != 32 || stored.Length == 0 || stored.Length > 32) throw new FormatException("The key file is damaged: an Ed25519 key has 32-byte keys.");
                    var seed = new byte[32]; Buffer.BlockCopy(stored, 0, seed, 0, stored.Length);
                    var sk = seed.Concat(pk).ToArray(); w.String(pk).String(sk); Wipe(stored, seed, sk); break;
                }
                case "ssh-rsa":
                {
                    var e = pub.String(); var n = pub.String(); var d = r.String(); var p = r.String(); var q = r.String(); var iqmp = r.String();
                    w.String(n).String(e).String(d).String(iqmp).String(p).String(q); Wipe(d, p, q, iqmp); break;
                }
                default: { var curve = pub.String(); var point = pub.String(); var d = r.String(); w.String(curve).String(point).String(d); Wipe(d); break; }
            }
            try { return w.ToArray(); } finally { w.Clear(); }
        }

        /// <summary>Checks that the public values inside the private fields are the ones of the public key blob.</summary>
        public static void CheckConsistent(PrivateKeyData k)
        {
            var pub = new SshReader(k.PublicBlob); pub.Text(); var r = new SshReader(k.Private);
            bool ok;
            switch (k.Type)
            {
                case "ssh-ed25519": { var pk = pub.String(); var pk2 = r.String(); var sk = r.String(); ok = pk.Length == 32 && Equal(pk, pk2) && sk.Length == 64 && Equal(Sub(sk, 32, 32), pk); Wipe(sk); break; }
                case "ssh-rsa": { var e = pub.String(); var n = pub.String(); ok = Equal(r.String(), n) & Equal(r.String(), e); break; }
                default: { ok = Equal(pub.String(), r.String()) & Equal(pub.String(), r.String()); break; }
            }
            if (!ok || pub.Remaining != 0) throw new FormatException("The key file is damaged: its private and public parts do not belong together.");
        }

        internal static byte[] Sub(byte[] b, int offset, int count) { var r = new byte[count]; Buffer.BlockCopy(b, offset, r, 0, count); return r; }
        internal static void Wipe(params byte[][] arrays) { foreach (var a in arrays) if (a != null) Array.Clear(a, 0, a.Length); }
        internal static bool Equal(byte[] a, byte[] b)
        {
            if (a == null || b == null || a.Length != b.Length) return false;
            int d = 0; for (int i = 0; i < a.Length; i++) d |= a[i] ^ b[i];
            return d == 0;
        }
        internal static byte[] Random(int n) { var b = new byte[n]; using (var rng = new RNGCryptoServiceProvider()) rng.GetBytes(b); return b; }
        internal static string Hex(byte[] b) { return string.Concat(b.Select(x => x.ToString("x2"))); }
        internal static byte[] FromHex(string s)
        {
            s = (s ?? "").Trim();
            if (s.Length % 2 != 0 || !Regex.IsMatch(s, "^[0-9A-Fa-f]*$")) throw new FormatException("The key file is damaged: a hexadecimal value is not valid.");
            return Enumerable.Range(0, s.Length / 2).Select(i => byte.Parse(s.Substring(2 * i, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture)).ToArray();
        }
    }

    // ------------------------------------------------------------------------------------------
    // OpenSSH format: "openssh-key-v1", with bcrypt_pbkdf and aes256-ctr when a passphrase protects it (sshkey.c)
    // ------------------------------------------------------------------------------------------
    internal sealed class OpenSshKeyFile
    {
        // Put together at run time, so that scanners for leaked keys do not take this source file for a key.
        public static readonly string Begin = "-----BEGIN OPENSSH " + "PRIVATE KEY-----", End = "-----END OPENSSH " + "PRIVATE KEY-----";
        private static readonly byte[] Magic = Encoding.ASCII.GetBytes("openssh-key-v1\0");
        /// <summary>ssh-keygen's number of bcrypt_pbkdf rounds (DEFAULT_ROUNDS in sshkey.c).</summary>
        public const int DefaultRounds = 24;
        /// <summary>The most bcrypt_pbkdf rounds a key file may ask for here (some 15 s of work).</summary>
        public const int MaxRounds = 2000;

        public string Cipher, Kdf; public byte[] KdfOptions, PublicBlob, Body;
        public bool Encrypted { get { return Cipher != "none"; } }
        public string Type { get { return new SshReader(PublicBlob).Text(); } }

        // Cipher name => key length and whether it is CTR (else CBC). ssh-keygen writes aes256-ctr; -Z can choose others.
        private static readonly Dictionary<string, KeyValuePair<int, bool>> Ciphers = new Dictionary<string, KeyValuePair<int, bool>>
        {
            { "aes128-ctr", new KeyValuePair<int, bool>(16, true) }, { "aes192-ctr", new KeyValuePair<int, bool>(24, true) }, { "aes256-ctr", new KeyValuePair<int, bool>(32, true) },
            { "aes128-cbc", new KeyValuePair<int, bool>(16, false) }, { "aes192-cbc", new KeyValuePair<int, bool>(24, false) }, { "aes256-cbc", new KeyValuePair<int, bool>(32, false) },
        };

        /// <summary>True when this program can decrypt the file itself (else ssh-keygen rewrites a copy first).</summary>
        public bool CanDecrypt { get { return (!Encrypted || Kdf == "bcrypt" && Ciphers.ContainsKey(Cipher)) && KeyFormats.PrivateFieldCount(Type) > 0; } }

        public static bool IsOpenSsh(string text) { return text != null && text.Contains(Begin); }

        public static OpenSshKeyFile Parse(string text)
        {
            int b = text.IndexOf(Begin, StringComparison.Ordinal), e = b < 0 ? -1 : text.IndexOf(End, b + Begin.Length, StringComparison.Ordinal);
            if (b < 0 || e < 0) throw new FormatException("Not a private key in the OpenSSH format.");
            byte[] blob;
            try { blob = Convert.FromBase64String(new string(text.Substring(b + Begin.Length, e - b - Begin.Length).Where(c => !char.IsWhiteSpace(c)).ToArray())); }
            catch (FormatException) { throw new FormatException("The OpenSSH private key is damaged: its text is not valid base64."); }
            if (blob.Length < Magic.Length || !KeyFormats.Equal(KeyFormats.Sub(blob, 0, Magic.Length), Magic)) throw new FormatException("Not a private key in the OpenSSH format (openssh-key-v1).");
            var r = new SshReader(blob); r.Bytes(Magic.Length);
            var f = new OpenSshKeyFile { Cipher = r.Text(), Kdf = r.Text(), KdfOptions = r.String() };
            if (r.UInt32() != 1) throw new FormatException("The file holds more than one key.");
            f.PublicBlob = r.String(); f.Body = r.String();
            if (f.PublicBlob.Length == 0) throw new FormatException("The OpenSSH private key is damaged: it has no public key.");
            return f;
        }

        public PrivateKeyData Decrypt(string passphrase)
        {
            if (KeyFormats.PrivateFieldCount(Type) < 0) throw new ConfigException("Keys of type " + Type + " cannot be converted by this program.");
            byte[] plain;
            if (!Encrypted) plain = (byte[])Body.Clone();
            else
            {
                KeyValuePair<int, bool> c;
                if (Kdf != "bcrypt" || !Ciphers.TryGetValue(Cipher, out c)) throw new ConfigException("The key is encrypted with " + Cipher + " (" + Kdf + "), which this program does not read.");
                if (string.IsNullOrEmpty(passphrase)) throw new WrongPassphraseException("The key is protected by a passphrase: enter it.");
                var ko = new SshReader(KdfOptions); var salt = ko.String(); var rounds = ko.UInt32();
                if (salt.Length == 0 || rounds < 1 || Body.Length % 16 != 0) throw new FormatException("The OpenSSH private key is damaged: its encryption settings are not valid.");
                // ssh-keygen uses 24 rounds unless told otherwise (-a); the limit keeps a crafted file from taking many minutes here.
                if (rounds > MaxRounds) throw new ConfigException("The key is protected with " + rounds + " rounds of bcrypt_pbkdf; this program reads keys with up to " + MaxRounds + ". ssh-keygen -p -a 100 -f <key> saves it with fewer.");
                var km = BcryptPbkdf.Derive(Encoding.UTF8.GetBytes(passphrase), salt, (int)rounds, c.Key + 16);
                try { plain = AesModes.Transform(KeyFormats.Sub(km, 0, c.Key), KeyFormats.Sub(km, c.Key, 16), Body, c.Value, false); }
                finally { KeyFormats.Wipe(km); }
            }
            try
            {
                var r = new SshReader(plain);
                uint check1 = r.UInt32(), check2 = r.UInt32();
                if (check1 != check2) { if (Encrypted) throw new WrongPassphraseException("Wrong passphrase."); throw new FormatException("The OpenSSH private key is damaged (its check values differ)."); }
                var type = r.Text();
                if (type != Type) throw new FormatException("The OpenSSH private key is damaged: its private part is of another type than its public key.");
                int start = r.Position;
                for (int i = 0; i < KeyFormats.PrivateFieldCount(type); i++) r.String();
                var k = new PrivateKeyData { Type = type, PublicBlob = PublicBlob, Private = KeyFormats.Sub(plain, start, r.Position - start), Comment = r.Text() };
                for (int i = 1; r.Remaining > 0; i++) if (r.Byte() != (byte)i) throw new FormatException("The OpenSSH private key is damaged (its padding is not valid).");
                KeyFormats.CheckConsistent(k);
                return k;
            }
            finally { KeyFormats.Wipe(plain); }
        }

        /// <summary>The key in the OpenSSH format as ssh-keygen writes it: aes256-ctr and bcrypt_pbkdf with a passphrase, else unencrypted.</summary>
        public static string Write(PrivateKeyData k, string passphrase, int rounds = DefaultRounds)
        {
            bool enc = !string.IsNullOrEmpty(passphrase);
            var kdfOptions = new byte[0]; byte[] km = null;
            if (enc)
            {
                var salt = KeyFormats.Random(16);
                kdfOptions = new SshWriter().String(salt).UInt32((uint)rounds).ToArray();
                km = BcryptPbkdf.Derive(Encoding.UTF8.GetBytes(passphrase), salt, rounds, 48);
            }
            var check = BitConverter.ToUInt32(KeyFormats.Random(4), 0);
            var w = new SshWriter().UInt32(check).UInt32(check).String(k.Type).Raw(k.Private).String(k.Comment ?? "");
            for (int i = 1; w.Length % (enc ? 16 : 8) != 0; i++) w.Byte((byte)i);
            var plain = w.ToArray(); w.Clear();
            try
            {
                var body = enc ? AesModes.Transform(KeyFormats.Sub(km, 0, 32), KeyFormats.Sub(km, 32, 16), plain, true, true) : plain;
                var blob = new SshWriter().Raw(Magic).String(enc ? "aes256-ctr" : "none").String(enc ? "bcrypt" : "none").String(kdfOptions).UInt32(1).String(k.PublicBlob).String(body).ToArray();
                var b64 = Convert.ToBase64String(blob);
                var sb = new StringBuilder(Begin).Append('\n');
                for (int i = 0; i < b64.Length; i += 70) sb.Append(b64, i, Math.Min(70, b64.Length - i)).Append('\n');
                return sb.Append(End).Append('\n').ToString();
            }
            finally { KeyFormats.Wipe(plain, km); }
        }
    }

    // ------------------------------------------------------------------------------------------
    // PuTTY format (.ppk) versions 2 and 3, as PuTTY's sshpubk.c reads and writes them
    // ------------------------------------------------------------------------------------------
    internal sealed class PpkFile
    {
        internal static readonly string Header = "PuTTY-User-" + "Key-File-";
        /// <summary>Argon2 settings of the version 3 files written here: PuTTYgen's memory and parallelism, a fixed number of passes.</summary>
        public const int Argon2Memory = 8192, Argon2Passes = 24, Argon2Parallelism = 1;

        public int Version; public string Algorithm, Encryption, Comment, Kdf;
        public byte[] CommentBytes, PublicBlob, PrivateBlob, Mac, Salt;
        public int Memory, Passes, Parallelism;
        public bool Encrypted { get { return Encryption != "none"; } }

        public static bool IsPpk(string text) { return text != null && text.TrimStart((char)0xFEFF, ' ', '\t', '\r', '\n').StartsWith(Header, StringComparison.Ordinal); }

        /// <summary>Parses a .ppk file. The bytes are read one to one (Latin-1), so that the MAC covers the comment exactly as stored.</summary>
        public static PpkFile Parse(byte[] data)
        {
            var text = Encoding.GetEncoding(28591).GetString(data);
            if (text.StartsWith(new string(new[] { (char)0xEF, (char)0xBB, (char)0xBF }), StringComparison.Ordinal)) text = text.Substring(3); // a UTF-8 byte order mark
            var lines = text.Replace("\r\n", "\n").Split('\n');
            int i = 0;
            Func<string> next = () => { if (i >= lines.Length) throw new FormatException("The PuTTY key file ends too early."); return lines[i++]; };
            Func<string, string> header = name =>
            {
                var l = next(); var p = name + ": ";
                if (!l.StartsWith(p, StringComparison.Ordinal)) throw new FormatException("The PuTTY key file has no \"" + name + "\" line where one belongs.");
                return l.Substring(p.Length);
            };
            Func<string, int, int> number = (name, max) =>
            {
                int n; var v = header(name);
                if (!int.TryParse(v, NumberStyles.None, CultureInfo.InvariantCulture, out n) || n > max) throw new FormatException("The PuTTY key file has a value that is not valid: " + name + ": " + v);
                return n;
            };
            Func<string, byte[]> body = name =>
            {
                int n = number(name, 100000); var sb = new StringBuilder();
                for (int k = 0; k < n; k++) sb.Append(next().Trim());
                try { return Convert.FromBase64String(sb.ToString()); }
                catch (FormatException) { throw new FormatException("The PuTTY key file is damaged: its " + name + " are not valid base64."); }
            };
            var m = Regex.Match(next(), "^" + Regex.Escape(Header) + @"(\d+): (\S+)$");
            if (!m.Success) throw new FormatException("Not a PuTTY key file.");
            int version; int.TryParse(m.Groups[1].Value, NumberStyles.None, CultureInfo.InvariantCulture, out version);
            var f = new PpkFile { Version = version, Algorithm = m.Groups[2].Value };
            if (f.Version != 2 && f.Version != 3) throw new ConfigException("This PuTTY key file has format version " + f.Version + "; versions 2 and 3 can be read. Open it in PuTTYgen and save it again.");
            f.Encryption = header("Encryption");
            if (f.Encryption != "none" && f.Encryption != "aes256-cbc") throw new ConfigException("The PuTTY key is encrypted with " + f.Encryption + ", which this program does not read.");
            f.CommentBytes = Encoding.GetEncoding(28591).GetBytes(header("Comment"));
            try { f.Comment = new UTF8Encoding(false, true).GetString(f.CommentBytes); } catch (DecoderFallbackException) { f.Comment = Encoding.Default.GetString(f.CommentBytes); }
            f.PublicBlob = body("Public-Lines");
            if (f.Version == 3 && f.Encrypted)
            {
                f.Kdf = header("Key-Derivation");
                if (f.Kdf != "Argon2d" && f.Kdf != "Argon2i" && f.Kdf != "Argon2id") throw new ConfigException("The PuTTY key uses the key derivation " + f.Kdf + ", which this program does not read.");
                f.Memory = number("Argon2-Memory", 4 * 1024 * 1024); f.Passes = number("Argon2-Passes", 100000); f.Parallelism = number("Argon2-Parallelism", 255);
                f.Salt = KeyFormats.FromHex(header("Argon2-Salt"));
            }
            f.PrivateBlob = body("Private-Lines");
            f.Mac = KeyFormats.FromHex(header("Private-MAC"));
            if (new SshReader(f.PublicBlob).Text() != f.Algorithm) throw new FormatException("The PuTTY key file is damaged: the key type in its header differs from the key's.");
            return f;
        }

        /// <summary>Upper limits for the Argon2 settings of a .ppk file: 256 MiB, and memory times passes of 16 GiB (some 15 s here).</summary>
        private const long MaxArgon2MemoryKiB = 256 * 1024, MaxArgon2WorkKiB = 16L * 1024 * 1024;

        public PrivateKeyData Decrypt(string passphrase)
        {
            if (!KeyFormats.PuttyCanUse(Algorithm)) throw new ConfigException("Keys of type " + Algorithm + " cannot be converted.");
            if (!Encrypted) return Decrypt(new byte[0]);
            if (string.IsNullOrEmpty(passphrase)) throw new WrongPassphraseException("The PuTTY key is protected by a passphrase: enter it.");
            try { return Decrypt(Encoding.UTF8.GetBytes(passphrase)); }
            catch (WrongPassphraseException) when (passphrase.Any(c => c > 127))
            {
                // PuTTYgen on Windows may have read a passphrase with other characters in the ANSI code page.
                return Decrypt(Encoding.Default.GetBytes(passphrase));
            }
        }

        private PrivateKeyData Decrypt(byte[] pass)
        {
            byte[] key = null, iv = null, macKey = null, plain = null;
            try
            {
                if (Version == 2) Version2Keys(pass, Encrypted, out key, out iv, out macKey);
                else if (Encrypted)
                {
                    // PuTTYgen's defaults are 8 MiB and a few dozen passes; the limits keep a crafted file from taking all memory or hours.
                    if (Memory < 8 || Memory > MaxArgon2MemoryKiB || Passes < 1 || (long)Memory * Passes > MaxArgon2WorkKiB || Parallelism < 1 || Parallelism > 64 || Memory < 8 * Parallelism || Salt.Length == 0)
                        throw new ConfigException("The PuTTY key's Argon2 settings are outside what this program reads (memory " + Memory + " KiB, passes " + Passes + ", parallelism " + Parallelism +
                            "; at most 256 MiB, and memory times passes at most 16 GiB). Open it in PuTTYgen and save it with the usual settings.");
                    var o = Argon2.Hash(Kdf == "Argon2d" ? Argon2.Kind.D : Kdf == "Argon2i" ? Argon2.Kind.I : Argon2.Kind.Id, pass, Salt, Memory, Passes, Parallelism, 80);
                    key = KeyFormats.Sub(o, 0, 32); iv = KeyFormats.Sub(o, 32, 16); macKey = KeyFormats.Sub(o, 48, 32); KeyFormats.Wipe(o);
                }
                else macKey = new byte[0];
                if (Encrypted && PrivateBlob.Length % 16 != 0) throw new FormatException("The PuTTY key file is damaged: its private part has a wrong length.");
                plain = Encrypted ? AesModes.Transform(key, iv, PrivateBlob, false, false) : (byte[])PrivateBlob.Clone();
                var macData = new SshWriter().String(Algorithm).String(Encryption).String(CommentBytes).String(PublicBlob).String(plain);
                var mac = Version == 2 ? Hashes.Hmac(Hashes.Sha1, 64, macKey, macData.ToArray()) : Hashes.Hmac(Hashes.Sha256, 64, macKey, macData.ToArray());
                macData.Clear();
                if (!KeyFormats.Equal(mac, Mac))
                {
                    if (Encrypted) throw new WrongPassphraseException("Wrong passphrase.");
                    throw new FormatException("The PuTTY key file is damaged: its MAC does not match.");
                }
                var k = new PrivateKeyData { Type = Algorithm, PublicBlob = PublicBlob, Comment = Comment, Private = KeyFormats.FromPutty(Algorithm, PublicBlob, plain) };
                KeyFormats.CheckConsistent(k);
                return k;
            }
            finally { KeyFormats.Wipe(pass, key, iv, macKey, plain); }
        }

        /// <summary>True for a passphrase a .ppk file can carry the same way in PuTTY: ASCII characters without control characters.</summary>
        public static bool PassphraseFits(string passphrase) { return (passphrase ?? "").All(c => c >= 32 && c <= 126); }

        /// <summary>Version 2: AES key from SHA-1 of the passphrase, a zero IV, and the MAC key "putty-private-key-file-mac-key" + passphrase.</summary>
        private static void Version2Keys(byte[] pass, bool encrypted, out byte[] key, out byte[] iv, out byte[] macKey)
        {
            macKey = Hashes.Sha1(new[] { Encoding.ASCII.GetBytes("putty-private-key-file-mac-key"), pass });
            key = iv = null;
            if (!encrypted) return;
            var k = Hashes.Sha1(new[] { new byte[] { 0, 0, 0, 0 }, pass }).Concat(Hashes.Sha1(new[] { new byte[] { 0, 0, 0, 1 }, pass })).ToArray();
            key = KeyFormats.Sub(k, 0, 32); KeyFormats.Wipe(k);
            iv = new byte[16];
        }

        /// <summary>The key as a .ppk file of version 2 or 3; with a passphrase, aes256-cbc (and Argon2id in version 3).</summary>
        public static string Write(PrivateKeyData k, string passphrase, int version)
        {
            if (version != 2 && version != 3) throw new ArgumentOutOfRangeException("version");
            if ((k.Comment ?? "").Any(char.IsControl)) throw new ConfigException("The key's comment has a line break, which a .ppk file cannot hold.");
            var priv = KeyFormats.ToPutty(k);
            bool enc = !string.IsNullOrEmpty(passphrase);
            var pass = enc ? Encoding.UTF8.GetBytes(passphrase) : new byte[0];
            var encryption = enc ? "aes256-cbc" : "none";
            byte[] plain = priv, key = null, iv = null, macKey = null, salt = null;
            try
            {
                if (enc)
                {
                    // Padding to the AES block size with the start of SHA-1 of the private blob, as PuTTY does.
                    plain = new byte[(priv.Length + 15) / 16 * 16];
                    Buffer.BlockCopy(priv, 0, plain, 0, priv.Length);
                    var h = Hashes.Sha1(new[] { priv }); Buffer.BlockCopy(h, 0, plain, priv.Length, plain.Length - priv.Length);
                }
                if (version == 2) Version2Keys(pass, enc, out key, out iv, out macKey);
                else if (enc)
                {
                    salt = KeyFormats.Random(16);
                    var o = Argon2.Hash(Argon2.Kind.Id, pass, salt, Argon2Memory, Argon2Passes, Argon2Parallelism, 80);
                    key = KeyFormats.Sub(o, 0, 32); iv = KeyFormats.Sub(o, 32, 16); macKey = KeyFormats.Sub(o, 48, 32); KeyFormats.Wipe(o);
                }
                else macKey = new byte[0];
                var comment = k.Comment ?? "";
                var macData = new SshWriter().String(k.Type).String(encryption).String(comment).String(k.PublicBlob).String(plain);
                var mac = version == 2 ? Hashes.Hmac(Hashes.Sha1, 64, macKey, macData.ToArray()) : Hashes.Hmac(Hashes.Sha256, 64, macKey, macData.ToArray());
                macData.Clear();
                var stored = enc ? AesModes.Transform(key, iv, plain, false, true) : plain;
                var sb = new StringBuilder();
                sb.Append(Header).Append(version).Append(": ").Append(k.Type).Append('\n');
                sb.Append("Encryption: ").Append(encryption).Append('\n');
                sb.Append("Comment: ").Append(comment).Append('\n');
                Lines(sb, "Public-Lines", k.PublicBlob);
                if (version == 3 && enc)
                {
                    sb.Append("Key-Derivation: Argon2id\n");
                    sb.Append("Argon2-Memory: ").Append(Argon2Memory.ToString(CultureInfo.InvariantCulture)).Append('\n');
                    sb.Append("Argon2-Passes: ").Append(Argon2Passes.ToString(CultureInfo.InvariantCulture)).Append('\n');
                    sb.Append("Argon2-Parallelism: ").Append(Argon2Parallelism.ToString(CultureInfo.InvariantCulture)).Append('\n');
                    sb.Append("Argon2-Salt: ").Append(KeyFormats.Hex(salt)).Append('\n');
                }
                Lines(sb, "Private-Lines", stored);
                sb.Append("Private-MAC: ").Append(KeyFormats.Hex(mac)).Append('\n');
                return sb.ToString();
            }
            finally { KeyFormats.Wipe(priv, plain, pass, key, iv, macKey); }
        }

        private static void Lines(StringBuilder sb, string name, byte[] data)
        {
            var b64 = Convert.ToBase64String(data);
            sb.Append(name).Append(": ").Append(((b64.Length + 63) / 64).ToString(CultureInfo.InvariantCulture)).Append('\n');
            for (int i = 0; i < b64.Length; i += 64) sb.Append(b64, i, Math.Min(64, b64.Length - i)).Append('\n');
        }
    }

    // ------------------------------------------------------------------------------------------
    // Primitives: AES modes, hashes and HMAC (FIPS-approved Windows providers), bcrypt_pbkdf, BLAKE2b, Argon2
    // ------------------------------------------------------------------------------------------
    internal static class AesModes
    {
        /// <summary>AES in CTR mode (ctr true, the IV is the first counter block) or CBC mode, without padding.</summary>
        public static byte[] Transform(byte[] key, byte[] iv, byte[] data, bool ctr, bool encrypt)
        {
            using (var aes = new AesCryptoServiceProvider { Mode = ctr ? CipherMode.ECB : CipherMode.CBC, Padding = PaddingMode.None, Key = key, IV = ctr ? new byte[16] : iv })
            {
                if (!ctr)
                {
                    if (data.Length % 16 != 0) throw new FormatException("The encrypted part has a wrong length.");
                    using (var t = encrypt ? aes.CreateEncryptor() : aes.CreateDecryptor()) return data.Length == 0 ? new byte[0] : t.TransformFinalBlock(data, 0, data.Length);
                }
                var output = new byte[data.Length]; var counter = (byte[])iv.Clone(); var stream = new byte[16];
                using (var t = aes.CreateEncryptor())
                {
                    for (int off = 0; off < data.Length; off += 16)
                    {
                        t.TransformBlock(counter, 0, 16, stream, 0);
                        for (int i = 0; i < 16 && off + i < data.Length; i++) output[off + i] = (byte)(data[off + i] ^ stream[i]);
                        for (int i = 15; i >= 0 && ++counter[i] == 0; i--) { }
                    }
                }
                KeyFormats.Wipe(counter, stream);
                return output;
            }
        }
    }

    internal static class Hashes
    {
        public static byte[] Sha1(byte[][] parts) { using (var h = new SHA1CryptoServiceProvider()) return Run(h, parts); }
        public static byte[] Sha256(byte[][] parts) { using (var h = new SHA256CryptoServiceProvider()) return Run(h, parts); }
        public static byte[] Sha512(byte[][] parts) { using (var h = new SHA512CryptoServiceProvider()) return Run(h, parts); }
        private static byte[] Run(HashAlgorithm h, byte[][] parts)
        {
            foreach (var p in parts) h.TransformBlock(p, 0, p.Length, null, 0);
            h.TransformFinalBlock(new byte[0], 0, 0);
            return h.Hash;
        }

        /// <summary>HMAC (RFC 2104) over one of the hashes above: the .NET HMAC classes use managed SHA-256, which FIPS mode refuses.</summary>
        public static byte[] Hmac(Func<byte[][], byte[]> hash, int blockSize, byte[] key, byte[] data)
        {
            var k = new byte[blockSize];
            var kk = key.Length > blockSize ? hash(new[] { key }) : key;
            Buffer.BlockCopy(kk, 0, k, 0, kk.Length);
            var ipad = k.Select(b => (byte)(b ^ 0x36)).ToArray(); var opad = k.Select(b => (byte)(b ^ 0x5c)).ToArray();
            try { return hash(new[] { opad, hash(new[] { ipad, data }) }); }
            finally { KeyFormats.Wipe(k, ipad, opad); }
        }
    }

    /// <summary>bcrypt_pbkdf of OpenBSD (openbsd-compat/bcrypt_pbkdf.c), the key derivation of OpenSSH private keys.</summary>
    internal static class BcryptPbkdf
    {
        public static byte[] Derive(byte[] pass, byte[] salt, int rounds, int keyLength)
        {
            if (pass.Length == 0 || salt.Length == 0 || keyLength < 1 || keyLength > 32 * 32 || rounds < 1) throw new ArgumentException("bcrypt_pbkdf: invalid parameters");
            const int H = 32;
            int stride = (keyLength + H - 1) / H, amt = (keyLength + stride - 1) / stride, remaining = keyLength;
            var key = new byte[keyLength];
            var sha2pass = Hashes.Sha512(new[] { pass });
            var countsalt = new byte[salt.Length + 4]; Buffer.BlockCopy(salt, 0, countsalt, 0, salt.Length);
            for (uint count = 1; remaining > 0; count++)
            {
                countsalt[salt.Length] = (byte)(count >> 24); countsalt[salt.Length + 1] = (byte)(count >> 16); countsalt[salt.Length + 2] = (byte)(count >> 8); countsalt[salt.Length + 3] = (byte)count;
                var tmp = BcryptHash(sha2pass, Hashes.Sha512(new[] { countsalt }));
                var output = (byte[])tmp.Clone();
                for (int i = 1; i < rounds; i++)
                {
                    tmp = BcryptHash(sha2pass, Hashes.Sha512(new[] { tmp }));
                    for (int j = 0; j < output.Length; j++) output[j] ^= tmp[j];
                }
                amt = Math.Min(amt, remaining);
                int k;
                for (k = 0; k < amt; k++)
                {
                    int dest = k * stride + (int)(count - 1);
                    if (dest >= keyLength) break;
                    key[dest] = output[k];
                }
                remaining -= k;
                KeyFormats.Wipe(tmp, output);
            }
            KeyFormats.Wipe(sha2pass);
            return key;
        }

        private static byte[] BcryptHash(byte[] sha2pass, byte[] sha2salt)
        {
            var s = new uint[1024]; var p = new uint[18];
            Array.Copy(Init, 0, s, 0, 1024); Array.Copy(Init, 1024, p, 0, 18);
            ExpandState(s, p, sha2salt, sha2pass);
            for (int i = 0; i < 64; i++) { Expand0State(s, p, sha2salt); Expand0State(s, p, sha2pass); }
            var ct = Encoding.ASCII.GetBytes("OxychromaticBlowfishSwatDynamite");
            var cdata = new uint[8]; int j = 0;
            for (int i = 0; i < 8; i++) cdata[i] = Word(ct, ref j);
            for (int i = 0; i < 64; i++) for (int b = 0; b < 4; b++) Encipher(s, p, ref cdata[2 * b], ref cdata[2 * b + 1]);
            var o = new byte[32];
            for (int i = 0; i < 8; i++) { o[4 * i + 3] = (byte)(cdata[i] >> 24); o[4 * i + 2] = (byte)(cdata[i] >> 16); o[4 * i + 1] = (byte)(cdata[i] >> 8); o[4 * i] = (byte)cdata[i]; }
            Array.Clear(s, 0, s.Length); Array.Clear(p, 0, p.Length); Array.Clear(cdata, 0, cdata.Length);
            return o;
        }

        private static uint F(uint[] s, uint x) { return ((s[x >> 24] + s[0x100 + ((x >> 16) & 0xff)]) ^ s[0x200 + ((x >> 8) & 0xff)]) + s[0x300 + (x & 0xff)]; }

        private static void Encipher(uint[] s, uint[] p, ref uint xl, ref uint xr)
        {
            uint l = xl ^ p[0], r = xr;
            for (int i = 1; i <= 16; i += 2) { r ^= F(s, l) ^ p[i]; l ^= F(s, r) ^ p[i + 1]; }
            xl = r ^ p[17]; xr = l;
        }

        private static uint Word(byte[] data, ref int j)
        {
            uint t = 0;
            for (int i = 0; i < 4; i++, j++) { if (j >= data.Length) j = 0; t = (t << 8) | data[j]; }
            return t;
        }

        private static void Expand0State(uint[] s, uint[] p, byte[] key)
        {
            int j = 0;
            for (int i = 0; i < 18; i++) p[i] ^= Word(key, ref j);
            uint l = 0, r = 0;
            for (int i = 0; i < 18; i += 2) { Encipher(s, p, ref l, ref r); p[i] = l; p[i + 1] = r; }
            for (int i = 0; i < 1024; i += 2) { Encipher(s, p, ref l, ref r); s[i] = l; s[i + 1] = r; }
        }

        private static void ExpandState(uint[] s, uint[] p, byte[] data, byte[] key)
        {
            int j = 0;
            for (int i = 0; i < 18; i++) p[i] ^= Word(key, ref j);
            j = 0; uint l = 0, r = 0;
            for (int i = 0; i < 18; i += 2) { l ^= Word(data, ref j); r ^= Word(data, ref j); Encipher(s, p, ref l, ref r); p[i] = l; p[i + 1] = r; }
            for (int i = 0; i < 1024; i += 2) { l ^= Word(data, ref j); r ^= Word(data, ref j); Encipher(s, p, ref l, ref r); s[i] = l; s[i + 1] = r; }
        }

        /// <summary>Blowfish's initial state, the hexadecimal digits of pi: the four S-boxes (1024 words), then the P-array (18 words), from openbsd-compat/blowfish.c.</summary>
        private static readonly uint[] Init =
        {
            0xd1310ba6, 0x98dfb5ac, 0x2ffd72db, 0xd01adfb7, 0xb8e1afed, 0x6a267e96, 0xba7c9045, 0xf12c7f99,
            0x24a19947, 0xb3916cf7, 0x0801f2e2, 0x858efc16, 0x636920d8, 0x71574e69, 0xa458fea3, 0xf4933d7e,
            0x0d95748f, 0x728eb658, 0x718bcd58, 0x82154aee, 0x7b54a41d, 0xc25a59b5, 0x9c30d539, 0x2af26013,
            0xc5d1b023, 0x286085f0, 0xca417918, 0xb8db38ef, 0x8e79dcb0, 0x603a180e, 0x6c9e0e8b, 0xb01e8a3e,
            0xd71577c1, 0xbd314b27, 0x78af2fda, 0x55605c60, 0xe65525f3, 0xaa55ab94, 0x57489862, 0x63e81440,
            0x55ca396a, 0x2aab10b6, 0xb4cc5c34, 0x1141e8ce, 0xa15486af, 0x7c72e993, 0xb3ee1411, 0x636fbc2a,
            0x2ba9c55d, 0x741831f6, 0xce5c3e16, 0x9b87931e, 0xafd6ba33, 0x6c24cf5c, 0x7a325381, 0x28958677,
            0x3b8f4898, 0x6b4bb9af, 0xc4bfe81b, 0x66282193, 0x61d809cc, 0xfb21a991, 0x487cac60, 0x5dec8032,
            0xef845d5d, 0xe98575b1, 0xdc262302, 0xeb651b88, 0x23893e81, 0xd396acc5, 0x0f6d6ff3, 0x83f44239,
            0x2e0b4482, 0xa4842004, 0x69c8f04a, 0x9e1f9b5e, 0x21c66842, 0xf6e96c9a, 0x670c9c61, 0xabd388f0,
            0x6a51a0d2, 0xd8542f68, 0x960fa728, 0xab5133a3, 0x6eef0b6c, 0x137a3be4, 0xba3bf050, 0x7efb2a98,
            0xa1f1651d, 0x39af0176, 0x66ca593e, 0x82430e88, 0x8cee8619, 0x456f9fb4, 0x7d84a5c3, 0x3b8b5ebe,
            0xe06f75d8, 0x85c12073, 0x401a449f, 0x56c16aa6, 0x4ed3aa62, 0x363f7706, 0x1bfedf72, 0x429b023d,
            0x37d0d724, 0xd00a1248, 0xdb0fead3, 0x49f1c09b, 0x075372c9, 0x80991b7b, 0x25d479d8, 0xf6e8def7,
            0xe3fe501a, 0xb6794c3b, 0x976ce0bd, 0x04c006ba, 0xc1a94fb6, 0x409f60c4, 0x5e5c9ec2, 0x196a2463,
            0x68fb6faf, 0x3e6c53b5, 0x1339b2eb, 0x3b52ec6f, 0x6dfc511f, 0x9b30952c, 0xcc814544, 0xaf5ebd09,
            0xbee3d004, 0xde334afd, 0x660f2807, 0x192e4bb3, 0xc0cba857, 0x45c8740f, 0xd20b5f39, 0xb9d3fbdb,
            0x5579c0bd, 0x1a60320a, 0xd6a100c6, 0x402c7279, 0x679f25fe, 0xfb1fa3cc, 0x8ea5e9f8, 0xdb3222f8,
            0x3c7516df, 0xfd616b15, 0x2f501ec8, 0xad0552ab, 0x323db5fa, 0xfd238760, 0x53317b48, 0x3e00df82,
            0x9e5c57bb, 0xca6f8ca0, 0x1a87562e, 0xdf1769db, 0xd542a8f6, 0x287effc3, 0xac6732c6, 0x8c4f5573,
            0x695b27b0, 0xbbca58c8, 0xe1ffa35d, 0xb8f011a0, 0x10fa3d98, 0xfd2183b8, 0x4afcb56c, 0x2dd1d35b,
            0x9a53e479, 0xb6f84565, 0xd28e49bc, 0x4bfb9790, 0xe1ddf2da, 0xa4cb7e33, 0x62fb1341, 0xcee4c6e8,
            0xef20cada, 0x36774c01, 0xd07e9efe, 0x2bf11fb4, 0x95dbda4d, 0xae909198, 0xeaad8e71, 0x6b93d5a0,
            0xd08ed1d0, 0xafc725e0, 0x8e3c5b2f, 0x8e7594b7, 0x8ff6e2fb, 0xf2122b64, 0x8888b812, 0x900df01c,
            0x4fad5ea0, 0x688fc31c, 0xd1cff191, 0xb3a8c1ad, 0x2f2f2218, 0xbe0e1777, 0xea752dfe, 0x8b021fa1,
            0xe5a0cc0f, 0xb56f74e8, 0x18acf3d6, 0xce89e299, 0xb4a84fe0, 0xfd13e0b7, 0x7cc43b81, 0xd2ada8d9,
            0x165fa266, 0x80957705, 0x93cc7314, 0x211a1477, 0xe6ad2065, 0x77b5fa86, 0xc75442f5, 0xfb9d35cf,
            0xebcdaf0c, 0x7b3e89a0, 0xd6411bd3, 0xae1e7e49, 0x00250e2d, 0x2071b35e, 0x226800bb, 0x57b8e0af,
            0x2464369b, 0xf009b91e, 0x5563911d, 0x59dfa6aa, 0x78c14389, 0xd95a537f, 0x207d5ba2, 0x02e5b9c5,
            0x83260376, 0x6295cfa9, 0x11c81968, 0x4e734a41, 0xb3472dca, 0x7b14a94a, 0x1b510052, 0x9a532915,
            0xd60f573f, 0xbc9bc6e4, 0x2b60a476, 0x81e67400, 0x08ba6fb5, 0x571be91f, 0xf296ec6b, 0x2a0dd915,
            0xb6636521, 0xe7b9f9b6, 0xff34052e, 0xc5855664, 0x53b02d5d, 0xa99f8fa1, 0x08ba4799, 0x6e85076a,
            0x4b7a70e9, 0xb5b32944, 0xdb75092e, 0xc4192623, 0xad6ea6b0, 0x49a7df7d, 0x9cee60b8, 0x8fedb266,
            0xecaa8c71, 0x699a17ff, 0x5664526c, 0xc2b19ee1, 0x193602a5, 0x75094c29, 0xa0591340, 0xe4183a3e,
            0x3f54989a, 0x5b429d65, 0x6b8fe4d6, 0x99f73fd6, 0xa1d29c07, 0xefe830f5, 0x4d2d38e6, 0xf0255dc1,
            0x4cdd2086, 0x8470eb26, 0x6382e9c6, 0x021ecc5e, 0x09686b3f, 0x3ebaefc9, 0x3c971814, 0x6b6a70a1,
            0x687f3584, 0x52a0e286, 0xb79c5305, 0xaa500737, 0x3e07841c, 0x7fdeae5c, 0x8e7d44ec, 0x5716f2b8,
            0xb03ada37, 0xf0500c0d, 0xf01c1f04, 0x0200b3ff, 0xae0cf51a, 0x3cb574b2, 0x25837a58, 0xdc0921bd,
            0xd19113f9, 0x7ca92ff6, 0x94324773, 0x22f54701, 0x3ae5e581, 0x37c2dadc, 0xc8b57634, 0x9af3dda7,
            0xa9446146, 0x0fd0030e, 0xecc8c73e, 0xa4751e41, 0xe238cd99, 0x3bea0e2f, 0x3280bba1, 0x183eb331,
            0x4e548b38, 0x4f6db908, 0x6f420d03, 0xf60a04bf, 0x2cb81290, 0x24977c79, 0x5679b072, 0xbcaf89af,
            0xde9a771f, 0xd9930810, 0xb38bae12, 0xdccf3f2e, 0x5512721f, 0x2e6b7124, 0x501adde6, 0x9f84cd87,
            0x7a584718, 0x7408da17, 0xbc9f9abc, 0xe94b7d8c, 0xec7aec3a, 0xdb851dfa, 0x63094366, 0xc464c3d2,
            0xef1c1847, 0x3215d908, 0xdd433b37, 0x24c2ba16, 0x12a14d43, 0x2a65c451, 0x50940002, 0x133ae4dd,
            0x71dff89e, 0x10314e55, 0x81ac77d6, 0x5f11199b, 0x043556f1, 0xd7a3c76b, 0x3c11183b, 0x5924a509,
            0xf28fe6ed, 0x97f1fbfa, 0x9ebabf2c, 0x1e153c6e, 0x86e34570, 0xeae96fb1, 0x860e5e0a, 0x5a3e2ab3,
            0x771fe71c, 0x4e3d06fa, 0x2965dcb9, 0x99e71d0f, 0x803e89d6, 0x5266c825, 0x2e4cc978, 0x9c10b36a,
            0xc6150eba, 0x94e2ea78, 0xa5fc3c53, 0x1e0a2df4, 0xf2f74ea7, 0x361d2b3d, 0x1939260f, 0x19c27960,
            0x5223a708, 0xf71312b6, 0xebadfe6e, 0xeac31f66, 0xe3bc4595, 0xa67bc883, 0xb17f37d1, 0x018cff28,
            0xc332ddef, 0xbe6c5aa5, 0x65582185, 0x68ab9802, 0xeecea50f, 0xdb2f953b, 0x2aef7dad, 0x5b6e2f84,
            0x1521b628, 0x29076170, 0xecdd4775, 0x619f1510, 0x13cca830, 0xeb61bd96, 0x0334fe1e, 0xaa0363cf,
            0xb5735c90, 0x4c70a239, 0xd59e9e0b, 0xcbaade14, 0xeecc86bc, 0x60622ca7, 0x9cab5cab, 0xb2f3846e,
            0x648b1eaf, 0x19bdf0ca, 0xa02369b9, 0x655abb50, 0x40685a32, 0x3c2ab4b3, 0x319ee9d5, 0xc021b8f7,
            0x9b540b19, 0x875fa099, 0x95f7997e, 0x623d7da8, 0xf837889a, 0x97e32d77, 0x11ed935f, 0x16681281,
            0x0e358829, 0xc7e61fd6, 0x96dedfa1, 0x7858ba99, 0x57f584a5, 0x1b227263, 0x9b83c3ff, 0x1ac24696,
            0xcdb30aeb, 0x532e3054, 0x8fd948e4, 0x6dbc3128, 0x58ebf2ef, 0x34c6ffea, 0xfe28ed61, 0xee7c3c73,
            0x5d4a14d9, 0xe864b7e3, 0x42105d14, 0x203e13e0, 0x45eee2b6, 0xa3aaabea, 0xdb6c4f15, 0xfacb4fd0,
            0xc742f442, 0xef6abbb5, 0x654f3b1d, 0x41cd2105, 0xd81e799e, 0x86854dc7, 0xe44b476a, 0x3d816250,
            0xcf62a1f2, 0x5b8d2646, 0xfc8883a0, 0xc1c7b6a3, 0x7f1524c3, 0x69cb7492, 0x47848a0b, 0x5692b285,
            0x095bbf00, 0xad19489d, 0x1462b174, 0x23820e00, 0x58428d2a, 0x0c55f5ea, 0x1dadf43e, 0x233f7061,
            0x3372f092, 0x8d937e41, 0xd65fecf1, 0x6c223bdb, 0x7cde3759, 0xcbee7460, 0x4085f2a7, 0xce77326e,
            0xa6078084, 0x19f8509e, 0xe8efd855, 0x61d99735, 0xa969a7aa, 0xc50c06c2, 0x5a04abfc, 0x800bcadc,
            0x9e447a2e, 0xc3453484, 0xfdd56705, 0x0e1e9ec9, 0xdb73dbd3, 0x105588cd, 0x675fda79, 0xe3674340,
            0xc5c43465, 0x713e38d8, 0x3d28f89e, 0xf16dff20, 0x153e21e7, 0x8fb03d4a, 0xe6e39f2b, 0xdb83adf7,
            0xe93d5a68, 0x948140f7, 0xf64c261c, 0x94692934, 0x411520f7, 0x7602d4f7, 0xbcf46b2e, 0xd4a20068,
            0xd4082471, 0x3320f46a, 0x43b7d4b7, 0x500061af, 0x1e39f62e, 0x97244546, 0x14214f74, 0xbf8b8840,
            0x4d95fc1d, 0x96b591af, 0x70f4ddd3, 0x66a02f45, 0xbfbc09ec, 0x03bd9785, 0x7fac6dd0, 0x31cb8504,
            0x96eb27b3, 0x55fd3941, 0xda2547e6, 0xabca0a9a, 0x28507825, 0x530429f4, 0x0a2c86da, 0xe9b66dfb,
            0x68dc1462, 0xd7486900, 0x680ec0a4, 0x27a18dee, 0x4f3ffea2, 0xe887ad8c, 0xb58ce006, 0x7af4d6b6,
            0xaace1e7c, 0xd3375fec, 0xce78a399, 0x406b2a42, 0x20fe9e35, 0xd9f385b9, 0xee39d7ab, 0x3b124e8b,
            0x1dc9faf7, 0x4b6d1856, 0x26a36631, 0xeae397b2, 0x3a6efa74, 0xdd5b4332, 0x6841e7f7, 0xca7820fb,
            0xfb0af54e, 0xd8feb397, 0x454056ac, 0xba489527, 0x55533a3a, 0x20838d87, 0xfe6ba9b7, 0xd096954b,
            0x55a867bc, 0xa1159a58, 0xcca92963, 0x99e1db33, 0xa62a4a56, 0x3f3125f9, 0x5ef47e1c, 0x9029317c,
            0xfdf8e802, 0x04272f70, 0x80bb155c, 0x05282ce3, 0x95c11548, 0xe4c66d22, 0x48c1133f, 0xc70f86dc,
            0x07f9c9ee, 0x41041f0f, 0x404779a4, 0x5d886e17, 0x325f51eb, 0xd59bc0d1, 0xf2bcc18f, 0x41113564,
            0x257b7834, 0x602a9c60, 0xdff8e8a3, 0x1f636c1b, 0x0e12b4c2, 0x02e1329e, 0xaf664fd1, 0xcad18115,
            0x6b2395e0, 0x333e92e1, 0x3b240b62, 0xeebeb922, 0x85b2a20e, 0xe6ba0d99, 0xde720c8c, 0x2da2f728,
            0xd0127845, 0x95b794fd, 0x647d0862, 0xe7ccf5f0, 0x5449a36f, 0x877d48fa, 0xc39dfd27, 0xf33e8d1e,
            0x0a476341, 0x992eff74, 0x3a6f6eab, 0xf4f8fd37, 0xa812dc60, 0xa1ebddf8, 0x991be14c, 0xdb6e6b0d,
            0xc67b5510, 0x6d672c37, 0x2765d43b, 0xdcd0e804, 0xf1290dc7, 0xcc00ffa3, 0xb5390f92, 0x690fed0b,
            0x667b9ffb, 0xcedb7d9c, 0xa091cf0b, 0xd9155ea3, 0xbb132f88, 0x515bad24, 0x7b9479bf, 0x763bd6eb,
            0x37392eb3, 0xcc115979, 0x8026e297, 0xf42e312d, 0x6842ada7, 0xc66a2b3b, 0x12754ccc, 0x782ef11c,
            0x6a124237, 0xb79251e7, 0x06a1bbe6, 0x4bfb6350, 0x1a6b1018, 0x11caedfa, 0x3d25bdd8, 0xe2e1c3c9,
            0x44421659, 0x0a121386, 0xd90cec6e, 0xd5abea2a, 0x64af674e, 0xda86a85f, 0xbebfe988, 0x64e4c3fe,
            0x9dbc8057, 0xf0f7c086, 0x60787bf8, 0x6003604d, 0xd1fd8346, 0xf6381fb0, 0x7745ae04, 0xd736fccc,
            0x83426b33, 0xf01eab71, 0xb0804187, 0x3c005e5f, 0x77a057be, 0xbde8ae24, 0x55464299, 0xbf582e61,
            0x4e58f48f, 0xf2ddfda2, 0xf474ef38, 0x8789bdc2, 0x5366f9c3, 0xc8b38e74, 0xb475f255, 0x46fcd9b9,
            0x7aeb2661, 0x8b1ddf84, 0x846a0e79, 0x915f95e2, 0x466e598e, 0x20b45770, 0x8cd55591, 0xc902de4c,
            0xb90bace1, 0xbb8205d0, 0x11a86248, 0x7574a99e, 0xb77f19b6, 0xe0a9dc09, 0x662d09a1, 0xc4324633,
            0xe85a1f02, 0x09f0be8c, 0x4a99a025, 0x1d6efe10, 0x1ab93d1d, 0x0ba5a4df, 0xa186f20f, 0x2868f169,
            0xdcb7da83, 0x573906fe, 0xa1e2ce9b, 0x4fcd7f52, 0x50115e01, 0xa70683fa, 0xa002b5c4, 0x0de6d027,
            0x9af88c27, 0x773f8641, 0xc3604c06, 0x61a806b5, 0xf0177a28, 0xc0f586e0, 0x006058aa, 0x30dc7d62,
            0x11e69ed7, 0x2338ea63, 0x53c2dd94, 0xc2c21634, 0xbbcbee56, 0x90bcb6de, 0xebfc7da1, 0xce591d76,
            0x6f05e409, 0x4b7c0188, 0x39720a3d, 0x7c927c24, 0x86e3725f, 0x724d9db9, 0x1ac15bb4, 0xd39eb8fc,
            0xed545578, 0x08fca5b5, 0xd83d7cd3, 0x4dad0fc4, 0x1e50ef5e, 0xb161e6f8, 0xa28514d9, 0x6c51133c,
            0x6fd5c7e7, 0x56e14ec4, 0x362abfce, 0xddc6c837, 0xd79a3234, 0x92638212, 0x670efa8e, 0x406000e0,
            0x3a39ce37, 0xd3faf5cf, 0xabc27737, 0x5ac52d1b, 0x5cb0679e, 0x4fa33742, 0xd3822740, 0x99bc9bbe,
            0xd5118e9d, 0xbf0f7315, 0xd62d1c7e, 0xc700c47b, 0xb78c1b6b, 0x21a19045, 0xb26eb1be, 0x6a366eb4,
            0x5748ab2f, 0xbc946e79, 0xc6a376d2, 0x6549c2c8, 0x530ff8ee, 0x468dde7d, 0xd5730a1d, 0x4cd04dc6,
            0x2939bbdb, 0xa9ba4650, 0xac9526e8, 0xbe5ee304, 0xa1fad5f0, 0x6a2d519a, 0x63ef8ce2, 0x9a86ee22,
            0xc089c2b8, 0x43242ef6, 0xa51e03aa, 0x9cf2d0a4, 0x83c061ba, 0x9be96a4d, 0x8fe51550, 0xba645bd6,
            0x2826a2f9, 0xa73a3ae1, 0x4ba99586, 0xef5562e9, 0xc72fefd3, 0xf752f7da, 0x3f046f69, 0x77fa0a59,
            0x80e4a915, 0x87b08601, 0x9b09e6ad, 0x3b3ee593, 0xe990fd5a, 0x9e34d797, 0x2cf0b7d9, 0x022b8b51,
            0x96d5ac3a, 0x017da67d, 0xd1cf3ed6, 0x7c7d2d28, 0x1f9f25cf, 0xadf2b89b, 0x5ad6b472, 0x5a88f54c,
            0xe029ac71, 0xe019a5e6, 0x47b0acfd, 0xed93fa9b, 0xe8d3c48d, 0x283b57cc, 0xf8d56629, 0x79132e28,
            0x785f0191, 0xed756055, 0xf7960e44, 0xe3d35e8c, 0x15056dd4, 0x88f46dba, 0x03a16125, 0x0564f0bd,
            0xc3eb9e15, 0x3c9057a2, 0x97271aec, 0xa93a072a, 0x1b3f6d9b, 0x1e6321f5, 0xf59c66fb, 0x26dcf319,
            0x7533d928, 0xb155fdf5, 0x03563482, 0x8aba3cbb, 0x28517711, 0xc20ad9f8, 0xabcc5167, 0xccad925f,
            0x4de81751, 0x3830dc8e, 0x379d5862, 0x9320f991, 0xea7a90c2, 0xfb3e7bce, 0x5121ce64, 0x774fbe32,
            0xa8b6e37e, 0xc3293d46, 0x48de5369, 0x6413e680, 0xa2ae0810, 0xdd6db224, 0x69852dfd, 0x09072166,
            0xb39a460a, 0x6445c0dd, 0x586cdecf, 0x1c20c8ae, 0x5bbef7dd, 0x1b588d40, 0xccd2017f, 0x6bb4e3bb,
            0xdda26a7e, 0x3a59ff45, 0x3e350a44, 0xbcb4cdd5, 0x72eacea8, 0xfa6484bb, 0x8d6612ae, 0xbf3c6f47,
            0xd29be463, 0x542f5d9e, 0xaec2771b, 0xf64e6370, 0x740e0d8d, 0xe75b1357, 0xf8721671, 0xaf537d5d,
            0x4040cb08, 0x4eb4e2cc, 0x34d2466a, 0x0115af84, 0xe1b00428, 0x95983a1d, 0x06b89fb4, 0xce6ea048,
            0x6f3f3b82, 0x3520ab82, 0x011a1d4b, 0x277227f8, 0x611560b1, 0xe7933fdc, 0xbb3a792b, 0x344525bd,
            0xa08839e1, 0x51ce794b, 0x2f32c9b7, 0xa01fbac9, 0xe01cc87e, 0xbcc7d1f6, 0xcf0111c3, 0xa1e8aac7,
            0x1a908749, 0xd44fbd9a, 0xd0dadecb, 0xd50ada38, 0x0339c32a, 0xc6913667, 0x8df9317c, 0xe0b12b4f,
            0xf79e59b7, 0x43f5bb3a, 0xf2d519ff, 0x27d9459c, 0xbf97222c, 0x15e6fc2a, 0x0f91fc71, 0x9b941525,
            0xfae59361, 0xceb69ceb, 0xc2a86459, 0x12baa8d1, 0xb6c1075e, 0xe3056a0c, 0x10d25065, 0xcb03a442,
            0xe0ec6e0e, 0x1698db3b, 0x4c98a0be, 0x3278e964, 0x9f1f9532, 0xe0d392df, 0xd3a0342b, 0x8971f21e,
            0x1b0a7441, 0x4ba3348c, 0xc5be7120, 0xc37632d8, 0xdf359f8d, 0x9b992f2e, 0xe60b6f47, 0x0fe3f11d,
            0xe54cda54, 0x1edad891, 0xce6279cf, 0xcd3e7e6f, 0x1618b166, 0xfd2c1d05, 0x848fd2c5, 0xf6fb2299,
            0xf523f357, 0xa6327623, 0x93a83531, 0x56cccd02, 0xacf08162, 0x5a75ebb5, 0x6e163697, 0x88d273cc,
            0xde966292, 0x81b949d0, 0x4c50901b, 0x71c65614, 0xe6c6c7bd, 0x327a140a, 0x45e1d006, 0xc3f27b9a,
            0xc9aa53fd, 0x62a80f00, 0xbb25bfe2, 0x35bdd2f6, 0x71126905, 0xb2040222, 0xb6cbcf7c, 0xcd769c2b,
            0x53113ec0, 0x1640e3d3, 0x38abbd60, 0x2547adf0, 0xba38209c, 0xf746ce76, 0x77afa1c5, 0x20756060,
            0x85cbfe4e, 0x8ae88dd8, 0x7aaaf9b0, 0x4cf9aa7e, 0x1948c25c, 0x02fb8a8c, 0x01c36ae4, 0xd6ebe1f9,
            0x90d4f869, 0xa65cdea0, 0x3f09252d, 0xc208e69f, 0xb74e6132, 0xce77e25b, 0x578fdfe3, 0x3ac372e6,
            0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344, 0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89,
            0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c, 0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917,
            0x9216d5d9, 0x8979fb1b,

        };
    }

    /// <summary>BLAKE2b (RFC 7693), unkeyed, for Argon2.</summary>
    internal static class Blake2b
    {
        private static readonly ulong[] IV = { 0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179 };
        private static readonly byte[][] Sigma =
        {
            new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 }, new byte[] { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
            new byte[] { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 }, new byte[] { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
            new byte[] { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 }, new byte[] { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
            new byte[] { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 }, new byte[] { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
            new byte[] { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 }, new byte[] { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
            new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 }, new byte[] { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
        };

        public static byte[] Hash(int outLength, params byte[][] parts)
        {
            if (outLength < 1 || outLength > 64) throw new ArgumentOutOfRangeException("outLength");
            var h = (ulong[])IV.Clone(); h[0] ^= 0x01010000UL ^ (ulong)outLength;
            var buf = new byte[128]; int fill = 0; ulong t = 0;
            foreach (var part in parts)
            {
                int off = 0;
                while (off < part.Length)
                {
                    if (fill == 128) { t += 128; Compress(h, buf, t, false); fill = 0; }
                    int n = Math.Min(128 - fill, part.Length - off);
                    Buffer.BlockCopy(part, off, buf, fill, n); fill += n; off += n;
                }
            }
            t += (ulong)fill;
            Array.Clear(buf, fill, 128 - fill);
            Compress(h, buf, t, true);
            var o = new byte[outLength];
            for (int i = 0; i < outLength; i++) o[i] = (byte)(h[i / 8] >> (8 * (i % 8)));
            Array.Clear(buf, 0, buf.Length); Array.Clear(h, 0, h.Length);
            return o;
        }

        private static void Compress(ulong[] h, byte[] block, ulong t, bool last)
        {
            var m = new ulong[16]; var v = new ulong[16];
            for (int i = 0; i < 16; i++) m[i] = Argon2.Le64(block, 8 * i);
            for (int i = 0; i < 8; i++) { v[i] = h[i]; v[i + 8] = IV[i]; }
            v[12] ^= t;
            if (last) v[14] = ~v[14];
            for (int r = 0; r < 12; r++)
            {
                var s = Sigma[r];
                G(v, 0, 4, 8, 12, m[s[0]], m[s[1]]); G(v, 1, 5, 9, 13, m[s[2]], m[s[3]]); G(v, 2, 6, 10, 14, m[s[4]], m[s[5]]); G(v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
                G(v, 0, 5, 10, 15, m[s[8]], m[s[9]]); G(v, 1, 6, 11, 12, m[s[10]], m[s[11]]); G(v, 2, 7, 8, 13, m[s[12]], m[s[13]]); G(v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
            }
            for (int i = 0; i < 8; i++) h[i] ^= v[i] ^ v[i + 8];
            Array.Clear(m, 0, 16); Array.Clear(v, 0, 16);
        }

        private static void G(ulong[] v, int a, int b, int c, int d, ulong x, ulong y)
        {
            v[a] = v[a] + v[b] + x; v[d] = Rotr(v[d] ^ v[a], 32);
            v[c] = v[c] + v[d]; v[b] = Rotr(v[b] ^ v[c], 24);
            v[a] = v[a] + v[b] + y; v[d] = Rotr(v[d] ^ v[a], 16);
            v[c] = v[c] + v[d]; v[b] = Rotr(v[b] ^ v[c], 63);
        }

        internal static ulong Rotr(ulong x, int n) { return (x >> n) | (x << (64 - n)); }
    }

    /// <summary>Argon2 version 1.3 (RFC 9106), the key derivation of PuTTY's .ppk version 3 files.</summary>
    internal static class Argon2
    {
        public enum Kind { D = 0, I = 1, Id = 2 }
        private const int Words = 128; // 1 KiB blocks of 64-bit words

        public static byte[] Hash(Kind kind, byte[] password, byte[] salt, int memoryKiB, int passes, int lanes, int tagLength, byte[] secret = null, byte[] associated = null)
        {
            secret = secret ?? new byte[0]; associated = associated ?? new byte[0];
            if (lanes < 1 || passes < 1 || tagLength < 4 || memoryKiB < 8 * lanes) throw new ArgumentException("Argon2: invalid parameters");
            var h0 = Blake2b.Hash(64, Le32(lanes), Le32(tagLength), Le32(memoryKiB), Le32(passes), Le32(0x13), Le32((int)kind),
                Le32(password.Length), password, Le32(salt.Length), salt, Le32(secret.Length), secret, Le32(associated.Length), associated);
            int segment = memoryKiB / (4 * lanes), laneLength = segment * 4, blocks = laneLength * lanes;
            var mem = new ulong[(long)blocks * Words];
            try
            {
                for (int l = 0; l < lanes; l++)
                    for (int b = 0; b < 2; b++) Load(mem, (l * laneLength + b) * Words, HPrime(1024, h0, Le32(b), Le32(l)));
                var address = new ulong[Words]; var input = new ulong[Words]; var zero = new ulong[Words]; var r = new ulong[Words]; var tmp = new ulong[Words];
                for (int pass = 0; pass < passes; pass++)
                    for (int slice = 0; slice < 4; slice++)
                        for (int lane = 0; lane < lanes; lane++)
                        {
                            bool independent = kind == Kind.I || kind == Kind.Id && pass == 0 && slice < 2;
                            if (independent)
                            {
                                Array.Clear(input, 0, Words);
                                input[0] = (ulong)pass; input[1] = (ulong)lane; input[2] = (ulong)slice; input[3] = (ulong)blocks; input[4] = (ulong)passes; input[5] = (ulong)kind;
                            }
                            int start = pass == 0 && slice == 0 ? 2 : 0;
                            if (independent && start == 2) NextAddresses(address, input, zero, r, tmp);
                            int curr = lane * laneLength + slice * segment + start;
                            int prev = curr % laneLength == 0 ? curr + laneLength - 1 : curr - 1;
                            for (int i = start; i < segment; i++, curr++, prev++)
                            {
                                if (curr % laneLength == 1) prev = curr - 1;
                                ulong rand;
                                if (independent) { if (i % Words == 0) NextAddresses(address, input, zero, r, tmp); rand = address[i % Words]; }
                                else rand = mem[(long)prev * Words];
                                int refLane = (int)((rand >> 32) % (ulong)lanes);
                                if (pass == 0 && slice == 0) refLane = lane;
                                int refIndex = IndexAlpha(pass, slice, i, segment, laneLength, (uint)rand, refLane == lane);
                                FillBlock(mem, prev * Words, mem, (refLane * laneLength + refIndex) * Words, mem, curr * Words, pass != 0, r, tmp);
                            }
                        }
                var final = new ulong[Words];
                for (int l = 0; l < lanes; l++) { int off = (l * laneLength + laneLength - 1) * Words; for (int w = 0; w < Words; w++) final[w] ^= mem[off + w]; }
                var bytes = new byte[1024];
                for (int w = 0; w < Words; w++) for (int k = 0; k < 8; k++) bytes[8 * w + k] = (byte)(final[w] >> (8 * k));
                try { return HPrime(tagLength, bytes); }
                finally { Array.Clear(bytes, 0, bytes.Length); Array.Clear(final, 0, Words); }
            }
            finally { Array.Clear(mem, 0, mem.Length); KeyFormats.Wipe(h0); }
        }

        private static int IndexAlpha(int pass, int slice, int index, int segment, int laneLength, uint rand, bool sameLane)
        {
            uint area;
            if (pass == 0)
            {
                if (slice == 0) area = (uint)(index - 1);
                else area = sameLane ? (uint)(slice * segment + index - 1) : (uint)(slice * segment + (index == 0 ? -1 : 0));
            }
            else area = sameLane ? (uint)(laneLength - segment + index - 1) : (uint)(laneLength - segment + (index == 0 ? -1 : 0));
            ulong rel = rand; rel = rel * rel >> 32;
            rel = (ulong)(area - 1) - ((ulong)area * rel >> 32);
            uint startPos = pass == 0 || slice == 3 ? 0u : (uint)((slice + 1) * segment);
            return (int)((startPos + rel) % (ulong)laneLength);
        }

        private static void NextAddresses(ulong[] address, ulong[] input, ulong[] zero, ulong[] r, ulong[] tmp)
        {
            input[6]++;
            FillBlock(zero, 0, input, 0, address, 0, false, r, tmp);
            FillBlock(zero, 0, address, 0, address, 0, false, r, tmp);
        }

        /// <summary>next = G(prev, ref), or next ^= G(prev, ref) (withXor, the passes after the first in version 1.3).</summary>
        private static void FillBlock(ulong[] pa, int po, ulong[] ra, int ro, ulong[] na, int no, bool withXor, ulong[] r, ulong[] tmp)
        {
            for (int i = 0; i < Words; i++) { r[i] = ra[ro + i] ^ pa[po + i]; tmp[i] = withXor ? r[i] ^ na[no + i] : r[i]; }
            for (int i = 0; i < 8; i++) Round(r, 16 * i, 16 * i + 1, 16 * i + 2, 16 * i + 3, 16 * i + 4, 16 * i + 5, 16 * i + 6, 16 * i + 7, 16 * i + 8, 16 * i + 9, 16 * i + 10, 16 * i + 11, 16 * i + 12, 16 * i + 13, 16 * i + 14, 16 * i + 15);
            for (int i = 0; i < 8; i++) Round(r, 2 * i, 2 * i + 1, 2 * i + 16, 2 * i + 17, 2 * i + 32, 2 * i + 33, 2 * i + 48, 2 * i + 49, 2 * i + 64, 2 * i + 65, 2 * i + 80, 2 * i + 81, 2 * i + 96, 2 * i + 97, 2 * i + 112, 2 * i + 113);
            for (int i = 0; i < Words; i++) na[no + i] = tmp[i] ^ r[i];
        }

        private static void Round(ulong[] v, int v0, int v1, int v2, int v3, int v4, int v5, int v6, int v7, int v8, int v9, int v10, int v11, int v12, int v13, int v14, int v15)
        {
            GB(v, v0, v4, v8, v12); GB(v, v1, v5, v9, v13); GB(v, v2, v6, v10, v14); GB(v, v3, v7, v11, v15);
            GB(v, v0, v5, v10, v15); GB(v, v1, v6, v11, v12); GB(v, v2, v7, v8, v13); GB(v, v3, v4, v9, v14);
        }

        private static void GB(ulong[] v, int a, int b, int c, int d)
        {
            v[a] = BlaMka(v[a], v[b]); v[d] = Blake2b.Rotr(v[d] ^ v[a], 32);
            v[c] = BlaMka(v[c], v[d]); v[b] = Blake2b.Rotr(v[b] ^ v[c], 24);
            v[a] = BlaMka(v[a], v[b]); v[d] = Blake2b.Rotr(v[d] ^ v[a], 16);
            v[c] = BlaMka(v[c], v[d]); v[b] = Blake2b.Rotr(v[b] ^ v[c], 63);
        }

        private static ulong BlaMka(ulong x, ulong y) { return x + y + 2 * ((x & 0xffffffff) * (y & 0xffffffff)); }

        /// <summary>H' of RFC 9106: BLAKE2b extended to any output length.</summary>
        private static byte[] HPrime(int outLength, params byte[][] parts)
        {
            var input = new[] { Le32(outLength) }.Concat(parts).ToArray();
            if (outLength <= 64) return Blake2b.Hash(outLength, input);
            var result = new byte[outLength];
            var v = Blake2b.Hash(64, input); Buffer.BlockCopy(v, 0, result, 0, 32); int pos = 32;
            int r = (outLength + 31) / 32 - 2;
            for (int i = 2; i <= r; i++) { v = Blake2b.Hash(64, v); Buffer.BlockCopy(v, 0, result, pos, 32); pos += 32; }
            v = Blake2b.Hash(outLength - pos, v); Buffer.BlockCopy(v, 0, result, pos, v.Length);
            return result;
        }

        private static void Load(ulong[] mem, int offset, byte[] block) { for (int w = 0; w < Words; w++) mem[offset + w] = Le64(block, 8 * w); Array.Clear(block, 0, block.Length); }
        internal static ulong Le64(byte[] b, int o) { ulong v = 0; for (int k = 7; k >= 0; k--) v = (v << 8) | b[o + k]; return v; }
        private static byte[] Le32(int v) { return new[] { (byte)v, (byte)(v >> 8), (byte)(v >> 16), (byte)(v >> 24) }; }
    }
}

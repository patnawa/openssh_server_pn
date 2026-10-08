using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Runtime.InteropServices;
using System.Net;
using System.IO;

namespace OpenSSHServerPNManager
{
    /// <summary>Configured endpoints and observed listeners are distinct until a restart applies a save.</summary>
    internal sealed class ServerStateSnapshot
    {
        public bool Verified;
        public string Error = "";
        public int[] ConfiguredPorts = new int[0], ListeningPorts = new int[0];
        public int[] Ports { get { return ConfiguredPorts.Concat(ListeningPorts).Distinct().OrderBy(p => p).ToArray(); } }
        public string FirewallPorts { get { return string.Join(",", Ports.Select(p => p.ToString(CultureInfo.InvariantCulture))); } }
    }

    internal static class ServerState
    {
        public static ServerStateSnapshot Read()
        {
            var definitionError = ServiceDefinitionError();
            if (definitionError != null) return new ServerStateSnapshot { Error = definitionError };
            var result = Parse(Ssh.Exe("sshd.exe"), Ssh.ConfigPath);
            if (!result.Verified) return result;
            var service = Services.Status("sshd");
            if (service.Status != "Running")
            {
                result.Verified = service.Status == "Stopped";
                if (!result.Verified) result.Error = "The SSH service state could not be verified: " + service.Status;
                return result;
            }
            List<TcpConnection> tcp; string error;
            if (service.Pid <= 0 || !WindowsTcp.TryRead(out tcp, out error))
            {
                result.Verified = false; result.Error = "The running SSH listeners could not be inspected.";
                return result;
            }
            result.ListeningPorts = tcp.Where(r => r.Pid == service.Pid && r.State == 2).Select(r => r.LocalPort).Distinct().OrderBy(p => p).ToArray();
            if (result.ListeningPorts.Length == 0) { result.Verified = false; result.Error = "The running SSH service has no verified listener."; }
            return result;
        }

        public static string ServiceDefinitionError()
        {
            try { return ServiceDefinitionError(Services.CommandLine("sshd"), Ssh.Exe("sshd.exe"), Ssh.ConfigPath); }
            catch (Exception ex) { return "The SSH service command line could not be verified: " + ex.Message; }
        }

        [DllImport("shell32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern IntPtr CommandLineToArgvW(string command, out int count);
        [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr value);

        internal static string ServiceDefinitionError(string command, string executable, string configPath)
        { return ServiceDefinitionError(command, executable, configPath, File.Exists); }

        internal static string ServiceDefinitionError(string command, string executable, string configPath, Func<string, bool> exists)
        {
            if (string.IsNullOrWhiteSpace(command)) return "The SSH service command line is missing or unavailable.";
            IntPtr arguments = IntPtr.Zero;
            try
            {
                var expanded = Environment.ExpandEnvironmentVariables(command.Trim());
                // An unquoted path with spaces is read as Ssh.InstallDir reads it, not split at its first space.
                string rest; var program = Services.SplitImagePath(expanded, out rest);
                bool unquoted = !expanded.StartsWith("\"", StringComparison.Ordinal) && program != null && program.IndexOfAny(new[] { ' ', '\t' }) >= 0;
                if (unquoted)
                {
                    var shadow = Services.UnquotedSearchOrder(program).FirstOrDefault(exists);
                    if (shadow != null) return "The SSH service path is not quoted, so Windows starts " + shadow + " instead of " + program + ". Quote the path of the service, or repair the installation.";
                }
                int count; arguments = CommandLineToArgvW(unquoted ? "sshd " + rest : expanded, out count);
                if (arguments == IntPtr.Zero || count == 0) return "The SSH service command line could not be parsed.";
                var args = new List<string>();
                for (int i = 0; i < count; i++) args.Add(Marshal.PtrToStringUni(Marshal.ReadIntPtr(arguments, i * IntPtr.Size)));
                if (unquoted) args[0] = program;
                if (!string.Equals(Path.GetFullPath(args[0]), Path.GetFullPath(executable), StringComparison.OrdinalIgnoreCase)) return "The SSH service runs a different executable than the manager's server tools.";
                for (int i = 1; i < args.Count; i++)
                {
                    var arg = args[i];
                    if (arg == "-D" || arg == "-e" || arg == "-d" || arg == "-dd" || arg == "-ddd") continue;
                    if (arg.StartsWith("-f", StringComparison.Ordinal))
                    {
                        var path = arg.Length > 2 ? arg.Substring(2) : (++i < args.Count ? args[i] : "");
                        if (!System.Text.RegularExpressions.Regex.IsMatch(path.Replace('/', '\\'), @"^[A-Za-z]:\\") && !path.StartsWith(@"\\", StringComparison.Ordinal))
                            return "The service uses a relative sshd configuration path; its working directory cannot be assumed.";
                        if (!string.Equals(Path.GetFullPath(path), Path.GetFullPath(configPath), StringComparison.OrdinalIgnoreCase)) return "The service uses a different sshd configuration (-f " + path + "). The manager cannot verify its settings or automatically change its firewall rules.";
                        continue;
                    }
                    if (arg == "-E") { if (++i >= args.Count) return "The service log-file argument is incomplete."; continue; }
                    if (arg.StartsWith("-E", StringComparison.Ordinal) && arg.Length > 2) continue;
                    return "The SSH service has an unsupported runtime option (" + arg + "). Its effective settings must not be inferred from the default configuration.";
                }
                return null;
            }
            catch (Exception ex) { return "The SSH service command line could not be verified: " + ex.Message; }
            finally { if (arguments != IntPtr.Zero) LocalFree(arguments); }
        }

        public static ServerStateSnapshot Parse(string executable, string configPath)
        {
            var r = Proc.Run(executable, "-T -f " + Proc.Quote(configPath), 20000);
            return FromEffectiveOutput(r);
        }

        /// <summary>Use sshd's resolver, including Include expansion and ListenAddress overrides; never infer port 22 on failure.</summary>
        internal static ServerStateSnapshot FromEffectiveOutput(RunResult result)
        {
            var state = new ServerStateSnapshot();
            if (!result.Ok) { state.Error = "sshd could not resolve its configuration: " + result.Output; return state; }
            var ports = new HashSet<int>(); var listen = new HashSet<int>();
            foreach (var line in result.StdOut.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
            {
                string keyword, value;
                if (!SshdConfig.Split(line, out keyword, out value)) continue;
                if (keyword.Equals("port", StringComparison.OrdinalIgnoreCase))
                {
                    int p;
                    if (!int.TryParse(value, out p) || p < 1 || p > 65535) { state.Error = "Invalid port in sshd's effective settings."; return state; }
                    ports.Add(p);
                }
                else if (keyword.Equals("listenaddress", StringComparison.OrdinalIgnoreCase))
                {
                    int p = SshdConfig.ListenPort(value);
                    if (p == 0) { state.Error = "An effective ListenAddress has no resolved port: " + value; return state; }
                    listen.Add(p);
                }
            }
            state.ConfiguredPorts = (listen.Count > 0 ? listen : ports).OrderBy(p => p).ToArray();
            state.Verified = state.ConfiguredPorts.Length > 0;
            if (!state.Verified) state.Error = "sshd reported no listening endpoints.";
            return state;
        }
    }

    internal sealed class TcpConnection
    {
        public int Pid, State, LocalPort, RemotePort;
        public string RemoteAddress;
        public string Peer { get { return (RemoteAddress.Contains(":") ? "[" + RemoteAddress + "]" : RemoteAddress) + ":" + RemotePort; } }
    }

    /// <summary>A complete TCP snapshot, or an explicit error; consumers must not interpret partial inspection as no peers.</summary>
    internal static class WindowsTcp
    {
        [StructLayout(LayoutKind.Sequential)] private struct Row4 { public uint State, LocalAddress, LocalPort, RemoteAddress, RemotePort, Pid; }
        [StructLayout(LayoutKind.Sequential)] private struct Row6
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] LocalAddress;
            public uint LocalScope, LocalPort;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] RemoteAddress;
            public uint RemoteScope, RemotePort, State, Pid;
        }
        [DllImport("iphlpapi.dll", SetLastError = true)] private static extern uint GetExtendedTcpTable(IntPtr table, ref int size, bool sort, int family, int tableClass, uint reserved);
        private static int Port(uint p) { return (int)(((p & 255) << 8) | ((p >> 8) & 255)); }
        public static bool TryRead(out List<TcpConnection> rows, out string error)
        {
            rows = new List<TcpConnection>(); error = null;
            try
            {
                foreach (int family in new[] { 2, 23 })
                {
                    bool read = false;
                    for (int attempt = 0; attempt < 3 && !read; attempt++)
                    {
                        int size = 0; uint rc = GetExtendedTcpTable(IntPtr.Zero, ref size, false, family, 5, 0);
                        if (rc != 0 && rc != 122) throw new System.ComponentModel.Win32Exception((int)rc);
                        if (size < 4) throw new InvalidOperationException("TCP snapshot returned an invalid buffer size.");
                        var buffer = Marshal.AllocHGlobal(size);
                        try
                        {
                            int capacity = size; rc = GetExtendedTcpTable(buffer, ref size, false, family, 5, 0);
                            if (rc == 122) continue;
                            if (rc != 0) throw new System.ComponentModel.Win32Exception((int)rc);
                            int count = Marshal.ReadInt32(buffer); int stride = Marshal.SizeOf(family == 2 ? typeof(Row4) : typeof(Row6));
                            if (count < 0 || (long)count * stride + 4 > capacity) throw new InvalidOperationException("TCP snapshot was truncated.");
                            for (int i = 0; i < count; i++)
                            {
                                var ptr = new IntPtr(buffer.ToInt64() + 4 + (long)i * stride);
                                if (family == 2)
                                {
                                    var r = (Row4)Marshal.PtrToStructure(ptr, typeof(Row4));
                                    rows.Add(new TcpConnection { Pid = (int)r.Pid, State = (int)r.State, LocalPort = Port(r.LocalPort), RemotePort = Port(r.RemotePort), RemoteAddress = new IPAddress(r.RemoteAddress).ToString() });
                                }
                                else
                                {
                                    var r = (Row6)Marshal.PtrToStructure(ptr, typeof(Row6)); var address = new IPAddress(r.RemoteAddress, r.RemoteScope);
                                    rows.Add(new TcpConnection { Pid = (int)r.Pid, State = (int)r.State, LocalPort = Port(r.LocalPort), RemotePort = Port(r.RemotePort), RemoteAddress = (address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address).ToString() });
                                }
                            }
                            read = true;
                        }
                        finally { Marshal.FreeHGlobal(buffer); }
                    }
                    if (!read) throw new InvalidOperationException("TCP state changed repeatedly during inspection.");
                }
                return true;
            }
            catch (Exception ex) { rows.Clear(); error = ex.Message; return false; }
        }
    }
}

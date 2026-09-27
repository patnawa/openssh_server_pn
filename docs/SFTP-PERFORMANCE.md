# SFTP performance

How fast OpenSSH Server PN moves files over SFTP, what 10.5.3.0 changed, how to get the full speed
from the server and the clients, and how to measure it on your own machines.

## In short

- **10.5.3.0 makes SFTP with AES about 3.5 times as fast on x64.** Up to 10.5.2.0, the encryption
  library never used the processor's AES instructions (AES-NI), so every AES cipher ran on slow
  software code. The x64 packages from 10.5.3.0 on use them.
- **Most clients profit without a change.** WinSCP and FileZilla choose AES by default. OpenSSH
  clients (`sftp`, `scp`, `ssh` on Windows, Linux and macOS) choose `chacha20-poly1305@openssh.com`
  first, which did not get faster: give them `-c aes128-gcm@openssh.com`, or leave ChaCha20 out on
  the server (see [below](#make-every-client-use-aes)).
- **Nothing to configure on the server.** Install the x64 package of 10.5.3.0 or later over the
  earlier one; the firewall rule, the port and `sshd_config` stay as they are.

## What changed in 10.5.3.0

SFTP runs inside an SSH connection, so every byte is encrypted by `sshd-session.exe` on the server
and by the client. Before 10.5.3.0 that encryption was the bottleneck of every AES cipher:

| Cipher (`openssl speed -evp`, 16 KB blocks) | 10.5.2.0 | 10.5.3.0 |
|---|---|---|
| AES-128-GCM | 205 MB/s | 4,717 MB/s |
| AES-256-GCM | 160 MB/s | 4,210 MB/s |
| AES-128-CTR | 263 MB/s | 16,263 MB/s |

The packages use LibreSSL for their cryptography. LibreSSL 4.x, built with Visual Studio as these
packages are, never found out which instructions the processor has: its detection is written for
GCC and is left out of Visual Studio builds, and the function that would run it is never called
there. So the AES-NI and carry-less multiplication code that the x64 build contains was never used,
and AES ran on table-based code, 20 to 60 times slower. Microsoft's own OpenSSH 10.0.0.0 package,
built the same way with LibreSSL 4.2.0, has the same code. 10.5.3.0 adds the detection for Visual
Studio builds (`msvc-x64-cpu-caps.patch`, see [BUILDING.md](BUILDING.md#6-refreshing-the-vendored-libraries)).

What that means for SFTP, measured with a 512 MiB file over the loopback of one computer, so that
the network does not limit the result (MB/s upload / download, the median of three runs, averaged
over two interleaved rounds):

| Cipher | 10.5.2.0 | 10.5.3.0 |
|---|---|---|
| `aes128-gcm@openssh.com` | 154 / 160 | 487 / 597 |
| `aes256-gcm@openssh.com` | 122 / 126 | 502 / 499 |
| `aes256-ctr` (WinSCP's first choice) | 143 / 144 | 500 / 472 |
| `chacha20-poly1305@openssh.com` (OpenSSH's first choice) | 296 / 280 | 291 / 325 |

The installed 10.5.3.0 service on the same computer, 1 GiB up and 1 GiB down with the
[test below](#measure-it-on-your-server): 756 MB/s with `aes128-gcm@openssh.com`, 260 MB/s with
`chacha20-poly1305@openssh.com`.

ChaCha20 did not change: it never depended on the processor's AES instructions. With AES-NI in use,
AES-GCM now moves files about two to three times as fast as ChaCha20 on x64.

## Getting the full speed

### The server

Install the x64 package of 10.5.3.0 or later (every Windows Server edition, 64-bit Windows 10 and
11). Check the installed version:

```powershell
(Get-Item "$env:ProgramFiles\OpenSSH\sshd.exe").VersionInfo.FileVersion   # 10.5.3.0 or later
```

The x86 and ARM64 packages are built without LibreSSL's assembly code, so they have no AES
acceleration; there `chacha20-poly1305@openssh.com` is likely the faster choice (measure it with the
test below).

### The clients

The client decides which cipher a connection uses: it takes the first one in its own list that the
server also offers.

| Client | Default choice | To get the full speed |
|---|---|---|
| WinSCP | AES (`aes256-ctr` first) | nothing |
| FileZilla | AES (it is built on PuTTY's SSH code, whose list starts with AES) | nothing |
| PuTTY `psftp`, `pscp` | AES | nothing |
| OpenSSH `sftp`, `scp`, `ssh` (Windows, Linux, macOS) | `chacha20-poly1305@openssh.com` | `-c aes128-gcm@openssh.com`, or in the client's `~/.ssh/config`: `Ciphers aes128-gcm@openssh.com,aes256-gcm@openssh.com,chacha20-poly1305@openssh.com` |

Which cipher a connection really uses, from an OpenSSH client:

```powershell
ssh -v user@server exit 2>&1 | Select-String 'server->client cipher'
# debug1: kex: server->client cipher: aes128-gcm@openssh.com MAC: <implicit> compression: none
```

WinSCP shows it in its session log and under *Session → Server/Protocol Information*.

### Make every client use AES

When you cannot change the clients, the server can leave ChaCha20 out of the ciphers it offers.
Clients that prefer it then take their next choice: AES-GCM for current OpenSSH clients, AES-CTR
for OpenSSH 7 and older. In
`%ProgramData%\ssh\sshd_config`, above the `Match` blocks (or in the *Ciphers* field of the
Settings tab of OpenSSH Server PN Manager):

```
Ciphers aes128-gcm@openssh.com,aes256-gcm@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr
```

Checked with a default OpenSSH client, which then negotiates `aes128-gcm@openssh.com`. AES-GCM and
ChaCha20-Poly1305 are both modern authenticated ciphers, and the Hardening tab accepts this list.
Do this only on an x64 server with 10.5.3.0 or later. A client without any of these ciphers could
no longer connect; every current SSH client has them.

### Other settings

- **Compression** slows transfers down on a fast network: leave it off in the clients (OpenSSH:
  no `-C`; WinSCP: *Enable compression* off, the default).
- **Several transfers at once**: WinSCP and FileZilla can transfer several files in parallel. Each
  transfer is a connection of its own with its own `sshd-session.exe` on the server, so parallel
  transfers use several processor cores.
- **Transfer logging** (*Log file transfers* on the SFTP tab of the manager, `sftp-server -l INFO`)
  writes event log lines when a file is opened and closed, not for every block.
- **SFTP-only accounts confined to a folder** use the same `sftp-server.exe`; the check that keeps
  them in their folder happens when a file is opened.

## Measure it on your server

From a client computer, to include the network; or on the server itself with `localhost`, to see
what the processor allows. It needs a key login, because `sftp -b` does not ask for a password.

```powershell
# a 1 GiB test file of random data
$f = "$env:TEMP\sftp-test.bin"
$b = New-Object byte[] (1MB); (New-Object Random).NextBytes($b)
$s = [IO.File]::Create($f); for ($i = 0; $i -lt 1024; $i++) { $s.Write($b, 0, $b.Length) }; $s.Close()
"put `"$f`" sftp-test.bin`nget sftp-test.bin `"$f.back`"`nrm sftp-test.bin" | Set-Content "$env:TEMP\sftp-test.txt" -Encoding ascii

foreach ($c in 'aes128-gcm@openssh.com', 'chacha20-poly1305@openssh.com') {
    $t = Measure-Command { sftp -q -c $c -b "$env:TEMP\sftp-test.txt" user@server | Out-Null }
    '{0,-32} {1,6:N0} MB/s (1 GiB up, 1 GiB down)' -f $c, (2048 / $t.TotalSeconds)
}
```

Replace `user@server`; add `-i <key>` when the key is not the default one. The time includes the
login, so small files give lower figures. Delete `sftp-test.bin*` in `%TEMP%` afterwards.

## Where the limit is now

- **Processor, per connection.** Over the loopback, one transfer reaches about 500 to 750 MB/s.
  The cipher is no longer what limits it (AES-GCM runs at over 4 GB/s): `sshd-session.exe` on the
  server and the client each use most of one processor core for packet handling. Several transfers
  at once use several cores.
- **Network.** A 1 Gbit/s network carries at most about 115 MB/s. With a fast processor, 10.5.2.0
  already reached that with AES, so there 10.5.3.0 shows as less processor load per transfer. The
  higher speed shows on 2.5 and 10 Gbit/s networks, on slower processors, and when several
  transfers share the server.
- **Disk and antivirus.** The server's disk, and an antivirus that scans files as they are written,
  can be slower than the connection.
- **Tried and left out**, because they did not help in repeated measurements: larger buffers for the
  pipes between `sshd-session.exe` and `sftp-server.exe` (64 KiB instead of 4 KiB), larger SFTP
  requests (`sftp -B 261120`), and more requests at once (`sftp -R 256`).

## How it was verified

- LibreSSL's own tests: all 134 pass with the change, in x64 and x86 builds.
- Transfers between a client and a server of which only one had the change, in both directions,
  arrived byte for byte with every AES cipher.
- The CI of the release built x64, x86 and ARM64, ran the 767 OpenSSH unit tests on each, and
  installed the packages on Windows Server 2022 and 2025 and Windows 11 on ARM64, with real SFTP
  transfers in OpenSSH Server PN Manager's `--authtest`; the owner installed the release on Windows
  Server 2008 R2, 2019, 2025 and Windows 11.
- The `libcrypto.dll` of the published x64 package encrypts with AES-128-GCM at 4.66 GB/s.

Test computer for the figures above: Windows 11 Pro 26200, x64, 27 September 2026; SSH key login;
random data; the time of each transfer includes the login. Figures differ from computer to computer:
measure your own with the test above. Every detail is in the [changelog](CHANGELOG.md#10530-2026-09-27).

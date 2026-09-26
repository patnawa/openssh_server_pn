# Feature audit: OpenSSH for Windows 10.2.0.0 versus Bitvise SSH Server

This audit compares the server side of this repository's OpenSSH for Windows build (10.2.0.0,
2026-09-25, `sshd` 10.2p1 with LibreSSL 4.3.2) with the feature list published on
[bitvise.com/ssh-server](https://bitvise.com/ssh-server), as read on 2026-09-25. Bitvise's
claims are taken from that page; OpenSSH facts were taken from the effective configuration of the
installed server (`sshd -T`), from `ssh -Q` algorithm queries, from the build configuration
(`config.h.vs`) and from the OpenSSH manual pages.

Status legend: **Match** = equivalent capability available; **Partial** = achievable with
configuration, another Windows component or with limits; **Gap** = not available;
**N/A** = does not apply to OpenSSH's design.

## Summary

| Area | Match | Partial | Gap | N/A |
|---|---|---|---|---|
| Protocols and remote access | 4 | 1 | 1 | 1 |
| Administration and ease of use | 2 | 2 | 0 | 0 |
| Authentication | 4 | 1 | 1 | 0 |
| Account management | 1 | 0 | 3 | 0 |
| File transfer and storage | 2 | 5 | 3 | 0 |
| Terminal and shell | 2 | 2 | 1 | 1 |
| Advanced features | 3 | 4 | 2 | 1 |
| Security hardening | 5 | 1 | 2 | 0 |
| Cryptography | 7 | 2 | 2 | 1 |
| Platform, compliance, licensing | 2 | 1 | 2 | 0 |
| **Total** | **32** | **19** | **17** | **4** |

Where OpenSSH is at least as strong: SSH transport security, key exchange and signature
algorithms (including post-quantum ML-KEM-768 and sntrup761 hybrids, FIDO2 security keys, OpenSSH
certificates, PKCS#11), Kerberos single sign-on for domain accounts, group-based policy with
`Match` blocks, connection throttling and automatic per-source penalties, port forwarding
controls, licensing (free for any use, source available).

Where Bitvise is ahead: FTPS, virtual accounts and virtual groups, a built-in RFC 6238 one-time
password factor, virtual filesystem mount points and encrypted volumes, quotas and bandwidth
limits, tasks and e-mail alerts driven by log events, settings replication between servers, FIPS
140 validated cryptography, support for Windows XP / 2003 / Vista, and a mature GUI control
panel. This repository adds a management GUI (`tools/OpenSSH-Server-Manager`) that closes the
day-to-day administration gap: service control, settings, keys, firewall, logs and a hardening
check. The remaining gaps are architectural and are listed with the closest workaround.

## 1. Protocols and remote access

| Bitvise feature | OpenSSH for Windows 10.2 | Status | Notes |
|---|---|---|---|
| SSH server, console access | `sshd` with `cmd.exe`, PowerShell or any shell (`DefaultShell` registry value) | Match | |
| SFTP server | `sftp-server.exe` subsystem, SFTP protocol v3 plus OpenSSH extensions (`copy-data`, `posix-rename`, `statvfs`, `hardlink`, `fsync`, `lsetstat`, `limits`, `expand-path`, `users-groups-by-id`) | Match | |
| SCP server | `scp.exe` (SFTP-backed by default since 9.0, legacy protocol with `-O`) | Match | |
| FTPS server (FTP over TLS) | none | Gap | Use IIS FTP over TLS or another FTPS product alongside |
| Secure GUI remote access (RDP, VNC through the tunnel) | Local, remote and dynamic port forwarding (`-L`, `-R`, `-D`), `AllowTcpForwarding`, `PermitOpen`, `PermitListen`, `GatewayPorts` | Match | RDP over `ssh -L 3390:localhost:3389` works out of the box |
| Secure TCP/IP tunneling | as above | Match | |
| Dark mode interface | no server-side UI in OpenSSH | N/A | The manager GUI follows Windows system colours |

## 2. Administration and ease of use

| Bitvise feature | OpenSSH for Windows 10.2 | Status | Notes |
|---|---|---|---|
| Works immediately after installation | Yes: MSI starts `sshd`, creates default `sshd_config`, generates host keys, allows password login for local and domain accounts | Match | |
| Designed for Windows, easy to install and configure | MSI / winget install; configuration is a text file (`%ProgramData%\ssh\sshd_config`) | Partial | Text configuration; the manager GUI covers common settings |
| GUI control panel | Not in OpenSSH. This repository ships **OpenSSH Server Manager** (service status, settings editor with syntax test, login methods per user and group, authorized keys, key generator, default shell, firewall, event log viewer, hardening check) | Partial | Fewer features than Bitvise's panel; no virtual accounts or statistics |
| Remote configuration through the SSH client | Edit `sshd_config` over SSH or PowerShell remoting, then `Restart-Service sshd`; `sshd -t` validates | Match | Scriptable, no dedicated tool |

## 3. Authentication

| Bitvise feature | OpenSSH for Windows 10.2 | Status | Notes |
|---|---|---|---|
| Password authentication, local and Active Directory accounts | `PasswordAuthentication yes`: the Windows password, checked by `LogonUser`, for local and domain accounts (`DOMAIN\user` or UPN). Keyboard-interactive has no Windows back end | Match | |
| Password policy for virtual accounts | Windows account policy applies; no virtual accounts | Gap | Local security policy / AD policy governs real accounts |
| Public key authentication | `authorized_keys`, `administrators_authorized_keys`, OpenSSH certificates (`TrustedUserCAKeys`), FIDO2 keys (`sk-ssh-ed25519`, `sk-ecdsa`), PKCS#11 tokens | Match | Broader than Bitvise (certificates, FIDO2) |
| Kerberos 5 single sign-on via GSSAPI | Built with `GSSAPI_SSPI`; `GSSAPIAuthentication yes` enables SSO for domain accounts | Match | Off by default; a box on the Authentication tab of the manager (a Kerberos login was not tested here) |
| Choice of methods per account or group (password, public key; either one or both required) | `Match User` and `Match Group` blocks with `PasswordAuthentication`, `PubkeyAuthentication` and `AuthenticationMethods`, written by the Authentication tab of OpenSSH Server Manager | Match | Tested with real logins (`--authtest`) |
| Two-factor with time-based one-time passwords (RFC 6238) | No built-in TOTP. `AuthenticationMethods publickey,password` requires two factors of different kinds; FIDO2 keys with `verify-required` give possession plus PIN | Partial | Third-party TOTP requires a PAM-like hook, which the Windows port lacks |
| Windows session cache (reuse of logon sessions) | Each connection performs its own logon | Match | Functionally transparent; no configuration needed |

## 4. Account management

| Bitvise feature | OpenSSH for Windows 10.2 | Status | Notes |
|---|---|---|---|
| Windows group support for configuration | `AllowGroups`, `DenyGroups`, `Match Group` blocks (local and domain groups) | Match | |
| Virtual accounts defined in the server | none; every login maps to a Windows account | Gap | Create dedicated local accounts (for example in an `sftp-only` group) |
| Virtual group based configuration | none | Gap | `Match Group` on real Windows groups |
| Delegated administration | none; file ACLs on `sshd_config` and `%ProgramData%\ssh` | Gap | |

## 5. File transfer and storage

| Bitvise feature | OpenSSH for Windows 10.2 | Status | Notes |
|---|---|---|---|
| Virtual filesystem with directory restrictions | `ChrootDirectory` with `ForceCommand internal-sftp` in a `Match` block confines SFTP users to a directory tree | Partial | SFTP only; chroot for shells is not supported on Windows |
| Multiple virtual mount points | One chroot root per `Match`; junctions inside the root are followed | Partial | Build the tree with NTFS junctions or `subst` |
| Encrypted volumes, at-rest encryption | none in `sshd`; BitLocker or EFS on the data folder | Partial | OS-level encryption |
| SFTP jump server to remote SFTP servers | `ProxyJump` / `-J` for SSH sessions; no SFTP proxying | Partial | |
| SFTP v6 optimisations (`copy-file`, `check-file`) | SFTP v3 with `copy-data` extension; no `check-file` | Partial | |
| Unlimited file sizes | 64-bit offsets, limited by NTFS and the client | Match | |
| Quotas and usage statistics | none | Gap | NTFS quotas per user on the data volume give a storage cap; no transfer statistics |
| Per-user / per-group bandwidth limits | none | Gap | Windows QoS policy (`New-NetQosPolicy -IPDstPortStart 22`) can cap the port, not per user |
| Separate upload / download speed limits | none | Gap | |
| Permissions honoured | NTFS ACLs apply to every transfer | Match | |

## 6. Terminal and shell

| Bitvise feature | OpenSSH for Windows 10.2 | Status | Notes |
|---|---|---|---|
| VT100 / xterm terminal support | ConPTY pseudo console on Windows 10 1809+ / Server 2019+ gives correct xterm behaviour; older Windows use the `ssh-shellhost` VT100 emulation | Match | Fallback has limits on older Windows |
| bvterm (proprietary terminal) | none | N/A | Bitvise-client specific |
| Restricted shell (BvShell) with directory limits | `ForceCommand`, `PermitTTY no`, `internal-sftp` for file-only users; no restricted interactive shell | Partial | |
| Full Windows console feature support | ConPTY passes through console applications, colours and resizing | Match | Windows 10 1809+ |
| Choice of shell per user | Global `DefaultShell`; per-group `ForceCommand` in `Match` blocks | Partial | No per-user shell selection without `Match User` |
| Telnet forwarding to legacy Telnet servers | none | Gap | Port-forward to the Telnet host instead |

## 7. Advanced features

| Bitvise feature | OpenSSH for Windows 10.2 | Status | Notes |
|---|---|---|---|
| Unlimited users, no connection limits | No licence limits; `MaxSessions`, `MaxStartups`, `PerSourceMaxStartups` are administrator-controlled | Match | |
| Git integration (Git-only shell) | Git over SSH works with Git for Windows; restrict with `ForceCommand` and `git-shell` | Partial | |
| Tasks triggered by log events | none in `sshd`; Windows Task Scheduler can trigger on OpenSSH event IDs (Event Viewer, *Attach Task To This Event*) | Partial | |
| E-mail notifications from log conditions | none | Gap | Task Scheduler plus `Send-MailMessage` or a monitoring agent |
| Master / follower settings synchronisation | none; copy `sshd_config` and keys with your configuration management (DSC, Ansible, GPO file preferences) | Gap | |
| Multi-instance on the same computer | Possible manually: second service with `sshd.exe -f <other config> -p <port>` | Partial | Not packaged |
| Server-side port forwarding configuration | `AllowTcpForwarding`, `PermitOpen`, `PermitListen`, `GatewayPorts`, `PermitTunnel`, `AllowStreamLocalForwarding`, per `Match` block | Match | |
| Scriptable settings (BssCfg / PowerShell) | Plain-text `sshd_config`, `sshd -T` to dump effective settings, PowerShell for everything else | Match | |
| Logging and auditing | ETW / Event Log (*OpenSSH/Operational*), optional file log (`SyslogFacility LOCAL0`), `LogLevel VERBOSE` records key fingerprints per login | Match | No built-in statistics |
| Dark mode | see section 1 | N/A | |

## 8. Security hardening

| Bitvise feature | OpenSSH for Windows 10.2 | Status | Notes |
|---|---|---|---|
| Denial-of-service protection, connection throttling | `MaxStartups 10:30:100` (random early drop), `PerSourceMaxStartups`, `LoginGraceTime` | Match | Enabled by default |
| Login attempt delay for concurrent logins | `PerSourcePenalties` slows repeat offenders; `MaxAuthTries 6` per connection | Match | |
| Automatic temporary IP blocking with whitelist | `PerSourcePenalties` (default `authfail:5 noauth:1 crash:90 max:600`) refuses connections from penalised sources; `PerSourcePenaltyExemptList` whitelists | Match | Active in the effective configuration of this build |
| Username blacklist | `DenyUsers`, `DenyGroups` | Match | |
| Client IP address restrictions | `Match Address` / `Match LocalAddress`, `from=` options in `authorized_keys`, Windows Firewall scopes | Match | |
| Client version restrictions | none | Gap | |
| Account-specific IP restrictions | `Match User ... Address` and `from=` per key | Match | |
| IP access rules by country | none; GeoIP requires a firewall or proxy with country lists | Gap | |
| Obfuscated SSH protocol | none (non-standard extension) | Partial | Use a different port or a VPN; obfuscation is not part of the SSH standard |

## 9. Cryptography

| Bitvise feature | OpenSSH for Windows 10.2 | Status | Notes |
|---|---|---|---|
| Post-quantum hybrid KEX ML-KEM 768 + Curve25519 | `mlkem768x25519-sha256` (default-preferred), plus `sntrup761x25519-sha512` | Match | |
| Post-quantum hybrid ML-KEM 1024 + nistp384 | not implemented in OpenSSH 10.2 | Gap | |
| Curve25519, ECDH nistp256/384/521 | `curve25519-sha256`, `ecdh-sha2-nistp256/384/521` | Match | secp256k1 is not offered |
| DH group exchange SHA-256, fixed groups 2048 to 8192 | `diffie-hellman-group-exchange-sha256`, `group14/16/18` | Match | |
| DH 1024-bit legacy, SHA-1 groups | present but disabled by default (`group1-sha1`, `group14-sha1`, `gex-sha1`) | Match | Enable only for legacy clients |
| GSSAPI key exchange | not in upstream OpenSSH (GSSAPI is used for authentication only) | Gap | |
| Ed25519, ECDSA, RSA signatures | `ssh-ed25519`, `ecdsa-sha2-nistp*`, `rsa-sha2-256/512`; `ssh-rsa` (SHA-1) disabled by default; `RequiredRSASize 1024` | Match | |
| DSA (legacy) | removed in OpenSSH 10.0 | N/A | Insecure; Bitvise lists it as legacy only |
| ChaCha20-Poly1305, AES-GCM, AES-CTR | all offered; AES-CBC and 3DES available but disabled by default | Match | |
| HMAC-SHA2 encrypt-then-MAC, HMAC-SHA1 legacy | `hmac-sha2-256/512-etm`, `umac-64/128-etm`, SHA-1 variants available | Match | |
| FIPS 140 validated cryptography | LibreSSL is not FIPS validated and `sshd` does not use Windows CNG for SSH transport | Gap | The inbox Windows OpenSSH has the same limitation |
| FTP over TLS cipher suites | no FTPS | Gap | see section 1 |
| Encryption suitable for PCI / HIPAA | Modern default algorithm set, configurable with `Ciphers`, `MACs`, `KexAlgorithms`, `HostKeyAlgorithms` | Partial | Compliance depends on policy and documentation, not on the product |

## 10. Platform, compliance and licensing

| Bitvise feature | OpenSSH for Windows 10.2 | Status | Notes |
|---|---|---|---|
| Windows Server 2008 R2 to 2025, Windows 7 to 11 | Same range (see `docs/COMPATIBILITY.md`) | Match | |
| Windows XP, Server 2003, Vista, Server 2008 | not supported (`VersionNT >= 601`) | Gap | |
| 32-bit and 64-bit | x86, x64 and additionally ARM64 packages | Match | Bitvise does not list ARM64 |
| FIPS 140 validation | none | Gap | see section 9 |
| Licensing | BSD-style licence, free for personal and commercial use, source available; no per-server fee | Match | Bitvise: free personal edition, USD 99.95 per commercial licence |
| Support | Community (upstream issue trackers); no vendor support contract | Partial | |

## Appendix: other leading SSH and SFTP servers

The same audit was extended to other widely used servers on 2026-09-25 to find functions worth
adopting. Only server-side capabilities that go beyond a plain OpenSSH `sshd` are listed; the
ranked list of what this repository can adopt, and how, is in [ROADMAP.md](ROADMAP.md).

| Product | Positioning | Distinctive server-side functions (source) |
|---|---|---|
| **Tectia SSH Server** (SSH Communications Security) | Commercial, long-term-supported SSH for regulated enterprises and mainframes | X.509 and OpenSSH certificates side by side; smart card, PIV and YubiKey logon; RADIUS and SecurID; key policy enforcement (minimum key length, migration from user-managed to admin-managed keys); checkpoint-resume for multi-terabyte transfers; transparent FTP-to-SFTP conversion for legacy applications; FIPS and quantum-safe modules; forced commands per user or group ([ssh.com](https://www.ssh.com/products/tectia-ssh), datasheet) |
| **VanDyke VShell** | Windows-centric SSH2, SFTP, FTPS and HTTPS server with a control panel | Virtual roots per user or group, including roots that proxy to another SFTP server; per-user service ACLs (SFTP, SCP, shell, forwarding); connection filters and a Deny Host list that blocks after N failures; bandwidth throttling global, per user or per location; triggers on login, logout, failed authentication, upload, download and file events with e-mail; "RunAs" commands that let low-privilege users run approved commands elevated; logging to file, event log or syslog ([vandyke.com](https://www.vandyke.com/products/vshell/features.html)) |
| **SFTPGo** (open source) | Go-based, event-driven multi-protocol file server with virtual accounts | Virtual accounts in a database, cloud and encrypted backends, per-folder permissions and quotas by size, file count and transferred data; TOTP MFA and per-user allowed methods; Defender with weighted failure scores, observation window, ban time and escalation, shared across instances; per-protocol rate limits and geo-IP; Event Manager (filesystem, provider and schedule triggers; HTTP, command, e-mail, backup and retention actions); REST API, Prometheus metrics, audit logs ([sftpgo.com](https://sftpgo.com/), [docs](https://docs.sftpgo.com/latest/)) |
| **Cerberus FTP Server** | Windows-native SFTP, FTPS and HTTPS server with desktop and web administration | AD, LDAP and Entra ID single sign-on; client certificate verification with CRL; virtual directories with folder-level permissions, quotas and retention; IP allow and deny lists with auto-banning and geoblocking; "rogue transfer detection and shutdown"; event manager with folder automation and e-mail; statistics, reporting and SQL log capture; replication ([cerberusftp.com](https://www.cerberusftp.com/pricing/)) |
| **CrushFTP** | Browser-administered multi-protocol file server with a job engine | Virtual filesystem over S3, Azure, Google Drive, SharePoint and others, merged views, per-directory quotas, expiring share links; SAML, OIDC, RADIUS and authenticator-app OTP; hammering protection; active log viewer with filtering; scheduled jobs and reports; HA with DMZ front ends ([crushftp.com](https://www.crushftp.com/features.html)) |
| **Rebex Buru SFTP Server** | Lightweight Windows-only SFTP, SCP and FTPS server, YAML configuration, CLI and web administration | Windows or built-in accounts; per-method policy `disabled`, `enabled` or `required` (both required gives true two-factor); account lockout policy and manual locks; path mappings from virtual to physical or UNC paths with R, W, D flags combined with NTFS permissions; three shell modes (`none` confined to virtual paths, `legacy` with admin aliases, `terminal`); portable mode and instance cloning ([rebex.net](https://www.rebex.net/buru-sftp-server/features/)) |
| **Syncplify Server** | Enterprise SFTP, FTPS and HTTPS server with heuristic intrusion blocking and scripting | Protector with automatic block-listing; soft and hard quotas; per-user and global speed limits; multiple isolated instances per machine; cryptographically signed audit logs; JavaScript event scripts on 45+ triggers; active high availability ([syncplify.com](https://www.syncplify.com/syncplify-server)) |
| **Apache MINA SSHD** | Embeddable Java SSH library | Catalogue of SFTP extensions (`copy-file`, `check-file`, `md5-hash`, `space-available`) and hook points (file-system accessor, session and channel listeners); hybrid post-quantum key exchanges including ML-KEM-1024 with nistp384 ([github.com/apache/mina-sshd](https://github.com/apache/mina-sshd)) |
| **wolfSSH** | Tiny embeddable SSH server on wolfCrypt | FIPS 140-3 validated crypto, X.509 login, TPM-resident keys, ML-DSA signatures, `sshd_config`-style directives ([wolfssl.com](https://www.wolfssl.com/products/wolfssh/)) |
| **Dropbear** | Minimal SSH server for embedded systems | `permitopen` and `permitlisten` in `authorized_keys`, maximum session duration switch, authorized-keys directory, SHA-1 disabled by default ([matt.ucc.asn.au](https://matt.ucc.asn.au/dropbear/dropbear.html)) |
| **Pragma Fortress SSH** | Long-standing Windows SSH server with GUI and CLI management | Centralised configuration deployed to many servers; session manager across local and remote servers; FIPS 140-3 through the Microsoft crypto primitives; X.509 authentication ([pragmasys.com](https://www.pragmasys.com/ssh-server/features)) |
| **Upstream OpenSSH 10.3 to 10.5** | Reference implementation | Server-side security fixes and features released after the 10.2p1 code that the Windows port carries; see ROADMAP item 1 ([release notes](https://www.openssh.com/releasenotes.html)) |

## Recommendations for closing the most relevant gaps

1. **Two-factor authentication.** Require `AuthenticationMethods publickey,password` for
   administrators, or issue FIDO2 keys (`ssh-keygen -t ed25519-sk -O verify-required`). Document
   the policy in `sshd_config` `Match Group administrators`.
2. **SFTP-only users with confinement.** Create a local `sftp-only` group and add
   `Match Group sftp-only` / `ChrootDirectory C:\sftp\%u` / `ForceCommand internal-sftp` /
   `AllowTcpForwarding no` / `PermitTTY no`.
3. **Alerts.** Attach a Scheduled Task to OpenSSH event ID 4 (authentication failure) or use
   `LogLevel VERBOSE` with a log shipper.
4. **Bandwidth and storage.** Use NTFS quotas for storage caps and Windows QoS policies for
   port-level rate limits; there is no per-user limit in `sshd`.
5. **Server administration.** Use the OpenSSH Server Manager GUI from this repository for
   status, settings, keys, firewall and logs; keep `sshd_config` under version control for
   replication between servers.

# OpenSSH Server PN improvement plan

The October 2026 audit began at `1d60e71107cd8808bab4642ade9dd5ab9ea038ea`
(10.5.5.0 / Manager 2.2.1). The implementation is now 10.5.6.0 / Manager 2.3.0,
available as unsigned testing previews, with stable-release acceptance pending.
See [the findings and design analysis](AUDIT-2026-10-08.md).

The owner requested the full implementation, then explicitly chose to prepare the
automated checks and leave disposable-VM runs pending. No signing identity is
available. Checked items below mean implemented and verified within the stated
local scope. They do not imply that deferred acceptance or release signing passed.

## Correctness and recovery

- [x] Client file snapshots prevent stale known-host deletion and lost configuration
  edits; a cross-process lock coordinates manager writers and stale edits fail.
- [x] Client editing preserves repeated identities and first-value precedence;
  effective preview is restricted to the normal-user client workspace.
- [x] Authorized-key paths preserve quoting, percent tokens and multiple configured
  paths, including native parser/dumper round trips.
- [x] Verified endpoint discovery covers Includes, every listener, IPv6 and
  running/configured differences. Unsupported service command overrides fail explicitly.
- [x] Automatic blocking defers on incomplete session inspection and considers all
  verified endpoints instead of guessing a default port.
- [x] Transfer identity distinguishes separate events and survives archive round trips.
- [x] Incremental parsing preserves context across polling, day and report boundaries.
- [x] Log clear/wrap detection reports missing history and recovers checkpoints.
- [x] Persistent notifications retry each configured destination; transport work runs
  outside the shared state lock. Duplicate delivery is possible; after 12 failures,
  automatic retries stop and the queued item requires explicit retry.
- [x] Durable recovery records configuration and firewall state before restart, uses
  protected immutable runners and independent task scheduling, and preserves unresolved
  conflicts. Fault-injection and separate-process fixture tests pass.
- [x] Configuration writes fail without truncating the original when atomic replacement
  is unavailable; replacement preserves configuration security.
- [x] Client-only MSI feature selection excludes server cleanup. The shared GUI resolves
  bundled client tools in custom install directories without redirecting server operations.
- [ ] Prove actual SYSTEM-task recovery after GUI termination and reboot in a disposable VM.
- [ ] Prove client-only install/repair/uninstall preserves a running server and SSH session.

## Architecture and GUI

- [x] Configuration transaction and dependency modules preserve source semantics and
  detect changes to the edited file, included files and Include matches.
- [x] Shared server state distinguishes effective configuration and running endpoints.
- [x] Client/server entry modes and manifest separate normal-user client work from
  explicitly elevated administration; desktop-user launch carries that user's environment.
- [x] Foreground operations and dialog callbacks use awaited completion, with supported
  read cancellation and protection against late results reaching closed windows.
- [x] Navigation groups server, access, file exchange, client and diagnostics tasks and
  switches to a compact selector when width is limited.
- [x] Alert save controls and pending-change text stay visible while the form scrolls.
- [x] Agent health shows successful runs, checkpoint age, history gaps, delivery failures
  and degraded blocking; failed deliveries can be retried explicitly.
- [x] Client profiles are searchable and offer effective diagnostics and SFTP launching.
- [x] Automated checks cover navigation keys, accessibility properties, clipping,
  100/150/200% layout and light/dark/high-contrast palettes. Rendered samples were inspected.
- [ ] Verify desktop-user identity through UAC, including elevation with another account.
- [ ] Complete physical mixed-monitor, keyboard-only and screen-reader acceptance.
  System-DPI behavior is retained for the .NET Framework 4.5 baseline; PerMonitorV2 is
  a separate compatibility decision, not a completed feature of this change.

## Release and maintenance assurance

- [x] Pin Roslyn 4.14.0 and .NET Framework 4.5 reference packages with verified SHA-256 hashes.
- [x] Compare independent manager builds, test the resulting executable, package those
  bytes and reject extracted-payload differences. All three local MSIs contain the same
  tested manager executable and configuration.
- [x] Manager changes trigger integration workflows; required client-only, SSH/SFTP and
  process-termination checks have prepared automated drivers.
- [x] Release-tag workflows require signing, verify intended manager/native payloads,
  and retest signed artifacts. Unsigned branch builds remain available.
- [x] Inventory upstream revisions and local patches, rationale and removal conditions.
- [x] Maintain key-format differential/tamper tests and add seeded native config-dump
  round trips; interoperability drivers are prepared for the installed-server fixture.
- [x] Update versions, the tested tracked manager binary, changelog, build/release,
  security and validation documentation.
- [ ] Execute the changed hosted CI workflows on the final committed revision.
- [ ] Run the signed release workflow after a signing identity is configured.

## Local evidence — 8 October 2026

| Check | Result and scope |
|---|---|
| Manager build | Two independent builds produced identical executable, configuration and build metadata; pinned compiler `4.14.0-3.25262.10 (8edf7bcd)`; four build-script regressions passed, including equivalent LF/CRLF and BOM inputs across checkout paths |
| Manager regressions | **160 passed**, including cross-process edits, async completion/cancellation, client semantics, transfer replay/outbox and durable recovery fixtures |
| GUI suite | **49 passed**; 19 PNGs, 100/150/200% layouts, three palettes, navigation, sticky controls, clipping and client-only pages |
| Native compilation | x64, x86 and ARM64 builds completed at version 10.5.6.0 |
| Native unit execution | **686 checks passed in seven binaries on each of x64 and x86**; the additional `win32compat` binary fails at its symlink case without elevation/Developer Mode. The complete native suite is therefore **not passed** locally |
| Crypto probes | **9/9 passed on each of x64 and x86**, including x86 DLL probes through 32-bit Windows PowerShell |
| AuthorizedKeysFile native round trips | **136/136 passed on each of x64 and x86**: eight fixed cases and 128 seeded combinations |
| Installer preinstall script | **137 passed** against simulated installer state |
| MSI table/package checks | **136 x64, 136 x86, 137 ARM64 passed**; these inspect packages without installing them |
| MSI payload identity | Extracted manager executable and configuration match the tested build in all three unsigned MSIs |
| ARM64 execution | Pending an ARM64 fixture; cross-compilation and MSI inspection do not establish runtime behavior |
| Static assurance | PowerShell parsing, workflow lint and upstream inventory checks pass; whitespace check passes |

Tested unsigned manager SHA-256:

```text
c814421ac38fa6c0ee767f8e02568988b0ef511d241adcbb0331dd9cd0d11f83
```

Configuration SHA-256:

```text
38607418bb4655c3c736572f52da1f35d926ccbf91ad1102f0dcda164e798451
```

The tracked files are `tools/OpenSSH-Server-PN-Manager/bin/OpenSSHServerPNManager.exe`
and its `.exe.config`. Local reports, build metadata, GUI images and unsigned MSI
artifacts are under `%TEMP%\pn-release-validation`; those local tested bytes are the
inputs for the unsigned preview assets, accompanied by their checksums and build record.
CI uploads reports and images separately
so failed runs also preserve evidence.

Reproduce the manager check from the repository root:

```powershell
./.github/scripts/Test-ManagerBuild.ps1 -OutDir "$env:TEMP\manager-tested"
```

Native, installer and package commands and fixture requirements are documented in
[VALIDATION.md](VALIDATION.md). VM drivers deliberately require an explicit
`-DisposableMachine` argument. They have been prepared and checked locally but
have not been run against a disposable installed system in this work.

## Deferred acceptance

- [ ] Elevated manager self-test, key-test and authentication/SFTP tests.
- [ ] Full native win32compat suite with symlink privileges, plus ARM64 runtime tests.
- [ ] MSI client-only, full install, upgrade, repair, failed-install rollback,
  uninstall and pending-file-replacement/reboot scenarios.
- [ ] Actual SYSTEM recovery after process termination and reboot, including
  external-edit conflicts and confirmation near the deadline.
- [ ] Client identity across elevation, physical mixed-DPI monitors and assistive technology.
- [ ] Signed tag pipeline and signature verification with the chosen identity.

Use the staged before/after-reboot driver in [VALIDATION.md](VALIDATION.md) when an
identified disposable VM is available. No experimental MSI was installed on the
workstation and the unrelated existing VM was not used. Only unsigned testing
prereleases are distributed; no signed stable release is claimed.

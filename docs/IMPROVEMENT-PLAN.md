# OpenSSH Server PN improvement plan

The October 2026 audit began at `1d60e71107cd8808bab4642ade9dd5ab9ea038ea`
(10.5.5.0 / Manager 2.2.1). The first audit implementation was distributed as
10.5.6.0 / Manager 2.3.0 testing previews. The 10.5.7.0 / Manager 2.3.1 follow-up
repairs their installer test failures, passed full hosted acceptance and was published
as regular unsigned releases on 8 October 2026, with Manager marked Latest.
See [the findings and design analysis](AUDIT-2026-10-08.md).

The owner requested the full implementation and later authorized unsigned regular
releases after hosted acceptance. Local manual VM/reboot runs remain deferred and
no signing identity is available. Checked items below refer only to their stated
local or hosted scope; they do not imply that remaining manual acceptance or signing passed.

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
- [x] Actual SYSTEM-task recovery after terminating the applying fixture process passed
  on all four hosted installation lanes; configuration, firewall and listeners were checked.
- [ ] Exercise termination through the actual GUI confirmation flow and recovery after a real reboot.
- [x] Client-only install/repair/uninstall preserves a running server and SSH session in all four hosted lanes.

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
  tested manager executable and configuration (historical r3 local package evidence).
- [x] Manager changes trigger integration workflows; required client-only, SSH/SFTP and
  process-termination checks have prepared automated drivers.
- [x] Signed `v*` / `manager-v*` tag workflows require signing, verify intended payloads
  and retest signed artifacts. Owner-authorized unsigned `release-*` publication uses
  exact hosted branch artifacts and leaves those signing gates unchanged.
- [x] Inventory upstream revisions and local patches, rationale and removal conditions.
- [x] Maintain key-format differential/tamper tests and add seeded native config-dump
  round trips; interoperability drivers are prepared for the installed-server fixture.
- [x] Update versions, the tested tracked manager binary, changelog, build/release,
  security and validation documentation.
- [x] Execute hosted manager validation on source `098e124`; its 164 unit tests, 49 GUI
  checks and 13 installer-fixture checks pass and its executable matches the local build.
- [x] All 14 expected jobs in product run 37773128497 passed, including the four installation lanes and release-files gate.
- [ ] Run the signed release workflow after a signing identity is configured.

## Historical local preview evidence — 10.5.6.0 / Manager 2.3.0

| Check | Result and scope |
|---|---|
| Manager build | Two independent builds produced identical executable, configuration and build metadata; pinned compiler `4.14.0-3.25262.10 (8edf7bcd)`; four build-script regressions passed, including equivalent LF/CRLF and BOM inputs across checkout paths |
| Manager regressions | **162 passed**, including cross-process edits, async completion/cancellation, client semantics, transfer replay/outbox and durable recovery fixtures |
| GUI suite | **49 passed**; 19 PNGs, 100/150/200% layouts, three palettes, navigation, sticky controls, clipping and client-only pages; explicit off-screen sizing and constrained-to-wide recovery checks |
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
86ae48a2d5ebf97d51391a1505e04247c4fca3a78665e82f7e5dea75eada25fd
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
`-DisposableMachine` argument. The manual before/after-reboot acceptance remains
unexecuted locally. Hosted installation results are recorded below.

## Historical preview verification and publication — 8 October 2026

The [manager workflow](https://github.com/patnawa/openssh_server_pn/actions/runs/37737760048)
passed on preview source commit `2f622a582dc894f683efc296b6b8fb86fa49a6d7`: **162 unit
tests and 49 GUI checks**. Its downloaded executable has the exact SHA-256 listed
above. All 19 screenshots had the expected dimensions, including full-width
navigation at 100%, 150% and 200% on the runner's small desktop.

Both unsigned prereleases are published:
[product 10.5.6.0](https://github.com/patnawa/openssh_server_pn/releases/tag/preview-v10.5.6.0-r3)
and [Manager 2.3.0](https://github.com/patnawa/openssh_server_pn/releases/tag/preview-manager-v2.3.0-r3).
All **12 product assets and 9 manager assets** were downloaded after publication
and matched their staged files byte for byte. At preview publication, `v10.5.5.0` was Latest.
The uploaded files are local unsigned builds; the independent hosted result does
not provide them with hosted build provenance or a cryptographic attestation.

The [full product workflow](https://github.com/patnawa/openssh_server_pn/actions/runs/37737760283)
has now completed with **failed installer acceptance**. Native build and unit jobs
passed for x64, x86 and ARM64. All four installer jobs (Windows Server 2022,
Windows Server 2025, the PowerShell 2.0 lane and Windows 11 ARM64) failed the same
three checks:

- The installed manager's `--selftest` failed **6 of 210 checks**, covering
  login-method initialization, SFTP reload, background refresh, initial dirty
  state and cumulative `AllowUsers` display. The passing preview unit/GUI suite did
  not establish their cause. The fixture defects are now repaired in `098e124`;
  the failed preview run itself remains a historical failure.
- The recovery fixture did not arm: its PowerShell child could not resolve
  `Get-FileHash`. Recovery after process termination was therefore not tested.
- The first-run check expected MSI action return value `1` and observed `0`.
  Separate assertions passed for opening the wizard, using the installing user's
  identity and consuming its request; this is not evidence of a failed wizard launch.

Basic installation, SSH/SFTP, key/authentication, upgrade, repair, rollback and
uninstall checks passed in that preview run. Its failed full integration acceptance
remains part of the preview record. The r3 files remain unchanged unsigned testing
previews; their assets and checksums have not been replaced.

## Follow-up repairs — 10.5.7.0 / Manager 2.3.1

Commit `098e124122438ae9b123af881a3897ba6487d8b4` corrects the test harness causes
without weakening the installed behavior assertions:

- The window fixture dispatches the posted `Shown` event before waiting for
  asynchronous startup. The direct background-refresh test restores a WinForms
  context before it starts, and each fixture restores its caller's context after
  disposal. Scratch fixtures reject attempted default-shell registry writes.
- The recovery test's Windows PowerShell child prioritizes its own modules over
  inherited PowerShell 7 modules before using `Get-FileHash` and related commands.
- The wizard test recognizes asynchronous MSI scheduling results while still
  requiring the wizard to open as the installing user and consume its request.

All six original isolated window failures now pass. Two new regressions failed
before their fixes and passed afterward. Local results are **164 unit tests,
49 GUI checks and 13 installer-fixture checks**, with matching independent pinned
manager builds. The [hosted manager run](https://github.com/patnawa/openssh_server_pn/actions/runs/37773127926)
passed the same checks and produced the exact same executable:

```text
ef1b84b5a1d5d3fe63579ceb50e614795de77c95b1090042be044b81b3090ea3
```

The [full product run](https://github.com/patnawa/openssh_server_pn/actions/runs/37773128497)
completed **successfully** on `098e124`: all **14 expected jobs passed**, with tag-only
signing/release jobs skipped as intended for a branch build. x64, x86 and ARM64 builds,
native unit tests, crypto probes and configuration round trips passed. All four installation
lanes — Server 2022, Server 2025, PowerShell 2.0 and Windows 11 ARM64 — passed **212/212
installed self-tests**, actual SYSTEM recovery after terminating the applying process,
wizard launch, client-only coexistence, authentication, SSH/SFTP, upgrade, repair, rollback
and uninstall checks. The release-files gate passed. Informational Pester: **159 passed,
0 failures, 1 ignored**. These results close the three preview failure categories on all
four hosts; the original failed preview run remains historical evidence.

Hosted process-termination recovery does not establish the manual GUI click flow or
recovery after an actual reboot.

The exact accepted hosted artifacts from source
`098e124122438ae9b123af881a3897ba6487d8b4` were published on **8 October 2026** as regular unsigned
[product 10.5.7.0](https://github.com/patnawa/openssh_server_pn/releases/tag/release-v10.5.7.0)
and [Manager 2.3.1](https://github.com/patnawa/openssh_server_pn/releases/tag/release-manager-v2.3.1),
with Manager marked Latest. Both regular-release flags and GitHub's Latest destination
were verified. All 11 product and 8 Manager assets were downloaded afresh before
publication and publicly afterward; all 19 hashes matched the accepted staging files.
These branch artifacts have no Authenticode signature or cryptographic attestation.
Existing r3 preview tags and assets remain unchanged; signed `v*` / `manager-v*`
workflow gates remain unchanged too.

## Remaining acceptance and publication

- [x] Repair the three preview failure causes without weakening their assertions;
  the original six isolated window cases and two new regressions pass locally.
- [x] Verify 164 unit tests, 49 GUI checks and 13 installer-fixture checks locally
  and in the hosted manager run, with identical manager bytes.
- [x] Pass 212/212 installed self-tests, actual SYSTEM process-termination recovery
  and wizard launch in all four hosted installation lanes.
- [x] Complete ARM64 installation and every required native, client-only,
  authentication/SSH/SFTP, installer lifecycle and release-files gate.
- [x] Publish and verify the two regular unsigned releases, mark Manager Latest,
  and verify all 19 asset hashes through fresh draft and public downloads.
- [ ] Run actual GUI-click recovery and deadline/conflict/cancel scenarios manually.
- [ ] Run pending-file-replacement and configuration recovery across a real reboot.
- [ ] Verify another-account UAC/client identity, physical mixed-DPI monitors,
  keyboard-only use, high contrast and screen-reader behavior.
- [ ] Run the signed tag pipeline after a signing identity is configured.

Use the before/after-reboot driver in [VALIDATION.md](VALIDATION.md) on an identified
disposable VM. No experimental MSI was installed on the workstation and the unrelated
existing VM was not used. Hosted acceptance and regular publication do not close these
manual or signing items; no signed release is claimed.

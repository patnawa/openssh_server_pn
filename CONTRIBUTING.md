# Contributing

Thank you for helping improve OpenSSH Server PN. The server and client source (`src/`), the
installer (`src/contrib/win32/install`), OpenSSH Server Manager (`tools/`) and the documentation
all live in this repository.

## Where changes go

| Change | Destination |
|---|---|
| Installer, Windows-specific code in `src/contrib/win32`, OpenSSH Server Manager, library version bumps, documentation | Pull request here |
| Bugs in OpenSSH itself that also affect upstream (protocol, `sshd`, `ssh`, key handling) | Pull request here, and please report them upstream as well: [openssh.com/report.html](https://www.openssh.com/report.html) for cross-platform code, [PowerShell/openssh-portable](https://github.com/PowerShell/openssh-portable) for the Windows port. A fix that lands upstream reaches this project with the next merge |
| Security vulnerabilities | Not as a public issue; see [SECURITY.md](SECURITY.md) |

## Reporting test results

The most valuable contribution is a verified result on a platform not yet listed in
[docs/COMPATIBILITY.md](docs/COMPATIBILITY.md). Open an issue with:

- Package file name and SHA-256 (`Get-FileHash`).
- Windows edition, version and build (`winver` or
  `(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').DisplayVersion`).
- Output of the verification steps in [docs/INSTALL.md](docs/INSTALL.md), section 4, and of
  `OpenSSHServerManager.exe --check`.
- Anything that failed, with the exact error text, the relevant events from
  *Applications and Services Logs / OpenSSH / Operational*, and the `preinstall:` lines of the
  MSI log for installer problems.

## Pull requests

1. Branch from `main`.
2. For documentation, keep the style of the existing files: short sentences, tables for
   parallel facts, commands in fenced blocks, and no claims that were not actually tested.
   Mark untested statements as such.
3. For source or installer changes, follow [docs/BUILDING.md](docs/BUILDING.md), build all three
   architectures, and run on at least x64 the unit tests, an install over the previous release
   and `OpenSSHServerManager.exe --check`. Add a changelog entry.
4. For OpenSSH Server Manager changes, run `--unittest`, then `--selftest`, `--keytest` and
   `--authtest` elevated, and keep them green; add a unit test for new logic and a self-test for
   anything that needs the server. Rebuild `bin\OpenSSHServerManager.exe` and commit it with the
   source; CI checks both. `--authtest` leaves the profile
   of its test account until the next restart, because `sshd` does not unload profiles.
5. Describe in the pull request what was tested and on which Windows version.

Pull requests are reviewed on a best-effort basis. Small, focused changes are merged fastest.

## Releasing a build (maintainers)

1. For a new OpenSSH release, merge it into `src/` as described in `docs/BUILDING.md`, section 2,
   and run the unit tests.
2. Set the file version in `src/contrib/win32/openssh/version.rc`, then build x64, x86 and ARM64
   and package the MSIs (`docs/BUILDING.md`, sections 3 to 5).
3. Verify on x64: install over the previous release with a session open, log in with a key,
   restart and kill `sshd`, run `OpenSSHServerManager.exe --check`, `--keytest` and
   `--authtest`. Record the
   results in the changelog.
4. Generate `SHA256SUMS.txt`, add the changelog entry, update the README tables and
   `docs/COMPATIBILITY.md`.
5. Attach the MSIs, `OpenSSHServerManager.exe` and `SHA256SUMS.txt` to a GitHub release tagged
   `v<version>`, and note that the packages are unsigned.

# Contributing

Thank you for helping improve OpenSSH Server PN. The server and client source (`src/`), the
installer (`src/contrib/win32/install`), OpenSSH Server PN Manager (`tools/`) and the documentation
all live in this repository.

## Where changes go

| Change | Destination |
|---|---|
| Installer, Windows-specific code in `src/contrib/win32`, OpenSSH Server PN Manager, library version bumps, documentation | Pull request here |
| Bugs in OpenSSH itself that also affect upstream (protocol, `sshd`, `ssh`, key handling) | Pull request here, and please report them upstream as well: [openssh.com/report.html](https://www.openssh.com/report.html) for cross-platform code, [PowerShell/openssh-portable](https://github.com/PowerShell/openssh-portable) for the Windows port. A fix that lands upstream reaches this project with the next merge |
| Security vulnerabilities | Not as a public issue; see [SECURITY.md](SECURITY.md) |

## Reporting test results

The most valuable contribution is a verified result on a platform not yet listed in
[docs/COMPATIBILITY.md](docs/COMPATIBILITY.md). Open an issue with:

- Package file name and SHA-256 (`Get-FileHash`).
- Windows edition, version and build (`winver` or
  `(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').DisplayVersion`).
- Output of the verification steps in [docs/INSTALL.md](docs/INSTALL.md), section 4, and of
  `OpenSSHServerPNManager.exe --check`.
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
   and `OpenSSHServerPNManager.exe --check`. Add a changelog entry.
4. For OpenSSH Server PN Manager changes, run `--unittest`, then `--selftest`, `--keytest` and
   `--authtest` elevated, and keep them green; add a unit test for new logic and a self-test for
   anything that needs the server. Rebuild `bin\OpenSSHServerPNManager.exe` and commit it with the
   source for local users. CI restores the pinned toolchain, builds twice, checks reproducibility,
   and tests/packages the fresh artifact; the committed binary is not a release input. `--authtest` leaves the profile
   of its test account until the next restart, because `sshd` does not unload profiles.
5. Describe in the pull request what was tested and on which Windows version.

Pull requests are reviewed on a best-effort basis. Small, focused changes are merged fastest.

## Releasing a build (maintainers)

Since the workflow `.github/workflows/openssh.yml` exists, a tag `v<version>` builds, tests and
packages everything and creates a draft release with `SHA256SUMS.txt`, an SBOM and attestations;
[docs/RELEASING.md](docs/RELEASING.md) describes it. Pull requests that change `src/`, the
workflows, manager source or release tools run the build and integration checks too; use the pull request template.
The manual steps below remain the way to build without CI, and the record of how 10.5.1.0 was
made.

1. For a new OpenSSH release, merge it into `src/` as described in `docs/BUILDING.md`, section 2,
   and run the unit tests.
2. Set the file version in `src/contrib/win32/openssh/version.rc`, then build x64, x86 and ARM64
   and package the MSIs (`docs/BUILDING.md`, sections 3 to 5).
3. Verify on x64: install over the previous release with a session open, log in with a key,
   restart and kill `sshd`, run `OpenSSHServerPNManager.exe --check`, `--keytest` and
   `--authtest`. Record the
   results in the changelog.
4. Generate `SHA256SUMS.txt` (one line per file: the lower-case hash, two spaces, the file
   name; LF line endings, so that `sha256sum -c` reads it too), add the changelog entry, update the README tables and `docs/COMPATIBILITY.md`.
5. Configure an owner-supplied signing identity before stable release tags. Stable tag builds require trusted,
   timestamped signatures on native payloads, the manager and MSI wrappers. CI verifies CAB payloads
   against the exact tested manager and creates a draft with checksums, build metadata, SBOM and provenance.
   Review that draft and the [disposable VM evidence](docs/VALIDATION.md) before publishing it.
6. For a manager-only release, `manager-v<version>` must match `Program.AppVersion`. The workflow builds
   reproducibly from pinned inputs, signs and tests the final bytes, then creates a draft rather than
   publishing the committed executable. It is not marked latest. Signing credentials and actual VM
   acceptance runs remain pending until provided; configuration alone is not evidence they passed.

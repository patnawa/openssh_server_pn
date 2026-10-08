# Releasing OpenSSH Server PN

How a release is made since the packages are built by GitHub Actions: what the workflows do, what a
person still does, how to set up code signing, and how anyone can verify the published files. The
manual build in [BUILDING.md](BUILDING.md) stays the reference for building on your own machine.

The current testing preview is **10.5.6.0**, with **Manager 2.3.0**. It is unsigned and is not the
latest stable release. The stable tag workflows require Authenticode signing, a timestamp, and successful
verification of every intended executable payload. Branch and pull-request artifacts remain unsigned.
No signed release has been produced by this implementation work. On 2026-10-08 the repository's
Actions variable and secret lists were empty; signing still requires an owner-supplied identity.

### Unsigned testing previews

The owner requested distribution of the locally tested audit follow-up while signing and
disposable-VM acceptance remain pending. It is available through the separate prerelease tags
[`preview-v10.5.6.0-r2`](https://github.com/patnawa/openssh_server_pn/releases/tag/preview-v10.5.6.0-r2)
and [`preview-manager-v2.3.0-r2`](https://github.com/patnawa/openssh_server_pn/releases/tag/preview-manager-v2.3.0-r2).
These releases are explicitly **unsigned previews for testing**, marked prerelease and not latest.
The stable product release remains 10.5.5.0. They do not establish production readiness.

Preview tags point to the source commit for the tested local artifacts and use a namespace that
does not trigger the stable `v*` or `manager-v*` release workflows. Stable signing gates remain
unchanged. A push of that source to `main` separately runs branch CI; its results are not
claimed as evidence for local binaries. Do not dispatch a stable workflow against a preview tag.

Preview assets include SHA-256 checksums, compiler build metadata, local build provenance,
validation results, and a product SBOM. Local provenance is a build record, **not** a GitHub
cryptographic attestation. The notes list deferred VM/reboot, signing, ARM64 execution and
desktop acceptance. Verify uploaded asset hashes after publishing. Do not replace a published
preview's binaries with later builds; use a new preview tag for changed bytes.

## 1. What runs where

| Workflow | Runs on | Does |
|---|---|---|
| [`openssh.yml`](../.github/workflows/openssh.yml) | pull requests and pushes to `main` that change `src/`, the workflow, `.github/scripts/`, `tools/release/` or any manager source; tags `v*`; manually | Builds x64, x86 and ARM64 on `windows-2022`, packages the MSIs and runs the installer tests that need no installation (`src/contrib/win32/install/tests`, when present) on each; runs the unit tests (x64 and x86 on `windows-2022`, ARM64 on `windows-11-arm`) followed by required crypto probes and AuthorizedKeysFile dump round trips (`.github/scripts/Test-CryptoProbes.ps1`: `libcrypto` arithmetic, curves and random numbers, each `ssh-keygen` key type and `sshd -t`, one process per probe with a timeout, so a broken library is told apart from a broken test); installs the x64 MSI on `windows-2022` and `windows-2025` and the ARM64 MSI on `windows-11-arm` and tests it (below), and the x64 MSI once more on `windows-2022` with the installer's steps on the Windows PowerShell 2.0 engine of Windows 7 and Server 2008 R2 (both packages get `-Version 2` on their `powershell.exe` command lines; the pre-install step must report PowerShell 2.0 in the MSI log); runs the Pester end-to-end tests (not gating); assembles the release files (SBOM, `SHA256SUMS.txt`). For a tag: attestations and a **draft** release |
| [`manager.yml`](../.github/workflows/manager.yml) | changes to `tools/OpenSSH-Server-PN-Manager/`; tags `manager-v*` | Restores SHA-256-pinned compiler/reference packages, builds twice, requires byte-for-byte equality, tests the fresh executable and uploads `manager-tested`. Product CI reuses this workflow and payload. Tags sign and retest that executable, then create a draft with provenance |
| [`upstream-watch.yml`](../.github/workflows/upstream-watch.yml) | Mondays; manually | Opens an issue for each new release of OpenSSH, LibreSSL, libfido2, libcbor or zlib |
| Dependabot ([`dependabot.yml`](../.github/dependabot.yml)) | weekly | Pull requests that update the pinned actions |

The install test on each of the four machines, in this order (every `msiexec` that runs longer than 20 minutes is ended and fails the step: a hung custom action):

| Step | Checks |
|---|---|
| Client-only coexistence | Starts an in-box server and authenticated session; `ADDLOCAL=Client` install, repair and uninstall must preserve the server process, capability, configuration, host keys and session; client GUI is installed without server shortcuts |
| Install | `msiexec /i` exit 0; product version; `sshd` and `ssh-agent` Running and Automatic, running the installed `sshd.exe`; file version; `ssh -V`; the banner on port 22; recovery policy; one firewall rule for `sshd.exe`, port 22, all networks on Windows Server and Domain and Private on Windows 11 |
| OpenSSH Server PN Manager | the installed copy of the already-tested artifact; `--check`, `--selftest`, `--keytest`, `--authtest` must return 0 |
| Focused E2E | Authenticated SSH command and byte-identical SFTP round trips for empty, one-byte and 64 KiB files, including spaced paths |
| Independent recovery | Kills the process that applied unconfirmed settings; the actual SYSTEM recovery task must restore configuration, complete firewall state and working listeners |
| Upgrade | the rule is set to port 2222 and Private only, then a package of the same build with the third version field raised by one (`10.5.7.0` for `10.5.6.0`) is installed; the rule must keep both |
| Repair | `msiexec /fa`; the rule still has port 2222 and Private |
| Rollback | a copy of the release MSI with a custom action that fails after `StartServices` (`New-FailingMsi` in `OpenSSHCI.psm1`), installed with `ALLOWDOWNGRADE=1`: `msiexec` returns 1603, the previous package is registered again with its services and files, the rule has port 2222 and Private again (the rollback action of the saved firewall record), the record is gone |
| Downgrade | the older package without `ALLOWDOWNGRADE` must fail with 1603 and change nothing; with `ALLOWDOWNGRADE=1 SSHD_PORT=2200`, `sshd` must answer on 2200, `sshd_config` must say `Port 2200` and the rule must have port 2200 and still Private |
| Sessions | a key login stays open; `ACTIVE_SESSIONS=abort` must refuse the upgrade (1603) and keep the session; `ACTIVE_SESSIONS=close` must install it and end the session |
| Uninstall | services, rule and program files removed, `%ProgramData%\ssh` kept |

The upgrade, repair, rollback, downgrade and session checks test installer features that were written at the same
time as the workflow (firewall settings kept across upgrades, `SSHD_PORT`, `ACTIVE_SESSIONS`). The
variables `FIREWALL_PRESERVATION_CHECK`, `SSHD_PORT_CHECK` and `ACTIVE_SESSIONS_CHECK` in the `install-test`
job switch each group between `enforce`, `report` (warning only) and `skip`; the expected values are at
the top of [`.github/scripts/Test-Installer.ps1`](../.github/scripts/Test-Installer.ps1).

The Pester job has `continue-on-error: true`: the maintainers' end-to-end suite was written for their test
machines (fixed test accounts, WinRM, port forwarding, AppVerifier) and had never run for this project.
It runs in PowerShell 7 with Pester 3.4.6, as upstream does. Since pull request #5 (2026-09-26) it passes
completely: 159 passed, 1 skipped, in about 12 minutes. The narrower SSH/SFTP integrity and independent recovery scenarios above are required gates; the broader Pester suite remains informational.

The native configuration gate runs eight fixed and 128 seeded path/quote round trips against each
fresh `sshd`. The manager gate also runs real off-screen form checks at 100%, 150% and 200% in light,
dark and high-contrast palettes; reports and screenshots are retained in `manager-test-evidence`.

On a pull request GitHub evaluates the `paths` filter against every file the pull request
changes, not against the last push, so once a pull request touches `src/` every push to it runs
`openssh.yml` again, and `cancel-in-progress` stops the run still going, whatever the push
contains (a documentation change included). Bundle small follow-ups, or wait for a run to finish
before pushing. On `main` the filter applies to the push itself.

## 2. Making a release

1. **Merge the changes** to `main` through pull requests; `openssh.yml` must be green on the last one.
2. **Set the version.** `FILEVERSION` and `PRODUCTVERSION` in `src/contrib/win32/openssh/version.rc`
   (BUILDING.md, section 2: after a merge of a new OpenSSH release, `Sync-VersionResource.ps1` resets the
   third field). Windows Installer compares only the first three fields, so a new build must raise one of
   them. Add the changelog entry; leave its hashes open.
3. **Tag** the commit on `main`. The tag must be `v` plus that version, or the workflow stops:

   ```powershell
   git tag -a v10.5.6.0 -m "OpenSSH Server PN 10.5.6.0"
   git push origin v10.5.6.0
   ```

4. **Wait for `openssh.yml`.** A tag build compiles the vcpkg dependencies from their pinned source
   archives instead of the binary cache, requires signing configuration and signs the files (section 4), and runs
   every test. The release job runs only when the build, the unit tests and all install tests passed. It
   attests the files (section 6) and creates a **draft** release `v<version>` with:

   | File | |
   |---|---|
   | `OpenSSH-Win64-v<version>.msi`, `OpenSSH-Win32-v<version>.msi`, `OpenSSH-ARM64-v<version>.msi` | built by the workflow |
   | `OpenSSHServerPNManager.exe`, `OpenSSHServerPNManager.exe.config` | the exact tested `manager-tested` artifact also embedded in every MSI |
   | `build-info.json` | pinned toolchain identities, normalized compiler-input hashes and unsigned deterministic build hashes; final signed hashes are in `SHA256SUMS.txt` |
   | `OpenSSH-Server-PN-v<version>.cdx.json` | CycloneDX 1.5 SBOM (section 5) |
   | `SHA256SUMS.txt` | lower-case SHA-256, two spaces, file name; LF line endings (`sha256sum -c` reads it) |

   The notes list the hashes and how to verify them. A second run for the same tag replaces the files of
   the draft; it never changes a published release.
5. **Review the draft** (section 3), then publish it on the Releases page and mark it as the latest
   release.
6. **Record the hashes.** The MSIs are not bit-for-bit reproducible (every build gets a new product code
   and package code), so the published hashes are those of the files in the release. Put them in the
   changelog entry and the README table, and update `packaging/winget` (section 7).

A manager-only tag is `manager-v2.3.0` for source `Program.AppVersion = "2.3.0"`.
`manager.yml` builds, compares, tests, signs, verifies and retests the same executable, then creates a
**draft**, not marked latest. It never publishes the committed `bin/` executable merely because its
version matches. Review and publish the draft explicitly after all checks.

## 3. Reviewing the draft

```powershell
gh release download v10.5.6.0 --repo patnawa/openssh_server_pn --dir .\review
cd .\review
Get-Content SHA256SUMS.txt
Get-ChildItem -Exclude SHA256SUMS.txt | Get-FileHash -Algorithm SHA256   # the same values, upper case
gh attestation verify .\OpenSSH-Win64-v10.5.6.0.msi --repo patnawa/openssh_server_pn `
    --signer-workflow patnawa/openssh_server_pn/.github/workflows/openssh.yml --source-ref refs/tags/v10.5.6.0
```

Also check:

- the run summary of each build job: `ProductVersion`, `ProductCode`, SHA-256 and signature status of
  the MSI (the product codes go into `packaging/winget` and `packaging/intune`);
- the unit test summary (767 tests in 8 binaries for 10.5.0.0; a different count needs an explanation);
- the install test summaries and the logs attached to the run (`install-logs-*`), in particular
  `preinstall: warning` lines;
- the Pester result and its failures, although it does not block the release yet;
- that the manager SHA-256 matches `manager-tested`, both inside every MSI and as a standalone file.

What CI does not cover and still has to be done by hand, as before: a restart of a machine with the new
package (services come back), Windows versions other than Server 2022, Server 2025 and Windows 11 on ARM
(Windows 10, Server 2016 and 2019, the older systems in COMPATIBILITY.md; of Windows 7 and Server 2008 R2, the CI covers only their PowerShell 2.0 engine, on Windows Server 2022), the x86 package on 32-bit
Windows, an upgrade started from inside an SSH session, and a Kerberos login. Record in the changelog
what ran where. The repeatable two-phase driver in [VALIDATION.md](VALIDATION.md) covers file replacement pending reboot, task recovery after reboot, and cleanup. Hosted CI does not count as proof of those reboot scenarios.

## 4. Required code signing for release tags

Set `SIGNING_METHOD` to `trusted-signing` or `pfx` and configure its credentials before tagging.
An empty or unrecognised value fails release tags before native packaging. Pull requests do not use
signing credentials. The manager is signed once; every MSI and standalone release consumes those same
bytes. Native `.exe`/`.dll` files are signed before packaging, followed by the MSI itself.

`Test-Authenticode.ps1` requires a valid trusted signature and timestamp. Set the optional repository
variable `SIGNING_CERTIFICATE_THUMBPRINT` to restrict the accepted signer further. `Test-MsiPayload.ps1`
extracts the CAB with WiX dark, checks the manager against its tested artifact, and verifies the MSI
and every extracted executable/DLL for tags. Checksums, SBOM and attestations describe the final bytes.
No signing credential or private key is checked into the repository.

**Azure Artifact Signing** (formerly Trusted Signing), `SIGNING_METHOD` = `trusted-signing`:

1. In Azure, create an Artifact Signing account, complete the identity validation, and create a
   certificate profile (*Public Trust* for software distributed to the public).
2. Create an app registration (service principal) with a client secret, and give it the role
   *Artifact Signing Certificate Profile Signer* on the certificate profile.
3. In the repository settings, *Secrets and variables → Actions*:

   | Name | Kind | Value |
   |---|---|---|
   | `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` | secrets | the app registration |
   | `SIGNING_METHOD` | variable | `trusted-signing` |
   | `SIGNING_ENDPOINT` | variable | the account's regional endpoint, e.g. `https://eus.codesigning.azure.net/` |
   | `SIGNING_ACCOUNT` | variable | the account name |
   | `SIGNING_PROFILE` | variable | the certificate profile name |

The step uses `azure/artifact-signing-action` (pinned), which installs Microsoft's signing tools from
the PowerShell Gallery and NuGet during the run; its dependency cache is turned off for release builds.
Federated credentials (OIDC) instead of a client secret need `id-token: write` on the build job and an
`azure/login` step; that is not set up.

**Certificate file**, `SIGNING_METHOD` = `pfx`: secrets `SIGNING_PFX_BASE64` (the `.pfx`, base64) and
`SIGNING_PFX_PASSWORD`, optional variable `SIGNING_TIMESTAMP_URL` (default
`http://timestamp.digicert.com`). [`.github/scripts/Invoke-Signtool.ps1`](../.github/scripts/Invoke-Signtool.ps1)
signs with `signtool` (SHA-256, RFC 3161 time stamp) and verifies each file. Public CAs no longer issue
code-signing certificates with exportable keys, so this path suits a certificate from your own enterprise
CA, for packages used inside that organisation. Put that CA's root certificate (`.cer`, base64) in the
variable `SIGNING_TRUSTED_ROOT_BASE64`: the script adds it to the runner's trusted roots, otherwise the
signature check fails with *terminated in a root certificate which is not trusted*. Tested on 26 September
2026 with an in-memory self-signed certificate: signing and the DigiCert time stamp worked, and the check
failed as described because that root was not trusted; the import of the root was not tested.

When publishing the first signed build, update download instructions that describe historical packages as unsigned: README, INSTALL.md, SECURITY.md,
COMPATIBILITY.md (AppLocker/WDAC can then use publisher rules) and `packaging/`.

## 5. SBOM

[`tools/release/New-Sbom.ps1`](../tools/release/New-Sbom.ps1) writes a CycloneDX 1.5 JSON SBOM from the
repository: OpenSSH (version and tag from `src/version.h`, with the Windows port as its ancestor), LibreSSL
and libfido2 (overlay ports, with the SHA-512 of the source archives the portfiles pin), libcbor and zlib
(vcpkg.json overrides), licences as SPDX identifiers, purls and CPEs, the vcpkg baseline and the source
commit, and the release files with SHA-256 and SHA-512. It is deterministic for the same inputs and
checks its output before writing it. Locally:

```powershell
pwsh ./tools/release/New-Sbom.ps1 -File .\dist\*.msi, .\dist\OpenSSHServerPNManager.exe -OutFile .\dist\sbom.cdx.json
```

The release job also attests the SBOM for the three MSIs (section 6), so it can be checked against them:

```powershell
gh attestation verify .\OpenSSH-Win64-v10.5.6.0.msi --repo patnawa/openssh_server_pn --predicate-type https://cyclonedx.org/bom
```

## 6. Attestations

For every release file the release job creates a signed [SLSA build provenance](https://slsa.dev/provenance/v1)
attestation (`actions/attest`): the file's SHA-256, the repository, the commit, the tag and the workflow
run that produced it. It is signed with a short-lived Sigstore certificate issued to the workflow and
recorded in the public Sigstore transparency log, and GitHub stores it with the repository. Anyone can
check a download with the GitHub CLI:

```powershell
gh attestation verify .\OpenSSH-Win64-v10.5.6.0.msi --repo patnawa/openssh_server_pn
# stricter: only this workflow, only this tag, only GitHub-hosted runners
gh attestation verify .\OpenSSH-Win64-v10.5.6.0.msi --repo patnawa/openssh_server_pn `
    --signer-workflow patnawa/openssh_server_pn/.github/workflows/openssh.yml `
    --source-ref refs/tags/v10.5.6.0 --deny-self-hosted-runners
```

For `OpenSSHServerPNManager.exe` the attestation covers the exact fresh, signed and tested artifact
from this workflow. `build-info.json` records its pinned unsigned build inputs; `SHA256SUMS.txt` records
final signed bytes. Reproducibility compares two unsigned clean builds before signing. Releases before this workflow (10.5.1.0,
manager 1.5.0) have no attestations; their hashes are in the changelog.

## 7. After publishing

- **winget.** [`packaging/winget`](../packaging/winget) has the manifests of the current release under the
  proposed identifier `Patnawa.OpenSSHServerPN` (the winget-pkgs reviewers may ask for another). For a new
  version, move the folder to the new version, change the version, URLs, SHA-256 and product codes, run
  `winget validate --manifest <folder>`, and submit it to
  [microsoft/winget-pkgs](https://github.com/microsoft/winget-pkgs) (for example with
  `wingetcreate submit <folder>`). Not submitted yet. 10.5.1.0 is not to be submitted: its ARM64 package
  does not run.
- **Intune and Configuration Manager.** [`packaging/intune/README.md`](../packaging/intune/README.md)
  lists the product codes of each release; add those of the new build and update the examples.
- **Upstream watch.** Close the issues of `upstream-watch.yml` that the release resolved.

## 8. Still manual

| Step | Why |
|---|---|
| Version in `version.rc`, changelog entry, README tables, hashes after the release | Written by a person; the hashes exist only after the build |
| Publishing the draft and marking it as latest | A person reviews every release |
| Tests CI cannot run: restart, other Windows versions, x86 on 32-bit Windows, upgrade from inside an SSH session, Kerberos | See section 3 |
| winget submission | Needs a pull request to microsoft/winget-pkgs |
| Signing setup | Needs an Azure account or a certificate (section 4) |
| Repository settings, once: private vulnerability reporting (*Settings → Code security*; SECURITY.md relies on it and it was off on 26 September 2026), *Require actions to be pinned to a full-length commit SHA* (*Settings → Actions*), a branch rule or ruleset for `main` that requires the `openssh.yml` and `manager.yml` checks and code-owner review | Settings are not files |

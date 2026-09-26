# Releasing OpenSSH Server PN

How a release is made since the packages are built by GitHub Actions: what the workflows do, what a
person still does, how to set up code signing, and how anyone can verify the published files. The
manual build in [BUILDING.md](BUILDING.md) stays the reference for building on your own machine.

> **Not run yet.** The workflow `openssh.yml`, the release job and the signing steps described here were
> written on 26 September 2026 and checked with actionlint, but have not run on GitHub. Until the first
> tag has gone through them, treat every step below as a plan and check its result.

## 1. What runs where

| Workflow | Runs on | Does |
|---|---|---|
| [`openssh.yml`](../.github/workflows/openssh.yml) | pull requests and pushes to `main` that change `src/`, the workflow, `.github/scripts/` or `tools/release/`; tags `v*`; manually | Builds x64, x86 and ARM64 on `windows-2022`, packages the MSIs and runs the installer tests that need no installation (`src/contrib/win32/install/tests`, when present) on each; runs the unit tests (x64 and x86 on `windows-2022`, ARM64 on `windows-11-arm`) followed by the crypto probes (`.github/scripts/Test-CryptoProbes.ps1`: `libcrypto` arithmetic, curves and random numbers, each `ssh-keygen` key type and `sshd -t`, one process per probe with a timeout, so a broken library is told apart from a broken test); installs the x64 MSI on `windows-2022` and `windows-2025` and the ARM64 MSI on `windows-11-arm` and tests it (below); runs the Pester end-to-end tests (not gating); assembles the release files (SBOM, `SHA256SUMS.txt`). For a tag: attestations and a **draft** release |
| [`manager.yml`](../.github/workflows/manager.yml) | changes to `tools/OpenSSH-Server-Manager/`; tags `manager-v*` | Builds OpenSSH Server Manager, runs `--unittest` on the fresh build and the committed executable, reports whether the fresh build reproduces the committed one. For a tag: publishes the committed executable with an attestation |
| [`upstream-watch.yml`](../.github/workflows/upstream-watch.yml) | Mondays; manually | Opens an issue for each new release of OpenSSH, LibreSSL, libfido2, libcbor or zlib |
| Dependabot ([`dependabot.yml`](../.github/dependabot.yml)) | weekly | Pull requests that update the pinned actions |

The install test on each of the three machines, in this order:

| Step | Checks |
|---|---|
| Install | `msiexec /i` exit 0; product version; `sshd` and `ssh-agent` Running and Automatic, running the installed `sshd.exe`; file version; `ssh -V`; the banner on port 22; recovery policy; one firewall rule for `sshd.exe`, port 22, all networks on Windows Server and Domain and Private on Windows 11 |
| OpenSSH Server Manager | built from source with `build.ps1`; `--check`, `--selftest`, `--keytest`, `--authtest` must return 0 |
| Upgrade | the rule is set to port 2222 and Private only, then a package of the same build with the third version field raised by one (`10.5.2.0` for `10.5.1.0`) is installed; the rule must keep both |
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
Make it gating once its results on the runners have been triaged.

## 2. Making a release

1. **Merge the changes** to `main` through pull requests; `openssh.yml` must be green on the last one.
2. **Set the version.** `FILEVERSION` and `PRODUCTVERSION` in `src/contrib/win32/openssh/version.rc`
   (BUILDING.md, section 2: after a merge of a new OpenSSH release, `Sync-VersionResource.ps1` resets the
   third field). Windows Installer compares only the first three fields, so a new build must raise one of
   them. Add the changelog entry; leave its hashes open.
3. **Tag** the commit on `main`. The tag must be `v` plus that version, or the workflow stops:

   ```powershell
   git tag -a v10.5.2.0 -m "OpenSSH Server PN 10.5.2.0"
   git push origin v10.5.2.0
   ```

4. **Wait for `openssh.yml`.** A tag build compiles the vcpkg dependencies from their pinned source
   archives instead of the binary cache, signs the files when signing is set up (section 4), and runs
   every test. The release job runs only when the build, the unit tests and all install tests passed. It
   attests the files (section 6) and creates a **draft** release `v<version>` with:

   | File | |
   |---|---|
   | `OpenSSH-Win64-v<version>.msi`, `OpenSSH-Win32-v<version>.msi`, `OpenSSH-ARM64-v<version>.msi` | built by the workflow |
   | `OpenSSHServerManager.exe`, `OpenSSHServerManager.exe.config` | the committed files, as always |
   | `OpenSSH-Server-PN-v<version>.cdx.json` | CycloneDX 1.5 SBOM (section 5) |
   | `SHA256SUMS.txt` | lower-case SHA-256, two spaces, file name; LF line endings (`sha256sum -c` reads it) |

   The notes list the hashes and how to verify them. A second run for the same tag replaces the files of
   the draft; it never changes a published release.
5. **Review the draft** (section 3), then publish it on the Releases page and mark it as the latest
   release.
6. **Record the hashes.** The MSIs are not bit-for-bit reproducible (every build gets a new product code
   and package code), so the published hashes are those of the files in the release. Put them in the
   changelog entry and the README table, and update `packaging/winget` (section 7).

A release of the management console alone works as before: a tag `manager-v<version>` on a commit whose
`bin\OpenSSHServerManager.exe` has that version. `manager.yml` publishes the committed executable, its
`.exe.config` and `SHA256SUMS.txt`, not marked as latest, now with a provenance attestation.

## 3. Reviewing the draft

```powershell
gh release download v10.5.2.0 --repo patnawa/openssh_server_pn --dir .\review
cd .\review
Get-Content SHA256SUMS.txt
Get-ChildItem -Exclude SHA256SUMS.txt | Get-FileHash -Algorithm SHA256   # the same values, upper case
gh attestation verify .\OpenSSH-Win64-v10.5.2.0.msi --repo patnawa/openssh_server_pn `
    --signer-workflow patnawa/openssh_server_pn/.github/workflows/openssh.yml --source-ref refs/tags/v10.5.2.0
```

Also check:

- the run summary of each build job: `ProductVersion`, `ProductCode`, SHA-256 and signature status of
  the MSI (the product codes go into `packaging/winget` and `packaging/intune`);
- the unit test summary (767 tests in 8 binaries for 10.5.0.0; a different count needs an explanation);
- the install test summaries and the logs attached to the run (`install-logs-*`), in particular
  `preinstall: warning` lines;
- the Pester result and its failures, although it does not block the release yet;
- that `OpenSSHServerManager.exe` in the draft has the SHA-256 recorded for that manager version.

What CI does not cover and still has to be done by hand, as before: a restart of a machine with the new
package (services come back), Windows versions other than Server 2022, Server 2025 and Windows 11 on ARM
(Windows 10, Server 2016 and 2019, the older systems in COMPATIBILITY.md), the x86 package on 32-bit
Windows, an upgrade started from inside an SSH session, and a Kerberos login. Record in the changelog
what ran where.

## 4. Code signing (optional)

The packages are unsigned today. The workflow signs them when the repository variable `SIGNING_METHOD`
is set, and only for tag builds: pull requests never see the signing credentials. It signs every
`.exe` and `libcrypto.dll` before they go into the MSI, then the MSI, so the hashes, the SBOM and the
attestations are those of the signed files. The check step fails the build if a tag build's MSI is not
validly signed while signing is on.

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

With signing on, update the text that calls the packages unsigned: README, INSTALL.md, SECURITY.md,
COMPATIBILITY.md (AppLocker/WDAC can then use publisher rules) and `packaging/`.

## 5. SBOM

[`tools/release/New-Sbom.ps1`](../tools/release/New-Sbom.ps1) writes a CycloneDX 1.5 JSON SBOM from the
repository: OpenSSH (version and tag from `src/version.h`, with the Windows port as its ancestor), LibreSSL
and libfido2 (overlay ports, with the SHA-512 of the source archives the portfiles pin), libcbor and zlib
(vcpkg.json overrides), licences as SPDX identifiers, purls and CPEs, the vcpkg baseline and the source
commit, and the release files with SHA-256 and SHA-512. It is deterministic for the same inputs and
checks its output before writing it. Locally:

```powershell
pwsh ./tools/release/New-Sbom.ps1 -File .\dist\*.msi, .\dist\OpenSSHServerManager.exe -OutFile .\dist\sbom.cdx.json
```

The release job also attests the SBOM for the three MSIs (section 6), so it can be checked against them:

```powershell
gh attestation verify .\OpenSSH-Win64-v10.5.2.0.msi --repo patnawa/openssh_server_pn --predicate-type https://cyclonedx.org/bom
```

## 6. Attestations

For every release file the release job creates a signed [SLSA build provenance](https://slsa.dev/provenance/v1)
attestation (`actions/attest`): the file's SHA-256, the repository, the commit, the tag and the workflow
run that produced it. It is signed with a short-lived Sigstore certificate issued to the workflow and
recorded in the public Sigstore transparency log, and GitHub stores it with the repository. Anyone can
check a download with the GitHub CLI:

```powershell
gh attestation verify .\OpenSSH-Win64-v10.5.2.0.msi --repo patnawa/openssh_server_pn
# stricter: only this workflow, only this tag, only GitHub-hosted runners
gh attestation verify .\OpenSSH-Win64-v10.5.2.0.msi --repo patnawa/openssh_server_pn `
    --signer-workflow patnawa/openssh_server_pn/.github/workflows/openssh.yml `
    --source-ref refs/tags/v10.5.2.0 --deny-self-hosted-runners
```

For `OpenSSHServerManager.exe` the attestation says that the file came from that commit through the
workflow; the executable itself is compiled by the maintainer and committed, and `manager.yml` reports
whether a fresh build on GitHub reproduces it byte for byte. Releases before this workflow (10.5.1.0,
manager 1.5.0) have no attestations; their hashes are in the changelog.

## 7. After publishing

- **winget.** [`packaging/winget`](../packaging/winget) has the manifests of 10.5.1.0 under the proposed
  identifier `Patnawa.OpenSSHServerPN` (the winget-pkgs reviewers may ask for another). For a new
  version, copy the folder, change the version, URLs, SHA-256 and product codes, run
  `winget validate --manifest <folder>`, and submit it to
  [microsoft/winget-pkgs](https://github.com/microsoft/winget-pkgs) (for example with
  `wingetcreate submit <folder>`). Not submitted yet.
- **Intune and Configuration Manager.** [`packaging/intune/README.md`](../packaging/intune/README.md)
  lists the product codes of 10.5.1.0; add those of the new build.
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

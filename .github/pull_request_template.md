## What and why

<!-- What changes, and the problem it solves. Link an issue if there is one. -->

## How it was tested

<!-- Windows edition, version and architecture, and what you ran. State what you did not test.
     CI builds x64, x86 and ARM64, runs the unit tests and installs the x64 and ARM64 packages; say what
     you tested beyond that. -->

## Checklist

- [ ] Source or installer: built with [docs/BUILDING.md](https://github.com/patnawa/openssh_server_pn/blob/main/docs/BUILDING.md); unit tests, an install over the previous release and `OpenSSHServerManager.exe --check` pass on at least x64.
- [ ] OpenSSH Server Manager: `--unittest`, and elevated `--selftest`, `--keytest`, `--authtest` pass; `bin\OpenSSHServerManager.exe` rebuilt with `build.ps1` and committed with the source.
- [ ] New or changed behaviour is described in the documentation (INSTALL.md, the manager README, ...), with nothing claimed that was not tested.
- [ ] An entry in [docs/CHANGELOG.md](https://github.com/patnawa/openssh_server_pn/blob/main/docs/CHANGELOG.md) with the change and how it was verified.
- [ ] Not a security fix. Security fixes go through a private advisory first ([SECURITY.md](https://github.com/patnawa/openssh_server_pn/blob/main/SECURITY.md)).

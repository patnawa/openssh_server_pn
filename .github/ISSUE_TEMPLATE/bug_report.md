---
name: Bug report
about: Something does not work in these packages - the installer, OpenSSH (ssh, sshd, sftp, keys), OpenSSH Server Manager, the build or the documentation
title: ''
labels: ''
assignees: ''
---

<!--
Report OpenSSH behaviour here too (authentication, sftp, terminal, forwarding, ...): these packages run
OpenSSH 10.5p1 with this project's changes, which Microsoft's Win32-OpenSSH project does not ship and
cannot reproduce. If the official Microsoft package behaves the same way, say so below; the fix may
then belong upstream as well, and we will forward it.

Security vulnerabilities: do not report them here. Use the private report (Security tab, "Report a
vulnerability"), see SECURITY.md.
-->

**Package**
File name, version and architecture (x64 / x86 / ARM64), and its SHA-256:
`Get-FileHash .\OpenSSH-Win64-v<version>.msi -Algorithm SHA256`

**Installed version**
Output of `ssh -V` and `(Get-Item "$env:ProgramFiles\OpenSSH\sshd.exe").VersionInfo.FileVersion`:

```
```

**Windows**
Edition, version, build and architecture:
`Get-CimInstance Win32_OperatingSystem | Format-List Caption, Version, BuildNumber, OSArchitecture`

```
```

Domain member or workgroup, and Server Core or not (for servers):

**What happened**
The exact command or step, what you expected, and what happened instead, with the full error text.

**Install log** (installer problems)
Run the step that fails with a log, e.g. `msiexec /i <package.msi> /qn /norestart /l*v "$env:TEMP\openssh-install.log"`
from an elevated prompt, then attach `openssh-install.log`, or at least its `preinstall:` lines and the lines
around `Return value 3`:
`Select-String -Path "$env:TEMP\openssh-install.log" -Pattern 'preinstall:|Return value 3'`

**Server log** (service or login problems)
Events from *Applications and Services Logs / OpenSSH / Operational*, or `sshd -ddd` output, with
passwords, keys and host names removed.

**OpenSSHServerManager.exe --check** (optional)

```
```

**Same with the official Microsoft package?** yes / no / not tried

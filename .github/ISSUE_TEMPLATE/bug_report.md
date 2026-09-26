---
name: Package or documentation issue
about: Problems with the MSI packages, build procedure or documentation in this fork
title: ''
labels: ''
assignees: ''
---

<!--
Bugs in OpenSSH behaviour itself (authentication, sftp, terminal handling, ...) should be
reported upstream with the official package so they can be reproduced there:
https://github.com/PowerShell/Win32-OpenSSH/issues
Security issues: see SECURITY.md, do not report them here.
-->

**Package**
File name and SHA-256 (`Get-FileHash <file> -Algorithm SHA256`):

**Windows version**
Edition, version and build, and architecture (x86 / x64 / ARM64):
`(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion') | Select-Object ProductName, DisplayVersion, CurrentBuild`

**Installed OpenSSH version**
`((Get-Item (Get-Command sshd).Source).VersionInfo.FileVersion)` and `ssh -V`

**What is failing**
Exact command or step, and what happened. Attach the `msiexec` log (`/l*v`) for installer
problems, and relevant events from *Applications and Services Logs / OpenSSH / Operational* for
service problems.

**Expected**

**Actual**

**Verification output** (optional, from docs/INSTALL.md section 4)

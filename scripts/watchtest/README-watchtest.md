# Sentinel — Watch-test bundle (v0.1.1)

This is a pre-release build of Sentinel handed to you for a 7-day watch test.
It is **not** a finished product. Read this once before running anything.

## What Sentinel does

Sentinel runs as a local DNS resolver on your Windows machine. When your
browser, email client, or any other program tries to look up a domain name
(say `example.com`), Sentinel answers — and if that domain is on a public
list of known-malicious sites (URLhaus), Sentinel returns its own address
(`127.0.0.1`) instead of the real one. Your browser then connects to a
small block-page running on your own machine that explains what was caught
and why.

If the domain is benign, Sentinel asks an upstream resolver (Cloudflare or
Quad9) for the real answer and passes it through.

Everything is local. Nothing about your browsing leaves your machine.

## What is NOT in this build (yet)

This build exists for the watch test only. It is missing things that the
finished v0.1 will have:

- **No installer.** You unzip a folder and run a `.ps1` script.
- **No tray icon.** Sentinel runs hidden in the background. The
  `sentinel.log` and `sentinel.err.log` files in this folder are the
  only UI when something is wrong.
- **No auto-update.** This build is frozen for the 7 days of the test.
- **No `Add/Remove Programs` entry.** Use `uninstall.ps1` to revert.
- **No code-signed binary.** Windows SmartScreen may complain about an
  "unrecognized publisher." That is expected for a pre-release. The
  finished v0.1 will be signed.

What this build DOES handle:

- **Auto-start across reboots.** `setup.ps1` registers a Task Scheduler
  task (`SentinelWatchtest`) that re-launches sentinel.exe every time
  you log in. You don't have to re-run setup after restart, sleep, or
  shutdown — just log back in. `uninstall.ps1` removes the task before
  it kills the process, so the test ends cleanly when you decide to
  stop.

If any of those bother you, please tell the person who handed you this
bundle. Their list of "what bothers a real user" is more important than
the test passing.

## Consent

By running `setup.ps1` you agree to:

1. The dev sitting with you for ~30 minutes during the install (silent
   observation; they take notes on their own screen).
2. The dev pinging you on day 3 with one question: "is it still running,
   did anything break?"
3. The dev pinging you on day 7 with one question: "uninstalled? still
   running? noticed anything?"

You can stop the test at any time by running `uninstall.ps1`. No data has
to be sent anywhere; the dev only knows what you tell them.

## Files in this bundle

| File                  | Purpose                                          |
|-----------------------|--------------------------------------------------|
| `sentinel.exe`        | The actual program. Cross-compiled for Windows.  |
| `setup.ps1`           | Install: backs up DNS, swaps to 127.0.0.1, runs sentinel.exe. |
| `uninstall.ps1`       | Revert: stops sentinel.exe, restores DNS, flushes cache. |
| `.dns-backup.json`    | (Created at install time.) Your prior DNS settings, used by uninstall to restore. |
| `QUICKSTART.txt`      | 5-line install instructions. Read this first.    |
| `README-watchtest.md` | This file.                                       |

## What "still running on day 7" means

For the watch-test result to count, on day 7 the dev will ask you to run
two commands in PowerShell:

```powershell
Get-Process sentinel
Get-DnsClientServerAddress -InterfaceAlias "Wi-Fi"
```

The first should show a running process. The second should show
`127.0.0.1`. If both are true, "still running" counts. If either isn't,
something happened — that's the data the test exists to surface.

## Source

Source code: https://github.com/MuzeenMir/sentinel  
License: Apache-2.0  
Issues: https://github.com/MuzeenMir/sentinel/issues

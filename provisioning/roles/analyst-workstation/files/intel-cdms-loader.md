# Threat profile — CDMS Loader

**Classification:** Commodity loader
**First observed:** June 2026
**Confidence:** Medium
**Source:** Sector CERT advisory, redistributed internally

## Summary

CDMS Loader is a first-stage downloader distributed through macro-enabled
Office documents, typically presented as an invoice or delivery notice. It
carries almost no functionality of its own: the macro launches PowerShell
with a base64-encoded command, which retrieves a second-stage payload from
attacker infrastructure and executes it.

Keeping the loader minimal lets the operators change payloads without
resending the lure, and keeps the document itself unremarkable to most
scanners.

## Observed behaviour

**Initial access.** Macro-enabled attachment. The macro spawns PowerShell
with `-nop -w hidden -enc`, so no window appears and the instruction is not
readable in process logs without decoding.

**Payload delivery.** The decoded command retrieves an executable over HTTP
and writes it to the user's roaming profile, generally under
`%APPDATA%\Microsoft\`, named after a legitimate Windows binary.

**Persistence.** Two mechanisms are usually deployed together — a Run key
under HKCU and a scheduled task named to resemble a vendor update job.
Removing only one leaves the host compromised.

**Credential access.** Later stages have been observed reading LSASS memory.
Where a service account is configured to log on locally, that account's
credentials are the usual target.

**Lateral movement.** Stolen service account credentials are used to
authenticate to file shares and, where permissions allow, to domain
controllers. Access to the AD database directory has been attempted in
several incidents.

**Command and control.** DNS queries at a fixed interval to a domain that
does not resolve. The queries themselves carry the signal; the operators
change the domain between campaigns.

## Detection notes

The loader's own artefacts change frequently. The behaviour does not:

- An Office application spawning a scripting interpreter
- PowerShell invoked with a hidden window and an encoded command
- An executable written to a user profile bearing a system process name
- DNS queries at a suspiciously regular interval to a non-resolving domain

Every observed sample carries a campaign marker of the form
`CDMS-<8 hex characters>-STAGE2` in plain ASCII. Extracting strings from a
suspected sample is a faster confirmation than hash matching, since the
hash differs between builds.

## Attribution

None. The tooling is sold rather than operated by a single group, and has
been seen in campaigns with no apparent relationship to one another.

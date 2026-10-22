# SecAudit Platform — Public Profile Catalog

This repository is the public catalog of **profiles** for [SecAudit Platform](https://github.com/secauditplatform/SecAudit-Platform-public).

A profile is a versioned check package for one target type. The platform imports it, runs its audit content against hosts, and records **PASS / FAIL / SKIP / ERROR** for every rule. Remediation scripts and an Ansible compliance playbook can travel in the same package.

## What a profile is

| Part | File | Purpose |
|------|------|---------|
| Metadata | `description.json` | Identity, version, target (`os` or `software`), rules file, optional playbook |
| Rules | `profile_rules.json` | One record per check: id, title, severity, script, and the pattern that reads its result |
| Runtime rules | `<Name>.rules.json` | Optional data-driven payload for the audit script (used by the Windows packages) |
| Audit | `*.sh`, `*.ps1`, `*.py` | Collects evidence and prints one result line per rule |
| Remediation | `*_remediation.*` | Optional fix script, run as a separate remediation job |
| Playbook | `*.yml` | Optional Ansible compliance template; not an audit script |

A run flows through four steps:

1. **Import** — the platform validates the package and copies it into profile storage.
2. **Execute** — a job or AuditFlow runs the package's audit content on the target.
3. **Interpret** — each rule's output is reduced to PASS, FAIL, SKIP, or ERROR.
4. **Report** — results feed reports, waivers, drift, and trends; the run keeps a snapshot of the profile version that executed.

Profiles are content, not targets or schedules:

| Concept | Role |
|---------|------|
| **Profile** | Reusable check content for one operating system, service, or device |
| **Job** | Profile + hosts + credentials + schedule; produces a run |
| **Compliance playbook** | Ansible YAML bundled with a profile; runs the audit under Ansible |
| **AuditFlow** | Guided discovery: scan a range, fingerprint the OS, match profiles, select hosts, run |

## How profiles are classified

| Dimension | Values | Meaning |
|-----------|--------|---------|
| `category_slug` | `linux-platform`, `windows-platform`, `network-platform`, `services` | Catalog grouping; inferred from `os`/`software`, can be set explicitly |
| `profile_family` | `custom` | The only supported value. It is not a provenance or certification marker |
| `source_format` | `custom`, `xccdf`, `oval` | Package origin; SCAP uploads are materialized into the same layout |
| Executor | SSH, WinRM, Python | Chosen by script extension: `.sh`, `.ps1`, `.py` |

## Using the catalog with the platform

### 1. Put the catalog next to the platform

```bash
git clone https://github.com/secauditplatform/SecAudit-Platform-public.git
git clone https://github.com/secauditplatform/SecAudit-Platform-profiles-public.git

cd SecAudit-Platform-public
cp .env.example .env
# In .env:
# PROFILES_SOURCE_PATH=../SecAudit-Platform-profiles-public
docker compose up --build
```

`PROFILES_SOURCE_PATH` is mounted read-only at `/profiles` (`PROFILES_PATH`). Imported packages are copied to `PROFILES_STORAGE_PATH` (default `/data/profiles/<profile_name>`), so the read-only mount is never modified. The platform's own `profiles/` directory already contains its README, which is why a sibling clone is simpler than cloning into it.

For `deploy/compose`, `PROFILES_SOURCE_PATH` is resolved from `deploy/compose`; use an absolute path or `../../../SecAudit-Platform-profiles-public` there.

### 2. Import packages

- **UI** — open **Profiles**, review the catalog, select packages, and import them.
- **API** — `GET /api/v1/profiles/catalog`, `POST /api/v1/profiles/import?package_path=/profiles/Ubuntu24`, `POST /api/v1/profiles/import/bulk`.
- **Automation** — set `PROFILES_AUTO_SEED=true` to import the catalog at API startup, or `PROFILES_CATALOG_SYNC_ENABLED=true` for periodic sync.

Import validates the package before copying it. A ZIP or SCAP/XCCDF/OVAL upload goes through the same validator; SCAP content is converted to the canonical package layout with `source_format=xccdf` or `oval`.

### 3. Run checks

- **Manual job** — select the profile, hosts, and a credential. Linux and services run over SSH, Windows over WinRM, network devices over the Python executor.
- **AuditFlow** — scan a range, let the platform fingerprint the OS and suggest profiles, then select the hosts to check. Hosts without a matching profile are skipped, not guessed. Every package here has the compliance playbook AuditFlow needs.
- **Applicability** — OS profiles target a specific distribution and version; service profiles expect the service installed on the host. Check `description.json` before running a profile outside its target.

### 4. Review and remediate

Results are per rule. Reports export to HTML, PDF, and CSV; drift, diff, compare, trend, and waiver views are available for the same runs.

To fix findings, run the package's remediation script as a remediation job, then re-audit. Network remediation can instead export CLI/config for an operator to apply.

### 5. Keep profiles current

- Change the package in git and bump `version` in `description.json`.
- Re-import with update, or call `POST /api/v1/profiles/{id}/sync`; the catalog shows an update when the mounted package differs from the imported copy.
- Rule edits append `rule_changelog.json` and bump the profile version; playbook edits append `playbook_changelog.json` and bump the playbook version. Both are written to the imported copy in storage, not to this repository.

## Authoring or changing a profile

A minimal package looks like this:

```text
MyProfile/
├── description.json
├── profile_rules.json
├── MyProfile.sh                # audit; stem must match check_script
├── MyProfile_remediation.sh    # optional
└── MyProfile.yml               # optional compliance playbook
```

```json
{
  "profile_name": "My Profile",
  "version": "1.0",
  "is_active": true,
  "overview": "Security configuration baseline for ...",
  "os": { "name": "Ubuntu Linux", "vendor": "Canonical Ltd.", "version": "24.04" },
  "profile_family": "custom",
  "profile_rules": "profile_rules.json",
  "compliance_playbook": "MyProfile.yml",
  "compliance_playbook_version": "1.0"
}
```

For a service, replace `os` with a `software` block (`name`, `vendor`, `category`, `version`). At least one of the two is required.

A rule binds one check to one script line:

```json
{
  "num": "1",
  "requirement_id": "RULE1",
  "title": "The cramfs kernel module is not available",
  "explanation": "Unused filesystems increase the local attack surface.",
  "criticality": "LOW",
  "check_script": "MyProfile",
  "match_pattern": "RULE1=(.*)"
}
```

The audit script prints the result lines the pattern captures:

```text
RULE1= PASS: cramfs is not available
RULE2= FAIL: freevxfs is loaded
RULE3= SKIP: not a separate mount
RULE4= ERROR: mount table unreadable
```

The import validator rejects a package when:

- neither `os` nor `software` is declared;
- there is no audit script;
- no audit script matches the `check_script` names in the rules, or a discovered audit script has no rules;
- a `match_pattern` does not compile.

Keep `requirement_id` values stable across versions so results stay comparable. Bump `version` for every content change. The built-in AAG assistant can draft a custom profile from a prompt; the draft passes this same validator before it joins the profile list.

## Notes and limits

- **Credentials** — OS profiles use the host login. Service and network profiles also use the service-layer username/password on the host record (database/middleware account or device login).
- **Privileges** — Linux profiles read `/etc`, kernel, audit, and service state; run them with root-level access, directly or via sudo. Windows profiles need administrative WinRM. Review scripts before running them in production.
- **Remediation changes systems** — test in a lab first, then re-audit to verify.
- **Scope** — these are configuration baselines, not vulnerability scanners. SecAudit does not scan package versions or maintain a CVE database; a customer CVE feed can be shown beside failed checks.
- **Versions** — a profile version is the package revision, not the SecAudit Platform release.

## License

Platform code [SecAudit Platform](https://github.com/secauditplatform/SecAudit-Platform-public) is licensed under [PolyForm Noncommercial 1.0.0](https://github.com/secauditplatform/SecAudit-Platform-public/blob/main/LICENSE). Profile content is licensed separately and is not covered by that license — see the platform [NOTICE](https://github.com/secauditplatform/SecAudit-Platform-public/blob/main/NOTICE).

## See also

- [SecAudit Platform](https://github.com/secauditplatform/SecAudit-Platform-public)
- [Platform profile package format](https://github.com/secauditplatform/SecAudit-Platform-public/blob/main/profiles/README.md)

# Security Policy

## Supported Versions

Only the latest release is actively supported with security updates.

## Reporting a Vulnerability

If you discover a security vulnerability in AtomicLoop, please report it
responsibly. Do **not** open a public GitHub issue.

1. Email the maintainer directly (see repository contact info).
2. Include a clear description of the vulnerability and reproduction steps.
3. Allow reasonable time for a fix before any public disclosure.

## Scope

AtomicLoop is a **purple team testing tool** designed to run exclusively on
controlled, authorized test systems. It **must not** be deployed on production
systems or exposed to the internet.

### Critical Security Requirements

- **Authorization**: Only run AtomicLoop on systems you own or have explicit
  written authorization to test. Executing the embedded atomic tests on
  unauthorized systems is a criminal offense in most jurisdictions.

- **Execution confirmation**: The `confirm=true` flag in API requests is a
  safety control — do not disable `require_confirm` in config.yaml unless you
  have implemented your own access control layer.

- **Network exposure**: AtomicLoop binds to `127.0.0.1` by default. To expose
  it across a network (Docker, cross-VM lab), pass `--host 0.0.0.0` explicitly.
  Never expose the API to an untrusted network without authentication and TLS.

- **Admin tests**: Tests marked `required_permissions: administrator` must be
  run in a dedicated lab environment. They modify system configuration and
  may trigger endpoint security tools.

- **Cleanup commands**: Always run cleanup commands after testing to restore
  system state. AtomicLoop does not run cleanup automatically.

- **Run database**: Contains all test run artifacts including command outputs.
  For SQLite (`atomicloop.db`), restrict filesystem permissions so untrusted
  users cannot read the file. For PostgreSQL, restrict `SELECT` grants on the
  `atomicloop_runs` table to the application role only.

- **Flask debug mode**: Never use `debug: true` in production.

## Responsible Use

AtomicLoop is built for:
- Purple team exercises
- Detection engineering validation
- Security control testing in lab environments

It is **not** intended for offensive operations against systems you do not own.

## Out of Scope

- Issues in third-party dependencies (report to the respective project).
- Issues requiring physical access to the host machine.
- Misuse of the tool for unauthorized testing (user responsibility).

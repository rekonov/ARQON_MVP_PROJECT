# Changelog

All notable changes to the ARQON project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project is currently in pre-release (MVP) and does not yet follow Semantic Versioning.

## [Unreleased]

## 2026-03-03

### Added

- Pipeline configuration (final) for GitLab CI.

## 2026-02-26

### Added

- Test suites for rules engine and reputation scoring.

### Changed

- Fixed all ruff lint violations across 26 files (import sorting, line length, UP rules).
- Updated secret store and signing key paths to reflect new project structure.

### Fixed

- Outdated file paths in README documentation.
- Configuration paths broken by project restructure.

## 2026-02-24

### Added

- GitLab CI pipeline with baseline validation, always-on smoke job, and manual `promote_to_public` job with divergent history support.

## 2026-02-22

### Changed

- Cleaned runtime artifacts and updated handoff notes.
- Recorded migration to `ARQON_PROJECT` directory layout.

## 2026-02-17

### Added

- Runtime lock mechanism for exclusive agent execution.
- Auth-aware browser extension integration test.

### Changed

- Normalized import order across modules for lint compliance.

## 2026-02-16

### Added

- One-command mode switch between `USER` and `BROWSER_GUARD` operating modes.
- Extension API key printed on Browser Guard startup for easier setup.

### Fixed

- User-mode agent no longer self-blocks on PowerShell startup.

## 2026-02-15

### Added

- Baseline `.gitignore` for the repository.

### Changed

- Hardened user-mode URL policy enforcement.

### Fixed

- Launcher synchronization and variant build issues.

## 2026-02-14

### Added

- Initial ARQON agent with full security feature set:
  - Real-time process and download monitoring with risk scoring.
  - File quarantine manager with timestamped records.
  - Archive inspection for ZIP (nested high-risk/blocked files).
  - Script and LOLBin behavior heuristics.
  - Local and optional remote reputation adapter with TTL cache.
  - Authenticode signature inspection for PE/scripts.
  - Local REST API for browser and UI integrations.
  - Web dashboard with scan, events, quarantine, and incident export.
  - Ed25519-signed policy packs with replay protection.
  - DPAPI-backed secret store for Windows.
  - Windows Firewall synchronization.
  - Runtime watchdog with self-healing module restarts.
  - Incident export in JSON/CSV (CLI + API).
  - Secure install/update flow with backup rollback.
  - Diagnostics bundle export for incident response.
  - Retention cleanup manager for logs, backups, and quarantine.
  - System tray launcher and hardened Windows startup automation.
  - Configurable user/admin build variants.
  - Chromium browser extension for URL scanning.

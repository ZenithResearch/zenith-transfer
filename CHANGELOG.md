# Changelog

All notable changes to this project are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)

## [Unreleased]

### Fixed

- Recheck protected local RPC v3 registrations for LAN, Tailnet and public service profiles — locally registered administration must use its pinned host adapter and fail closed when the binding changes.
- Accept bounded hierarchical grant-review envelopes and report safe protocol errors — valid path selections exceeded the setup parser's smaller nesting budget and otherwise produced an opaque failure.
- Follow the verified public Wallet packaging revision — its source-integrity checks now pin the reviewed workspace lockfile.
- Pin the public native Wallet source and document a complete build from public repositories — the previous private-only revision prevented installation.
- Allow locked Cargo downloads by default and make offline mode explicit — fresh machines do not yet have the dependency cache required by forced offline builds.

### Changed

- Pin the public Wallet revision `7d81c5b0a9f74271fb5b2d5ea8d2711df40bf485` and label the development app build 33 — native Transfer and the public Chrome extension now build from the same canonical Wallet source revision.

### Added

- Document canonical service credentials and future owner-controlled endpoints — access points must not be mistaken for distinct credential authorities while existing URL-bound contracts remain unchanged.

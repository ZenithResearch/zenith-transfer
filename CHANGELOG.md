# Changelog

All notable changes to this project are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)

## [Unreleased]

### Fixed

- Follow the verified public Wallet packaging revision — its source-integrity checks now pin the reviewed workspace lockfile.

- Pin the public native Wallet source and document a complete build from public repositories — the previous private-only revision prevented installation.
- Allow locked Cargo downloads by default and make offline mode explicit — fresh machines do not yet have the dependency cache required by forced offline builds.

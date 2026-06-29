# Contributing

Thank you for contributing to this repository. This document explains the preferred workflow, local setup, formatting
and testing rules, and how to submit changes.

## Table of Contents

- Getting started
- Branching & pull requests
- Development setup
- Formatting \& linting
- Tests
- Commit messages
- Code review \& CI
- Reporting issues

## Getting started

- Fork the repository and clone your fork.
- Ensure you have `origin` and the main project as `upstream` (if desired).
- The primary development branch for contributions is `dev`. Open pull requests against `dev`.

## Branching \& pull requests

- Create a feature branch from `dev`:  
  `git checkout dev && git pull origin dev && git checkout -b feat/short-description`
- Keep changes focused and small. One logical change per PR.
- Push to your fork and open a PR from your branch into `dev`.
- Include a clear description, motivation, and tests or screenshots when applicable.

## Development setup

- Install Rust toolchain: `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
- Install Python 3.8+ and a virtual environment:
    - `python3 -m venv .venv && source .venv/bin/activate`
    - On Windows PowerShell: `py -3 -m venv .venv; .\.venv\Scripts\Activate.ps1`
    - Install Python build/test tools as needed: `python -m pip install maturin twine pytest`
- Install C/C++ build tools:
    - Linux: install `cmake`, `gcc`/`clang`, `pkg-config`, and normal system build tools.
    - macOS: install Xcode command line tools and CMake.
    - Windows: install Visual Studio Build Tools with the MSVC C/C++ toolchain and CMake.
- Build and run the main validation route: `python3 build.py test`.

## Formatting \& linting

- Rust:
    - Format: `cargo fmt --all`
    - Lint: `cargo clippy --all-targets --all-features -- -D warnings`
- Python:
    - Format with Black: `python -m black .`
    - Lint with ruff/flake8 as configured: `python -m ruff .` or `flake8 .`
- Run linters/formatters before opening a PR.

## Tests

- Primary route: `python3 build.py test`.
  This runs strict clippy checks, Rust unit/integration tests, C system tests through the Rust
  harness, doctests, benchmark smoke tests, the Python feature build, Python unittest coverage,
  and embedded build validation when the cross target/toolchain is available.
- Full long-duration route: `python3 build.py test full`.
  Use this before releases or when changing routing, time sync, reliability, memory budgeting, or
  scheduler behavior.
- Python bindings:
    - Build/check the Python feature with `python3 build.py python` or `cargo build --features python,timesync`.
    - For local Python package testing, use `python3 build.py maturin-develop` inside a virtualenv,
      then run relevant scripts/tests under `python-example/` or Python-specific tests.
    - `python-example/test.py` runs the manual Python system suite that exercises runtime schema,
      discovery, P2P, routing, side replacement, network variables, and memory-budget reporting.
    - For wheel checks, use `python3 build.py maturin-build` or the release helper documented in
      `docs/wiki/Release-Checklist.md`.
- C ABI and C wrapper tests:
    - `python3 build.py test` includes the Rust harness under `tests/c-system-test/`, which
      configures and runs the C system test binaries.
    - When changing C headers, C ABI functions, CMake glue, or wrapper behavior, also build the
      C examples/tests directly on your target platform when practical.
- Linux development:
    - Linux is the easiest environment for Docker wheel builds and CI parity.
    - Use `python3 build.py test` for normal validation and the Docker commands in
      `docs/wiki/Release-Checklist.md` for local multi-platform wheel builds.
- Windows development:
    - Use the MSVC Rust toolchain unless intentionally testing GNU targets.
    - Prefer PowerShell or Developer PowerShell with Visual Studio Build Tools on PATH.
    - Run `py -3 build.py test` for the normal route. If shell scripts or POSIX-only helpers are
      unavailable, run the equivalent `cargo`/`maturin` commands directly and note any gap in the
      PR.
- Include tests for bug fixes and new features. CI must pass before merging.

## Commit messages

- Use clear, imperative messages. Example: `feat(parser): add support for X` or `fix(build): correct linkage when Y`.
- Small, focused commits are easier to review. Squash or rebase as needed before merge.

## Code review \& CI

- All PRs should have passing CI checks and at least one approving review.
- Address review comments promptly. Keep the conversation polite and constructive.
- Maintainers may request changes or adjust scope for consistency.

## Reporting issues

- Open an issue with a descriptive title and reproduction steps.
- Provide environment details (OS, Rust/Python versions) and minimal repro if possible.

## License \& acknowledgements

- By contributing you agree that your contributions will be licensed under the project's existing license.
- Credit third-party code and follow upstream licenses for dependencies.

Thank you for improving the project.

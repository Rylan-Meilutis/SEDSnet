# Release Checklist

Use this checklist before publishing a v4 release.

## Required Checks

Run the default and full test routes:

```sh
python3 build.py test
python3 build.py test full
```

Run package checks:

```sh
cargo package --manifest-path sedsnet_macros/Cargo.toml --no-verify
cargo package --no-verify
maturin build
```

Or run the crate release helper. It defaults to a dry-run and will not upload crates unless
`--publish` is passed:

```sh
python3 publish_crates.py
python3 publish_crates.py --publish
```

The same helper has explicit PyPI opt-ins:

```sh
python3 publish_crates.py --pypi
python3 publish_crates.py --publish-pypi
python3 publish_crates.py --skip-crates --publish-pypi
```

For local Linux wheel builds without depending on CI, use Docker:

```sh
python3 publish_crates.py --skip-crates --skip-tests --docker-wheels --docker-sdist
python3 publish_crates.py --skip-crates --skip-tests --docker-all-wheels --docker-sdist
python3 publish_crates.py --skip-crates --skip-tests --docker-wheels \
  --docker-target x86_64-unknown-linux-gnu \
  --docker-target aarch64-unknown-linux-gnu
```

The Docker path writes artifacts to `dist/` by default. Linux wheels use the maturin manylinux
image. Windows wheels default to `x86_64-pc-windows-msvc` and use `rust:bookworm` with LLVM/xwin
setup because the generic maturin image does not include the MSVC-compatible tools needed by
native C dependencies such as `zstd-sys`. macOS wheels use the same osxcross Docker images as
SmartCopy when those images are reachable. On a macOS host, the helper falls back to local maturin
macOS builds if the osxcross image cannot be pulled.

- `registry.gitlab.rylanswebsite.com/rylan-meilutis/macos-cargo-image/x86_64-apple-darwin:x86_64-apple-darwin`
- `registry.gitlab.rylanswebsite.com/rylan-meilutis/macos-cargo-image/aarch64-apple-darwin:aarch64-apple-darwin`

For PyPI uploads, set `MATURIN_PYPI_TOKEN` or use maturin's configured credentials. Install maturin
first if it is not already available:

```sh
python3 -m pip install maturin
```

For local PyPI publishing without exporting the token every shell session, run:

```sh
python3 build.py maturin-login
```

That command validates the PyPI token before saving it to `.sedsnet-release.toml`. The file is
ignored by git and read automatically by `publish_crates.py --publish-pypi`. If no environment token
or saved config exists, `publish_crates.py --publish-pypi` starts the login flow before upload.

## CI Releases

Pushing a tag matching `v*` starts the GitHub release workflow:

- publishes `sedsnet_macros` and then `SEDSnet` to crates.io using `CARGO_REGISTRY_TOKEN`
- builds PyPI wheels for Linux, macOS, and Windows
- builds an sdist
- publishes all Python artifacts to PyPI using trusted publishing

GitHub PyPI publishing expects the project to be configured as a PyPI trusted publisher for the
release workflow.

The GitLab pipeline also has tag-gated release jobs for Linux-only self-hosted runners:

- crates.io publishing uses `CARGO_REGISTRY_TOKEN`
- Linux wheels and sdist build inside Docker images
- Windows `win_amd64` cross wheels build in Docker by default
- macOS cross wheels build in Docker by default using the SmartCopy osxcross images
- PyPI publishing uses `MATURIN_PYPI_TOKEN`

If the macOS cross images are unavailable to a GitLab instance, disable the `macos-cross-wheels`
job or replace `MACOS_IMAGE` with an equivalent osxcross image.

`SEDSnet` depends on `sedsnet_macros` through a versioned path dependency. Publish order matters:

1. Publish `sedsnet_macros`.
2. Wait for crates.io to index it.
3. Package and publish `SEDSnet`.

The main crate package check fails with `no matching package named sedsnet_macros found` until the
macro crate is published and indexed.

## Documentation

Crates.io uses the top-level `README.md`. Keep it accurate and include links to:

- docs.rs API documentation
- the project wiki or `docs/wiki/Home.md`
- `CHANGELOG.md`

The wiki source lives in `docs/wiki`. If external wiki repos are used, sync with:

```sh
python3 docs/sync_wiki.py
```

## Version Metadata

Update these files together:

- `Cargo.toml`
- `sedsnet_macros/Cargo.toml`
- `pyproject.toml`
- `README.md`
- `CHANGELOG.md`
- `docs/wiki/Changelogs.md`

## Final Sanity

Before tagging:

```sh
git diff --check
git status --short
```

The working tree should be clean after the release commit.

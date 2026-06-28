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

For PyPI uploads, set `MATURIN_PYPI_TOKEN` or use maturin's configured credentials. Install maturin
first if it is not already available:

```sh
python3 -m pip install maturin
```

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

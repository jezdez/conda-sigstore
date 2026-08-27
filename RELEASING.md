# Releasing

Releases are built from bare version tags by the `Release` GitHub Actions
workflow. The workflow builds the wheel and source distribution once, checks
their metadata, records GitHub build provenance, and attaches those files to a
draft GitHub release. It publishes the same files to PyPI through Trusted
Publishing and makes the GitHub release public only after PyPI succeeds.

## Repository configuration

The PyPI Trusted Publisher uses these values:

- Owner: `jezdez`
- Repository: `conda-sigstore`
- Workflow: `release.yml`
- Environment: `pypi`

The GitHub Actions environment `pypi` permits deployments only from version
tags and requires maintainer approval. Immutable releases are enabled, so a
published release tag and its assets cannot be changed.

## Prepare 0.1.0

1. Update `CHANGELOG.md`, `CITATION.cff`, and installation documentation with
   the version and release date.
2. Merge the release preparation into `main`.
3. Update the local branch and record the exact commit:

   ```console
   git switch main
   git pull --ff-only
   git rev-parse HEAD
   ```

4. Confirm the required hosted checks passed for that commit.
5. Create and push an annotated bare version tag:

   ```console
   git tag -a 0.1.0 -m "conda-sigstore 0.1.0"
   git push origin 0.1.0
   ```

The tag starts this sequence:

1. build the wheel and source distribution once
2. check the distribution metadata
3. record GitHub build provenance
4. create a draft GitHub release and attach the distributions
5. wait for approval of the `pypi` environment
6. publish the distributions to PyPI through Trusted Publishing
7. make the GitHub release public

## Verify the release

Download both formats from GitHub and PyPI, compare their bytes, then verify
GitHub's build provenance and PyPI's publish attestations:

```console
set -euo pipefail
release_check="$(mktemp -d)"
gh release download 0.1.0 --repo jezdez/conda-sigstore \
  --dir "$release_check/github"
mkdir "$release_check/pypi"
curl --fail --location --silent --show-error \
  https://pypi.org/pypi/conda-sigstore/0.1.0/json \
  --output "$release_check/pypi.json"
wheel_url="$(jq -er \
  '.urls[] | select(.filename == "conda_sigstore-0.1.0-py3-none-any.whl") | .url' \
  "$release_check/pypi.json")"
sdist_url="$(jq -er \
  '.urls[] | select(.filename == "conda_sigstore-0.1.0.tar.gz") | .url' \
  "$release_check/pypi.json")"
if [[ "$wheel_url" != https://files.pythonhosted.org/* ]]; then
  echo "Unexpected PyPI wheel URL." >&2
  exit 1
fi
if [[ "$sdist_url" != https://files.pythonhosted.org/* ]]; then
  echo "Unexpected PyPI source archive URL." >&2
  exit 1
fi
curl --fail --location --silent --show-error "$wheel_url" \
  --output "$release_check/pypi/conda_sigstore-0.1.0-py3-none-any.whl"
curl --fail --location --silent --show-error "$sdist_url" \
  --output "$release_check/pypi/conda_sigstore-0.1.0.tar.gz"
cmp "$release_check/github/conda_sigstore-0.1.0-py3-none-any.whl" \
  "$release_check/pypi/conda_sigstore-0.1.0-py3-none-any.whl"
cmp "$release_check/github/conda_sigstore-0.1.0.tar.gz" \
  "$release_check/pypi/conda_sigstore-0.1.0.tar.gz"
gh attestation verify "$release_check"/github/* \
  --repo jezdez/conda-sigstore
pipx run --spec "pypi-attestations==0.0.30" pypi-attestations verify pypi \
  --repository https://github.com/jezdez/conda-sigstore \
  "$wheel_url"
pipx run --spec "pypi-attestations==0.0.30" pypi-attestations verify pypi \
  --repository https://github.com/jezdez/conda-sigstore \
  "$sdist_url"
```

Install the published wheel in a clean conda 26.7.1 environment and check
plugin discovery:

```console
release_prefix="$(mktemp -d)"
conda create --yes --prefix "$release_prefix" "conda=26.7.1" pip
conda run --prefix "$release_prefix" python -m pip install --no-cache-dir \
  "$release_check/pypi/conda_sigstore-0.1.0-py3-none-any.whl"
conda run --prefix "$release_prefix" python -m conda sigstore --help
```

The normal commands work with released conda. Pre-extraction verification
requires the draft conda branch used by the locked test suite.

If `Publish to PyPI` fails, inspect the live PyPI files before rerunning
anything. Rerun the failed jobs only when neither distribution was published.
If PyPI contains only one distribution, a missing attestation, an unexpected
filename, or different bytes, leave the draft release private and prepare a
new version. If both exact distributions and their attestations reached PyPI,
compare them with the draft assets using the commands above, then publish the
verified draft with `gh release edit 0.1.0 --repo jezdez/conda-sigstore --draft=false`
instead of rerunning the upload.

If `Publish GitHub Release` alone fails after the PyPI job succeeds, rerun only
that job.

Never move a release tag or replace files for a published version. Prepare a
new version and tag when an artifact must change after publication.

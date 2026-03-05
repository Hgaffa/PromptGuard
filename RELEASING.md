# Release Guide

Reference for publishing new versions of **promptguard-ml** to PyPI.

**PyPI:** https://pypi.org/project/promptguard-ml/
**Install:** `pip install promptguard-ml`

---

## Files to update for every release

| File | What to change |
|------|---------------|
| `pyproject.toml` | `version = "X.Y.Z"` |
| `promptguard/__init__.py` | `__version__ = "X.Y.Z"` |
| `CHANGELOG.md` | Add new `## [X.Y.Z] - YYYY-MM-DD` section |

---

## Versioning

Follow [Semantic Versioning](https://semver.org/):

- **PATCH** (`0.1.1` → `0.1.2`) — bug fixes, no API changes
- **MINOR** (`0.1.1` → `0.2.0`) — new backwards-compatible features
- **MAJOR** (`0.1.1` → `1.0.0`) — breaking API changes

---

## Automated release (recommended)

A GitHub Actions workflow (`.github/workflows/release.yml`) handles everything
automatically — tests, lint, type-check, build, PyPI publish, and GitHub Release.

### One-time setup (do this once)

**Step 1 — Create a GitHub environment called `release`:**

> Repo → Settings → Environments → New environment → name it **`release`**

Optionally add a *Required reviewers* protection rule so you must manually
approve each PyPI publish before it goes live.

**Step 2 — Register a Trusted Publisher on PyPI (no API token required):**

> pypi.org → *promptguard-ml* → Manage → Publishing → Add a publisher

| Field | Value |
|-------|-------|
| Publisher | GitHub Actions |
| Owner | your GitHub username |
| Repository | your repo name |
| Workflow name | `release.yml` |
| Environment | `release` |

No secrets to store anywhere — PyPI verifies the workflow identity via OIDC.

### Triggering a release

1. Bump the versions in `pyproject.toml` and `__init__.py` then update the `CHANGELOG.md`.
2. Commit and tag:

```bash
git add pyproject.toml promptguard/__init__.py CHANGELOG.md
git commit -m "chore: release 0.1.2"
git tag -a v0.1.2 -m "Release 0.1.2"
git push origin main
git push origin v0.1.2
```

The workflow starts automatically and:

| Step | What happens |
|------|-------------|
| **test** | Runs pytest, black, flake8, mypy (HuggingFace model is cached between runs) |
| **build** | Verifies tag version matches `pyproject.toml`, builds sdist + wheel, runs `twine check` |
| **publish** | Uploads to PyPI via OIDC — no token needed |
| **github-release** | Creates a GitHub Release with the wheel, sdist, and your CHANGELOG notes |

Monitor progress at: `https://github.com/<you>/<repo>/actions`

---

## Manual release (fallback)

Use this if you need to publish from your local machine.

### 1. Bump the version in two places

```
pyproject.toml          →   version = "0.1.2"
promptguard/__init__.py →   __version__ = "0.1.2"
```

### 2. Update CHANGELOG.md

Add a new section at the top (below the header):

```markdown
## [0.1.2] - YYYY-MM-DD

### Fixed
- ...

### Added
- ...
```

### 3. Run tests and linters

```bash
pip install -e ".[dev]"
pytest
black --check promptguard tests
flake8 promptguard tests
mypy promptguard
```

### 4. Commit and tag

```bash
git add pyproject.toml promptguard/__init__.py CHANGELOG.md
git commit -m "chore: release 0.1.2"
git tag -a v0.1.2 -m "Release 0.1.2"
git push origin main
git push origin v0.1.2
```

### 5. Clean old build artefacts

```bash
# Linux/macOS
rm -rf dist/ build/ promptguard_ml.egg-info/

# Windows (PowerShell)
Remove-Item -Recurse -Force dist, build, promptguard_ml.egg-info
```

### 6. Build

```bash
pip install build
python -m build
```

Produces:
- `dist/promptguard_ml-0.1.2.tar.gz`
- `dist/promptguard_ml-0.1.2-py3-none-any.whl`

### 7. Validate

```bash
pip install twine
twine check dist/*
# Both must print PASSED
```

### 8. Upload to TestPyPI (optional dry run)

```bash
twine upload --repository testpypi dist/*
```

Test install:
```bash
pip install --index-url https://test.pypi.org/simple/ \
            --extra-index-url https://pypi.org/simple/ \
            promptguard-ml
```

### 9. Upload to production PyPI

```bash
twine upload dist/*
```

### 10. Verify

```bash
pip install --upgrade promptguard-ml
python -c "import promptguard; print(promptguard.__version__)"
```

---

## Storing credentials (avoid re-typing tokens)

Create `~/.pypirc`:

```ini
[distutils]
index-servers =
    pypi
    testpypi

[pypi]
repository = https://upload.pypi.org/legacy/
username = __token__
password = pypi-<your-production-token>

[testpypi]
repository = https://test.pypi.org/legacy/
username = __token__
password = pypi-<your-testpypi-token>
```

---

## Fixing a bad release

PyPI does **not** allow re-uploading a file for the same version.

| Situation | Action |
|-----------|--------|
| Broken wheel, same version | Yank the release, then publish a patch version |
| Minor metadata mistake | Publish a patch version |
| Security issue | Yank immediately, release patch ASAP |

To yank: PyPI project page → the release → ⋮ menu → *Yank release*.

---

## Release checklist

Copy this for each release:

```
[ ] Version bumped in pyproject.toml
[ ] Version bumped in promptguard/__init__.py
[ ] CHANGELOG.md updated with new section
[ ] All changes committed
[ ] Tag pushed  →  workflow triggers automatically
[ ] GitHub Actions run passes (Actions tab)
[ ] pip install --upgrade promptguard-ml shows new version
```

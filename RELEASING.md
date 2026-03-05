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

- **PATCH** (`0.1.0` → `0.1.1`) — bug fixes, no API changes
- **MINOR** (`0.1.0` → `0.2.0`) — new backwards-compatible features
- **MAJOR** (`0.1.0` → `1.0.0`) — breaking API changes

---

## Step-by-step release process

### 1. Work on a release branch (optional but recommended)
```bash
git checkout -b release/0.2.0
```

### 2. Bump the version in two places
```bash
# pyproject.toml  →  version = "0.2.0"
# promptguard/__init__.py  →  __version__ = "0.2.0"
```

### 3. Update CHANGELOG.md
Add a new section at the top:
```markdown
## [0.2.0] - YYYY-MM-DD

### Added
- ...

### Fixed
- ...

### Changed
- ...
```

### 4. Run the full test suite
```bash
pip install -e ".[dev]"
pytest
```
All tests must pass and coverage must be ≥ 85%.

### 5. Lint and type-check
```bash
black --check promptguard tests
flake8 promptguard tests
mypy promptguard
```

### 6. Commit and tag
```bash
git add pyproject.toml promptguard/__init__.py CHANGELOG.md
git commit -m "chore: release 0.2.0"
git tag -a v0.2.0 -m "Release 0.2.0"
git push origin release/0.2.0
git push origin v0.2.0
```

### 7. Clean previous build artefacts
```bash
rm -rf dist/ build/ promptguard.egg-info/
# On Windows:
# Remove-Item -Recurse -Force dist, build, promptguard.egg-info
```

### 8. Build
```bash
pip install build
python -m build
```
This produces:
- `dist/promptguard_ml-0.2.0.tar.gz`  (source distribution)
- `dist/promptguard_ml-0.2.0-py3-none-any.whl`  (wheel)

### 9. Validate the distributions
```bash
pip install twine
twine check dist/*
```
Both must print `PASSED`.

### 10. Test publish to TestPyPI (dry run)
```bash
twine upload --repository testpypi dist/*
# Username: __token__
# Password: <TestPyPI API token>
```
Verify at https://test.pypi.org/project/promptguard-ml/

Test install:
```bash
pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ promptguard-ml
```
(The `--extra-index-url` is needed because the heavy deps like torch are not on TestPyPI.)

### 11. Publish to production PyPI
```bash
twine upload dist/*
# Username: __token__
# Password: <PyPI API token>
```

### 12. Verify the release
```bash
pip install --upgrade promptguard-ml
python -c "import promptguard; print(promptguard.__version__)"
```

### 13. Merge back and create GitHub release (optional)
```bash
git checkout main
git merge release/0.2.0
git push origin main
```
Then create a GitHub Release from the `v0.2.0` tag, pasting the CHANGELOG entry as the description.

---

## Credentials

Store API tokens in `~/.pypirc` so you never have to type them:

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

With this in place, `twine upload dist/*` uses the stored token automatically.

---

## Fixing a bad release (post-upload)

PyPI does **not** allow re-uploading a file for the same version. Your options:

| Situation | Action |
|-----------|--------|
| Broken wheel, same version | Yank the release on PyPI (marks it as broken without removing it), then release a patch version |
| Minor mistake in metadata only | Release a patch version (`0.1.1`) |
| Security issue | Yank immediately, release patch ASAP |

To yank a release: PyPI project page → Your Release → ⋮ menu → *Yank release*.

---

## Checklist (copy for each release)

```
[ ] Version bumped in pyproject.toml
[ ] Version bumped in promptguard/__init__.py
[ ] CHANGELOG.md updated
[ ] pytest passes, coverage ≥ 85%
[ ] black / flake8 / mypy clean
[ ] dist/ cleaned, python -m build run
[ ] twine check dist/* → PASSED
[ ] TestPyPI upload + install verified
[ ] Production PyPI upload
[ ] pip install --upgrade verified
[ ] Git tag pushed
[ ] GitHub Release created (optional)
```

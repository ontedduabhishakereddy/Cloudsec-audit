# Contributing to cloudsec-audit

Thank you for your interest in contributing! This document covers how to set up a development environment, run tests, and submit pull requests.

---

## Development Setup

```bash
# 1. Clone the repository
git clone https://github.com/ontedduabhishakereddy/cloudsec-audit.git
cd cloudsec-audit

# 2. Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate        # Linux/macOS
# .venv\Scripts\activate         # Windows

# 3. Install in editable mode with all dev dependencies
pip install -e ".[dev]"
```

---

## Running Tests

Tests use [pytest](https://pytest.org) and [moto](https://github.com/getmoto/moto) for AWS mocking. **No real AWS credentials are required.**

```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run only unit tests
pytest tests/unit/

# Run only integration tests
pytest tests/integration/

# Run a specific test file
pytest tests/unit/test_iam_analyzer.py

# Run a specific test by name
pytest -k "test_detects_admin_policy_on_user"

# Run with coverage report
pytest --cov=cloudsec_audit --cov-report=html
open htmlcov/index.html
```

---

## Code Quality

```bash
# Format code
black cloudsec_audit tests

# Lint
ruff check cloudsec_audit tests

# Type check
mypy cloudsec_audit

# Run all checks at once
black cloudsec_audit tests && ruff check cloudsec_audit tests && mypy cloudsec_audit
```

---

## Adding a New Check

1. **Identify the analyzer** — IAM, Network, or Storage. If it's a new category, create a new file in `cloudsec_audit/analyzers/`.

2. **Add the check method** — prefix with `_check_` so it's clearly internal:

```python
def _check_my_new_thing(self) -> None:
    # ... query AWS ...
    self._add_finding(Finding(
        title="Descriptive title",
        description="What's wrong and why it matters",
        severity=Severity.HIGH,
        category=self.category,
        subcategory="Relevant subcategory",
        cloud_provider=CloudProvider.AWS,
        resource_id=resource_arn,
        resource_type="AWS::Service::Resource",
        region=region,
        mitre_tactics=["Privilege Escalation"],
        mitre_techniques=["T1078"],
        compliance_controls={"CIS": ["x.y"], "SOC2": ["CCx.y"]},
        attack_path=AttackPath(
            steps=["Step 1", "Step 2", "Step 3"],
            blast_radius="Description of impact",
        ),
        remediation_steps=[
            RemediationStep(
                order=1,
                description="How to fix it",
                code_snippet="aws ... command",
            ),
        ],
    ))
```

3. **Call the check from `run()`** — add it to the `checks` list or call directly.

4. **Map to compliance controls** — add relevant CIS, SOC2, HIPAA, PCI-DSS control IDs in `compliance_controls`. Add any new control definitions to `cloudsec_audit/reporters/compliance.py` under `FRAMEWORK_CONTROLS`.

5. **Write tests** — add moto-based tests to the appropriate `tests/unit/test_*.py` file. Cover both the "detected" and "clean" cases.

---

## Adding a New Compliance Framework

1. Add the framework's controls to `FRAMEWORK_CONTROLS` in `cloudsec_audit/reporters/compliance.py`:

```python
"NIST": {
    "AC-2": "Account Management",
    "AC-6": "Least Privilege",
    # ...
}
```

2. Add the framework name to `ComplianceReporter.SUPPORTED_FRAMEWORKS`.

3. Map existing findings to the new framework controls by adding entries to `compliance_controls` in relevant `Finding` objects.

---

## Pull Request Guidelines

- **One PR per feature or fix** — keep changes focused
- **Tests required** — all new checks must have at least one moto-based test
- **No breaking changes to `Finding` fields** — these are part of the public API
- **Update `CHANGELOG.md`** under `[Unreleased]`
- **Docstrings** for all public classes and methods

---

## Project Structure

```
cloudsec_audit/
├── analyzers/       # One file per analyzer category
├── models/          # Finding, AWSSession data models
├── reporters/       # AuditReport, ComplianceReporter
└── utils/           # Shared helpers
```

Questions? Open a GitHub issue.
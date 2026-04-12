# Contributing to Crypt

Thank you for your interest in contributing to this educational cryptography library!
This document provides guidelines and workflows for contributors.

## Getting Started

1. Fork the repository
2. Clone your fork locally
3. Install dependencies with `uv sync --group dev --group test`
4. Run tests to ensure everything passes: `uv run pytest`

## Development Workflow

### Code Style

This project uses [ruff](https://docs.astral.sh/ruff/) for linting and formatting:

```bash
# Check linting
uv run ruff check .

# Auto-fix issues
uv run ruff check --fix .

# Format code
uv run ruff format .

# Run all formatting and linting
uv run poe full
```

### Type Hints

Please add type hints to new code, especially:

- Public API functions
- Internal state classes
- Block cipher implementations

### Testing Requirements

Before submitting a PR, ensure:

1. **All tests pass**: `uv run pytest`
2. **Coverage remains ≥90%**: Coverage is enforced in CI
3. **Tests validate against reference libraries**: Use `hashlib`, `pycryptodome`, or
   `cryptography` where applicable
4. **Edge cases are covered**: Empty inputs, boundary lengths, invalid inputs

Run specific test patterns:

```bash
# All tests
uv run pytest

# Specific module
uv run pytest tests/digest/test_sha.py

# No parallelization (for debugging)
uv run pytest -n0

# Fast tests only (skip slow algorithms)
uv run pytest -k "not slow"
```

### Adding a New Algorithm

When implementing a new cryptographic algorithm:

1. **Research first**: Reference the original RFC, NIST specification, or academic paper
2. **Follow existing patterns**: Match the file structure and API conventions of similar
   algorithms
3. **Add comprehensive tests**: Include known test vectors from authoritative sources
4. **Document complexity**: Add time/space complexity notes in docstrings
5. **Security status**: Clearly mark broken/deprecated algorithms with appropriate
   docstrings and warnings

#### File Organization

- **Algorithms**: `snake_case.py` (e.g., `sha2_256.py`, `chacha20.py`)
- **Variants**: Underscore separation (e.g., `sha2_512_224.py`)
- **Test files**: `test_<algorithm>.py`
- **Internal utilities**: Leading underscore for private modules
- **Keep files focused**: Prefer 200-400 lines; absolute maximum 800 lines. Extract
  large constant tables to separate files.

#### Docstring Template

```python
"""<Algorithm Name> implementation.

<One-sentence description>.

Security Status: <Secure | Deprecated | Broken | Legacy>
Complexity: O(<complexity>) time, O(<complexity>) space

Reference:
    - <RFC or paper citation>

Example:
    >>> result = algorithm_name(b"Hello, World!")
    >>> result.hex()
    '<expected_hex>'
"""
```

### Commit Message Format

We use conventional commits:

```
<type>: <description>

<optional body>
```

Types:

- `feat`: New algorithm or feature
- `fix`: Bug fix
- `refactor`: Code restructuring without behavior changes
- `docs`: Documentation updates
- `test`: Test additions or fixes
- `chore`: Maintenance tasks
- `perf`: Performance improvements
- `ci`: CI/CD changes

### Pull Request Process

1. Create a feature branch: `git checkout -b feat/<algorithm-name>`
2. Make focused, atomic commits
3. Push to your fork
4. Open a PR with:
    - Clear description of what changed and why
    - Test plan checklist
    - References to any specifications or papers
5. Ensure CI passes (lint + tests)

## Review Criteria

PRs are reviewed for:

- **Correctness**: Tests validate against reference implementations
- **Clarity**: Code is readable and well-commented for educational value
- **Consistency**: Follows existing patterns and conventions
- **Coverage**: New code has adequate test coverage
- **Security**: No hardcoded secrets, proper input validation, safe defaults

## Questions?

Open an issue for discussion before major changes. We're happy to help!

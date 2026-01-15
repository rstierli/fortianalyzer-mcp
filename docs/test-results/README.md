# Test Results Documentation

This directory contains test results from unit tests and integration tests against real FortiAnalyzer instances.

## Purpose

- Track which FAZ versions have been tested
- Document known issues per version
- Provide compatibility matrix for users
- Record integration test coverage

## Structure

```
test-results/
├── README.md                 # This file
├── compatibility.md          # Version compatibility matrix
├── faz-7.6.5.md             # Test results for FAZ 7.6.5
├── faz-7.6.4.md             # Test results for FAZ 7.6.4
├── faz-7.4.x.md             # Test results for FAZ 7.4.x
└── faz-7.2.x.md             # Test results for FAZ 7.2.x
```

## Test Categories

### Unit Tests
- Run without real FAZ connection
- Test code logic, parsing, error handling
- Command: `pytest tests/ -m "not integration"`

### Integration Tests
- Require real FAZ connection
- Test actual API calls and responses
- Command: `pytest tests/integration/ -m integration`

## How to Run Tests

```bash
# All unit tests
uv run pytest tests/ -v --tb=short

# Integration tests (requires .env with FAZ credentials)
uv run pytest tests/integration/ -v -m integration

# Generate coverage report
uv run pytest tests/ --cov=src/fortianalyzer_mcp --cov-report=html
```

## Contributing Test Results

When testing against a new FAZ version:

1. Create a new file: `faz-X.Y.Z.md`
2. Use the template below
3. Run full test suite
4. Document any failures or issues
5. Submit PR with results

## Template for Version Results

```markdown
# FortiAnalyzer X.Y.Z Test Results

**Test Date:** YYYY-MM-DD
**Tester:** Name
**MCP Version:** X.Y.Z

## Environment
- FAZ Version: X.Y.Z
- FAZ Build: XXXX
- Test ADOM: root
- Python Version: 3.12.x

## Unit Test Results
- Total: XX tests
- Passed: XX
- Failed: XX
- Skipped: XX

## Integration Test Results

| Category | Tests | Passed | Failed | Notes |
|----------|-------|--------|--------|-------|
| System | X | X | X | |
| Log Search | X | X | X | |
| FortiView | X | X | X | |
| Reports | X | X | X | |
| Alerts | X | X | X | |
| Incidents | X | X | X | |

## Known Issues
- Issue 1: Description
- Issue 2: Description

## Notes
Additional observations or recommendations.
```

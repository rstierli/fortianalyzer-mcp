# Contributing

Thank you for your interest in contributing to fortianalyzer-mcp!

## How to Contribute

### Reporting Bugs

- Open a GitHub issue with a clear description
- Include steps to reproduce, expected vs actual behavior
- Mention your FortiAnalyzer version and Python version

### Suggesting Features

- Open a GitHub issue with the `enhancement` label
- Describe the use case and proposed solution

### Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Make your changes
4. Run tests: `pytest tests/`
5. Run linting: `ruff check src/`
6. Commit with a clear message
7. Push and open a Pull Request

### Code Style

- Python 3.12+
- Type hints required (mypy strict mode)
- Linting with ruff
- Tests for new functionality

### Testing

Unit tests run without a real FortiAnalyzer:
```bash
pytest tests/ -v
```

Integration tests require a real FortiAnalyzer instance and configured `.env.test`:
```bash
python tests/run_tests.py --env your-env
```

## Code of Conduct

Be respectful and constructive. We follow the [Contributor Covenant](https://www.contributor-covenant.org/).

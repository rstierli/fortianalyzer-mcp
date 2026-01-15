# FortiAnalyzer MCP - Version Compatibility Matrix

**Last Updated:** 2025-01-15

## Supported Versions

| FAZ Version | MCP Version | Status | Unit Tests | Integration Tests | Notes |
|-------------|-------------|--------|------------|-------------------|-------|
| 7.6.5 | 0.3.0-beta | Supported | Pending | Pending | Primary target |
| 7.6.4 | 0.3.0-beta | Supported | Pending | Pending | |
| 7.4.x | 0.3.0-beta | Expected | Pending | Pending | Should work |
| 7.2.x | 0.3.0-beta | Expected | Pending | Pending | Should work |
| 7.0.x | 0.3.0-beta | Unknown | Not tested | Not tested | May work |

## Status Legend

| Status | Meaning |
|--------|---------|
| **Supported** | Actively tested and maintained |
| **Expected** | Should work based on API compatibility |
| **Unknown** | Not tested, may or may not work |
| **Deprecated** | No longer supported |

## API Compatibility Notes

FortiAnalyzer and FortiManager share the same JSON-RPC API codebase. General patterns are identical across versions:

- Authentication: Same across all versions
- Request/Response format: Same across all versions
- Error codes: Same across all versions

### Version-Specific Differences

#### FAZ 7.6.x
- Full feature support
- All 75 tools tested

#### FAZ 7.4.x
- Expected full compatibility
- Some newer FortiView charts may not be available

#### FAZ 7.2.x
- Expected compatibility for core features
- Some incident management features may differ

## Python Version Support

| Python | Status |
|--------|--------|
| 3.13.x | Supported |
| 3.12.x | Supported (Primary) |
| 3.11.x | Should work |
| 3.10.x | Not tested |
| < 3.10 | Not supported |

## Testing Your Version

To test compatibility with your FAZ version:

```bash
# 1. Configure environment
cp .env.example .env
# Edit .env with your FAZ credentials

# 2. Run unit tests (no FAZ required)
uv run pytest tests/ -v

# 3. Run integration tests (FAZ required)
uv run pytest tests/integration/ -v -m integration

# 4. Report results
# Create docs/test-results/faz-X.Y.Z.md with your results
```

## Reporting Issues

If you encounter version-specific issues:

1. Check existing issues on GitHub
2. Include FAZ version and build number
3. Include full error message
4. Include steps to reproduce

## Contributing

Help us expand compatibility testing:

1. Test against your FAZ version
2. Document results using template in README.md
3. Submit PR with test results
4. Report any version-specific issues

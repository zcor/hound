# Contributing to Hound

Thank you for your interest in contributing to Hound! This document provides guidelines and instructions for contributing to the project.

## Quick Links

- [Developer Guide](docs/DEVELOPER_GUIDE.md) - Complete development setup and guidelines
- [Architecture](docs/ARCHITECTURE.md) - System architecture and design decisions
- [Module Documentation](docs/MODULES.md) - Code-level module reference
- [API Reference](docs/API_REFERENCE.md) - API documentation

## Getting Started

### 1. Fork and Clone

```bash
git clone https://github.com/YOUR_USERNAME/hound.git
cd hound
git remote add upstream https://github.com/firepan-labs/hound.git
```

### 2. Set Up Development Environment

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install development dependencies
pip install pytest pytest-asyncio pytest-cov black mypy ruff

# Configure environment
cp .env.example .env
# Edit .env with your API keys
```

### 3. Run Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=. --cov-report=html

# Run specific tests
pytest tests/test_agent_core.py
```

See [Developer Guide - Testing](docs/DEVELOPER_GUIDE.md#testing) for more details.

## How to Contribute

### Reporting Bugs

1. **Search existing issues** to avoid duplicates
2. **Create a new issue** with:
   - Clear, descriptive title
   - Steps to reproduce
   - Expected vs. actual behavior
   - Environment details (OS, Python version, etc.)
   - Relevant logs or error messages

### Suggesting Features

1. **Check existing issues** for similar requests
2. **Create a feature request** with:
   - Clear description of the feature
   - Use case and motivation
   - Proposed implementation (optional)
   - Examples of similar features (optional)

### Contributing Code

#### Before You Start

1. **Check for existing issues** or create one to discuss your changes
2. **Get feedback** on your approach before implementing large changes
3. **Review the codebase** to understand the architecture and style

#### Development Process

1. **Create a feature branch:**
   ```bash
   git checkout -b feature/my-feature
   ```

2. **Make your changes:**
   - Write clean, readable code
   - Follow the [Code Style Guide](#code-style)
   - Add tests for new functionality
   - Update documentation as needed

3. **Test your changes:**
   ```bash
   # Format code
   black . --line-length 100
   
   # Lint
   ruff check .
   
   # Type check
   mypy llm/ analysis/
   
   # Run tests
   pytest
   ```

4. **Commit your changes:**
   ```bash
   git add .
   git commit -m "feat: add new feature"
   ```

   **Commit message format:**
   - `feat:` - New feature
   - `fix:` - Bug fix
   - `docs:` - Documentation changes
   - `test:` - Test additions or changes
   - `refactor:` - Code refactoring
   - `perf:` - Performance improvements
   - `chore:` - Maintenance tasks

5. **Push to your fork:**
   ```bash
   git push origin feature/my-feature
   ```

6. **Create a Pull Request:**
   - Provide a clear description of your changes
   - Reference any related issues
   - Include screenshots for UI changes
   - Ensure all CI checks pass

## Code Style

### Python

**Formatter:** Black (line length: 100)
```bash
black . --line-length 100
```

**Linter:** Ruff
```bash
ruff check .
ruff check --fix .
```

**Type Checking:** MyPy
```bash
mypy llm/ analysis/ commands/
```

### Code Conventions

**Naming:**
- Functions: `snake_case`
- Classes: `PascalCase`
- Constants: `UPPER_SNAKE_CASE`
- Private: `_leading_underscore`

**Imports:**
```python
# Standard library
import os
from pathlib import Path

# Third-party
import typer
from rich.console import Console

# Local
from llm.unified_client import LLMClient
from analysis.agent_core import AgentCore
```

**Docstrings:**
```python
def build_graph(project_name: str, iterations: int = 3) -> dict:
    """Build knowledge graph for a project.
    
    Args:
        project_name: Name of the project
        iterations: Number of refinement iterations
        
    Returns:
        Graph data with nodes and edges
        
    Raises:
        ProjectNotFoundError: If project doesn't exist
    """
    pass
```

See [Developer Guide - Code Style](docs/DEVELOPER_GUIDE.md#code-style) for more details.

## Testing Guidelines

### Writing Tests

**Unit tests:**
```python
def test_hypothesis_deduplication():
    """Test that duplicate hypotheses are merged."""
    h1 = {"title": "Bug A", "confidence": 0.8}
    h2 = {"title": "Bug A", "confidence": 0.9}
    result = deduplicate_hypotheses([h1, h2])
    assert len(result) == 1
    assert result[0]["confidence"] == 0.9
```

**Integration tests:**
```python
def test_api_create_project(client):
    """Test project creation via API."""
    response = client.post("/projects", json={
        "name": "test",
        "source_path": "/tmp/test"
    })
    assert response.status_code == 201
    assert response.json()["name"] == "test"
```

### Test Coverage

- Aim for >80% coverage for new code
- All new features must include tests
- Bug fixes should include regression tests

### Running Tests

```bash
# All tests
pytest

# Specific module
pytest tests/test_llm/

# With coverage report
pytest --cov=. --cov-report=html
open htmlcov/index.html
```

## Documentation

### What to Document

**Always document:**
- Public APIs and interfaces
- New features
- Configuration options
- Breaking changes

**Update documentation when you:**
- Add new modules or components
- Change public APIs
- Modify configuration
- Add new dependencies

### Documentation Style

- Use clear, concise language
- Include code examples
- Add diagrams for complex concepts
- Keep examples up-to-date

### Where to Add Documentation

- **API changes:** [docs/API_REFERENCE.md](docs/API_REFERENCE.md)
- **Architecture changes:** [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- **Module docs:** [docs/MODULES.md](docs/MODULES.md)
- **User guides:** [docs/QUICK_START.md](docs/QUICK_START.md)
- **Code comments:** Inline for complex logic

## Pull Request Process

### Before Submitting

- [ ] Code is formatted (`black`)
- [ ] No linting errors (`ruff`)
- [ ] Type hints are correct (`mypy`)
- [ ] Tests pass (`pytest`)
- [ ] Documentation is updated
- [ ] Commit messages follow convention
- [ ] Branch is up-to-date with `main`

### PR Description Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] Manual testing completed

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] No new warnings
- [ ] Tests pass locally

## Screenshots (if applicable)
[Add screenshots for UI changes]

## Related Issues
Closes #[issue number]
```

### Review Process

1. **Automated checks** run on your PR
2. **Maintainer review** - may request changes
3. **Address feedback** and push updates
4. **Approval** from maintainer(s)
5. **Merge** to main branch

## Development Workflow

### Branch Strategy

- `main` - Stable release branch
- `feature/*` - New features
- `fix/*` - Bug fixes
- `docs/*` - Documentation changes

### Release Process

1. Version bump in `pyproject.toml`
2. Update CHANGELOG.md
3. Create release tag
4. Publish to PyPI (maintainers only)

## Areas for Contribution

### Good First Issues

Look for issues labeled `good-first-issue`:
- Documentation improvements
- Test coverage
- Code cleanup
- Minor bug fixes

### High-Priority Areas

- **LLM Providers:** Add support for new providers
- **Graph Builders:** Specialized graph types for specific languages/frameworks
- **Analyzers:** Domain-specific security checks
- **Integrations:** GitHub Apps, CI/CD tools, etc.
- **Performance:** Optimization and caching
- **Testing:** Increase test coverage

### Feature Ideas

- ML-based vulnerability prioritization
- Multi-language support improvements
- Enhanced visualization
- Plugin system
- Distributed workers
- Advanced reporting

## Community

### Code of Conduct

- Be respectful and inclusive
- Provide constructive feedback
- Help others learn and grow
- Follow project guidelines

### Getting Help

- **Questions:** GitHub Discussions
- **Bugs:** GitHub Issues
- **Chat:** Discord (link in README)
- **Email:** maintainers (for sensitive issues)

## Recognition

Contributors are recognized in:
- README.md contributors section
- Release notes
- Git commit history

Significant contributions may earn:
- Commit access
- Maintainer status
- Project direction input

## Resources

### Documentation
- [Quick Start Guide](docs/QUICK_START.md)
- [Developer Guide](docs/DEVELOPER_GUIDE.md)
- [Architecture](docs/ARCHITECTURE.md)
- [API Reference](docs/API_REFERENCE.md)
- [Module Docs](docs/MODULES.md)

### Tools
- [Black](https://black.readthedocs.io/) - Code formatter
- [Ruff](https://beta.ruff.rs/) - Linter
- [MyPy](https://mypy.readthedocs.io/) - Type checker
- [Pytest](https://docs.pytest.org/) - Testing framework

### External Resources
- [LLM Provider Docs](docs/MODULES.md#llm-module)
- [FastAPI Docs](https://fastapi.tiangolo.com/)
- [Celery Docs](https://docs.celeryq.dev/)
- [SQLAlchemy Docs](https://docs.sqlalchemy.org/)

## License

By contributing to Hound, you agree that your contributions will be licensed under the Apache 2.0 License. See [LICENSE.txt](LICENSE.txt) for details.

## Questions?

If you have questions about contributing:
1. Check the [Developer Guide](docs/DEVELOPER_GUIDE.md)
2. Search existing [GitHub Issues](https://github.com/firepan-labs/hound/issues)
3. Ask in [GitHub Discussions](https://github.com/firepan-labs/hound/discussions)
4. Reach out to maintainers

Thank you for contributing to Hound! 🚀

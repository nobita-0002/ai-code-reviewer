# AI Code Reviewer

An intelligent code review assistant that analyzes code quality, detects potential bugs, and suggests improvements using machine learning techniques.

## Features

- **Static Code Analysis**: Analyze Python code for potential issues and code smells
- **Quality Metrics**: Calculate code complexity, maintainability, and other metrics
- **Security Checks**: Identify potential security vulnerabilities
- **Style Enforcement**: Check for PEP 8 compliance and coding standards
- **Detailed Reports**: Generate comprehensive markdown and JSON reports
- **Customizable Rules**: Extend and customize analysis rules

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/nobita-0002/ai-code-reviewer.git
   cd ai-code-reviewer
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Basic Usage

Analyze a single Python file:
```bash
python main.py path/to/your/code.py
```

### Command Line Options

```bash
python main.py --help
```

Options:
- `-o, --output`: Specify output report file (default: report.md)
- `-v, --verbose`: Enable verbose logging
- `--json`: Output report in JSON format

### Example

```bash
python main.py example.py --output analysis_report.md --verbose
```

## Project Structure

```
ai-code-reviewer/
├── main.py              # Main entry point
├── code_analyzer.py     # Core analysis logic
├── report_generator.py  # Report generation
├── requirements.txt     # Dependencies
├── README.md           # This file
├── .gitignore          # Git ignore rules
└── utils/
    └── logger.py       # Logging configuration
```

## Analysis Capabilities

### Code Quality Checks
- Function length and complexity
- Naming conventions (PEP 8)
- Code duplication detection
- Comment ratio analysis

### Bug Detection
- Potential runtime errors
- Logical errors
- Resource leaks
- Exception handling issues

### Security Analysis
- Input validation issues
- Code injection vulnerabilities
- Insecure dependencies
- Hardcoded secrets detection

### Style Enforcement
- Line length (79 characters)
- Import organization
- Whitespace usage
- Documentation standards

## Extending the Analyzer

You can extend the analyzer by adding new checkers to the `CodeAnalyzer` class:

```python
class CustomAnalyzer(CodeAnalyzer):
    def _check_custom_rules(self, tree: ast.AST) -> None:
        # Add your custom analysis logic here
        pass
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Inspired by various static analysis tools like Pylint, Flake8, and Bandit
- Built with Python's AST module for reliable code parsing
- Thanks to the open-source community for inspiration and tools

## Support

For issues, questions, or suggestions, please open an issue on GitHub.

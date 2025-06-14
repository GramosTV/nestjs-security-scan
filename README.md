# nestjs-security-scan

[![npm version](https://img.shields.io/npm/v/nestjs-security-scan.svg)](https://www.npmjs.com/package/nestjs-security-scan)
[![npm downloads](https://img.shields.io/npm/dm/nestjs-security-scan.svg)](https://www.npmjs.com/package/nestjs-security-scan)
[![npm license](https://img.shields.io/npm/l/nestjs-security-scan.svg)](https://www.npmjs.com/package/nestjs-security-scan)
[![Donate](https://img.shields.io/badge/Donate-PayPal-red.svg)](https://paypal.me/gramostv)

A powerful security vulnerability scanner for NestJS applications.

## Features

- **🔍 Legacy Scan**: Traditional rule-based security analysis
- **🤖 AI Scan**: Intelligent analysis powered by Google Gemini AI
- **Dependency Scanning**: Detect known vulnerabilities in your dependencies using npm audit and Snyk
- **Code Analysis**: Find common security issues in your NestJS code
- **Configuration Validation**: Identify insecure configuration settings
- **Detailed Reports**: Get comprehensive security reports in various formats
- **CLI Interface**: Easy to use command line interface

## Installation

You can install the package globally:

```bash
npm install -g nestjs-security-scan
```

Or locally in your project:

```bash
npm install --save-dev nestjs-security-scan
```

## Usage

### Basic Usage

Run the security scanner in your NestJS project:

```bash
npx nestjs-security-scan
```

The tool will prompt you to choose between:

- **Legacy Scan**: Traditional rule-based analysis
- **AI Scan**: Intelligent analysis using Google Gemini

### AI-Powered Security Scan

For advanced security analysis with AI:

1. Get a Google AI API key from [Google AI Studio](https://aistudio.google.com/apikey)
2. Run the scanner and choose "AI Scan"
3. The tool will automatically fetch available Gemini models
4. Select your preferred model from the dynamically populated list
5. Enter your API key when prompted

```bash
# Interactive AI scan with dynamic model selection
npx nestjs-security-scan

# Non-interactive AI scan with specific model
npx nestjs-security-scan --ai-model gemini-1.5-pro --ai-key YOUR_API_KEY
```

**AI Scan Features:**

- **Dynamic Model Selection**: Automatically fetches the latest available Gemini models
- **Advanced Pattern Recognition**: Identifies complex security vulnerabilities using AI
- **Contextual Analysis**: Understands business logic flaws and architectural issues
- **NestJS Expertise**: Specialized knowledge of NestJS security best practices
- **Intelligent Recommendations**: Provides specific, actionable security advice
- **Comprehensive Coverage**: Analyzes code, configurations, and architectural patterns
- **Smart Filtering**: Focuses on real security issues, reduces false positives
- **Architectural Review**: Evaluates overall application security design

### Options

```bash
Usage: npx nestjs-security-scan [options]

Options:
  -V, --version                    output the version number
  -p, --path <path>               Path to NestJS application (default: current directory)
  -v, --verbose                   Show detailed output
  --no-deps                       Skip dependency vulnerabilities check
  --no-code                       Skip code security analysis
  --no-config                     Skip configuration analysis
  --no-interactive                Skip interactive prompts (use legacy scan)
  --ai-model <model>              AI model for AI scan (gemini-1.5-pro, gemini-1.5-flash, gemini-pro)
  --ai-key <key>                  Google AI API key for AI scan
  -o, --output <format>           Output format (text, json) (default: "text")
  -h, --help                      display help for command
```

### Examples

#### Scanning a specific NestJS project

```bash
npx nestjs-security-scan -p /path/to/nestjs-project
```

#### Generating a JSON report

```bash
npx nestjs-security-scan -o json > security-report.json
```

#### Skip dependency scanning

```bash
npx nestjs-security-scan --no-deps
```

#### AI Scan Examples

```bash
# Interactive AI scan with prompts
npx nestjs-security-scan

# Non-interactive AI scan with Gemini 1.5 Pro
npx nestjs-security-scan --no-interactive --ai-model gemini-1.5-pro --ai-key YOUR_API_KEY

# AI scan with JSON output
npx nestjs-security-scan --ai-model gemini-1.5-flash --ai-key YOUR_API_KEY -o json

# Legacy scan (skip AI prompts)
npx nestjs-security-scan --no-interactive
```

## Security Checks

### Dependency Checks

- Known security vulnerabilities in dependencies
- Transitive dependencies with security issues

### Code Checks

- **Input Validation**

  - Unvalidated request bodies, query parameters, and route parameters
  - Missing DTO validation with class-validator

- **Authentication & Authorization**

  - Missing guards on sensitive endpoints
  - Insecure Direct Object References (IDOR)
  - Endpoints without proper authorization checks
  - Missing rate limiting on authentication endpoints

- **Database Security**

  - Automatic database schema synchronization in production
  - Disabled entity validation

- **API Security**

  - Missing or permissive CORS policies
  - Hardcoded JWT secrets
  - JWT tokens without expiration
  - Missing security headers

- **Cryptography Issues**

  - Weak encryption algorithms (e.g., DES)
  - Broken hash functions (MD5, SHA-1)
  - Insecure cryptographic practices

- **Code Execution**

  - Unsafe eval() usage
  - Direct filesystem access without proper validation

- **Configuration Weaknesses**
  - Insecure cookie configurations
  - Default security middleware settings

### Configuration Checks

- Environment variables in version control
- Insecure cookie settings
- Hardcoded secrets in configuration files
- Missing security headers
- Missing CSRF protection

## Exit Codes

- **0**: No security issues found
- **1**: One or more high severity vulnerabilities found

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT

# nestjs-security-scan

[![npm version](https://img.shields.io/npm/v/nestjs-security-scan.svg)](https://www.npmjs.com/package/nestjs-security-scan)
[![npm downloads](https://img.shields.io/npm/dm/nestjs-security-scan.svg)](https://www.npmjs.com/package/nestjs-security-scan)
[![npm license](https://img.shields.io/npm/l/nestjs-security-scan.svg)](https://www.npmjs.com/package/nestjs-security-scan)
[![Donate](https://img.shields.io/badge/Donate-PayPal-red.svg)](https://paypal.me/gramostv)

A powerful security vulnerability scanner for NestJS applications.

## Features

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

### Options

```bash
Usage: npx nestjs-security-scan [options]

Options:
  -V, --version       output the version number
  -p, --path <path>   Path to NestJS application (default: current directory)
  -v, --verbose       Show detailed output
  --no-deps           Skip dependency vulnerabilities check
  --no-code           Skip code security analysis
  --no-config         Skip configuration analysis
  -o, --output <format>  Output format (text, json) (default: "text")
  -h, --help          display help for command
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

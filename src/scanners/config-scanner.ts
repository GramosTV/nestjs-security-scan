import * as fs from 'fs-extra';
import * as path from 'path';
import { SecurityVulnerability, Scanner } from '../types';
import * as globModule from 'glob';
import chalk from 'chalk';

// Use synchronous glob
const globSync = globModule.sync;

export class ConfigScanner implements Scanner {
  private projectPath: string;
  private scannedFiles: string[] = [];
  private verbose: boolean;

  constructor(projectPath: string, verbose: boolean = false) {
    // Resolve the path to an absolute path to ensure consistency
    this.projectPath = path.resolve(projectPath);
    this.verbose = verbose;
    this.log(`ConfigScanner initialized with resolved path: ${this.projectPath}`);
  }

  private log(message: string): void {
    if (this.verbose) {
      console.log(message);
    }
  }

  async scan(): Promise<{ vulnerabilities: SecurityVulnerability[]; scannedFiles: string[] }> {
    const vulnerabilities: SecurityVulnerability[] = [];

    try {
      this.log('Starting config scanner...');

      // Check for environment variables handling
      const dotEnvVulns = await this.checkDotEnvFiles();
      vulnerabilities.push(...dotEnvVulns);

      // Check main configuration files
      const configVulns = await this.checkConfigFiles();
      vulnerabilities.push(...configVulns);

      // Check security settings in package.json
      const packageJsonVulns = await this.checkPackageJson();
      vulnerabilities.push(...packageJsonVulns);

      this.log(
        `Config scanner completed. Scanned ${this.scannedFiles.length} files, found ${vulnerabilities.length} vulnerabilities`,
      );

      // Always display the number of vulnerabilities found
      if (vulnerabilities.length > 0) {
        console.log(`Found ${vulnerabilities.length} configuration vulnerabilities`);
      }
    } catch (error) {
      if (this.verbose) {
        console.error('Error scanning configurations:', error);
      }
    }

    return { vulnerabilities, scannedFiles: this.scannedFiles };
  }

  private async checkDotEnvFiles(): Promise<SecurityVulnerability[]> {
    const vulnerabilities: SecurityVulnerability[] = [];

    // Find .env files
    const envFiles = [
      path.join(this.projectPath, '.env'),
      path.join(this.projectPath, '.env.development'),
      path.join(this.projectPath, '.env.production'),
      path.join(this.projectPath, '.env.local'),
    ].filter(file => fs.existsSync(file));

    this.log(`Found ${envFiles.length} .env files to scan`);

    // Check each env file
    for (const envFile of envFiles) {
      try {
        const content = await fs.readFile(envFile, 'utf8');
        const relativeFilePath = path.relative(this.projectPath, envFile);
        this.scannedFiles.push(relativeFilePath);
        this.log(`Scanning .env file: ${relativeFilePath}`);

        // Check for sensitive data in env files
        const sensitivePatterns = [
          { key: 'PASSWORD', label: 'Password' },
          { key: 'SECRET', label: 'Secret' },
          { key: 'KEY', label: 'API Key' },
          { key: 'TOKEN', label: 'Token' },
          { key: 'CREDENTIAL', label: 'Credential' },
        ];

        for (const pattern of sensitivePatterns) {
          const regex = new RegExp(`${pattern.key}[^=]*=[^\\s].*`, 'gi');
          let match;
          while ((match = regex.exec(content)) !== null) {
            // Get line number
            const lineNumber = this.getLineNumber(content, match.index);

            // Don't add vulnerabilities for environment variable definitions that use other variables
            if (!match[0].includes('${') && !match[0].includes('$(')) {
              // Format and colorize the vulnerability finding
              console.log(
                `${chalk.cyan('➤')} Found vulnerability in ${chalk.yellow(relativeFilePath)}:${chalk.yellow(
                  lineNumber.toString(),
                )}: ` +
                  `${chalk.yellow.bold('[MEDIUM]')} Sensitive ${pattern.label} in Environment File`,
              );

              vulnerabilities.push({
                id: `config-env-${pattern.key.toLowerCase()}`,
                title: `Sensitive ${pattern.label} in Environment File`,
                description: `Sensitive ${pattern.label.toLowerCase()} found directly in environment file`,
                severity: 'medium',
                location: relativeFilePath,
                line: lineNumber,
                code: this.maskSensitiveData(match[0]),
                recommendation:
                  'Store sensitive values in a secure vault or as environment variables on the server, not in checked-in .env files',
                category: 'configuration',
              });
            }
          }
        }

        // Check if .env file is in .gitignore
        const isInGitignore = await this.isFileInGitignore(relativeFilePath);
        if (!isInGitignore) {
          // Format and colorize the vulnerability finding
          console.log(
            `${chalk.cyan('➤')} Found vulnerability in ${chalk.yellow(relativeFilePath)}: ` +
              `${chalk.yellow.bold('[MEDIUM]')} Environment File Not in .gitignore`,
          );

          vulnerabilities.push({
            id: 'config-env-gitignore',
            title: 'Environment File Not in .gitignore',
            description: `The environment file ${relativeFilePath} is not excluded from version control in .gitignore`,
            severity: 'medium',
            location: '.gitignore',
            recommendation:
              'Add .env files to .gitignore to prevent committing sensitive data to version control',
            category: 'configuration',
          });
        }
      } catch (error) {
        if (this.verbose) {
          console.error(`Error checking env file ${envFile}:`, error);
        }
      }
    }

    // Check .gitignore
    const gitignorePath = path.join(this.projectPath, '.gitignore');
    if (fs.existsSync(gitignorePath)) {
      const relativeGitignorePath = path.relative(this.projectPath, gitignorePath);
      this.scannedFiles.push(relativeGitignorePath);
      this.log(`Added .gitignore to scanned files: ${relativeGitignorePath}`);
    } else {
      this.log('No .gitignore file found');
    }

    return vulnerabilities;
  }

  private async checkConfigFiles(): Promise<SecurityVulnerability[]> {
    const vulnerabilities: SecurityVulnerability[] = [];

    try {
      // First, try to find files in common config directories
      this.log('Looking for config files in standard locations');
      const configPatterns = [
        path.join(this.projectPath, 'src/config/**/*.{ts,js}'),
        path.join(this.projectPath, 'src/configs/**/*.{ts,js}'),
        path.join(this.projectPath, 'config/**/*.{ts,js}'),
        path.join(this.projectPath, 'src/**/config.{ts,js}'),
      ];

      const configFiles = [];
      for (const pattern of configPatterns) {
        this.log(`Searching with pattern: ${pattern}`);
        try {
          const matches = globSync(pattern, {
            ignore: ['**/node_modules/**', '**/dist/**'],
          });
          configFiles.push(...matches);
        } catch (error) {
          if (this.verbose) {
            console.error('Error with glob sync', error);
          }
        }
      }

      this.log(`Found ${configFiles.length} config files to scan`);

      for (const filePath of configFiles) {
        try {
          const content = await fs.readFile(filePath, 'utf8');
          const relativeFilePath = path.relative(this.projectPath, filePath);
          this.scannedFiles.push(relativeFilePath);
          this.log(`Scanning config file: ${relativeFilePath}`);

          // Check for hardcoded secrets in config files
          const sensitivePatterns = [
            {
              regex: /(password|secret|key|token|credential)(['"]\s*:\s*['"])[^'"${}]+(['"])/gi,
              label: 'Secret/Credential',
            },
            { regex: /jwt\.sign\(\s*[^,]+,\s*['"`][^'"`${}]+['"`]/gi, label: 'JWT Secret' },
          ];

          for (const pattern of sensitivePatterns) {
            let match;
            while ((match = pattern.regex.exec(content)) !== null) {
              // Get line number
              const lineNumber = this.getLineNumber(content, match.index);

              // Format and colorize the vulnerability finding
              console.log(
                `${chalk.cyan('➤')} Found vulnerability in ${chalk.yellow(relativeFilePath)}:${chalk.yellow(
                  lineNumber.toString(),
                )}: ` + `${chalk.red.bold('[HIGH]')} Hardcoded ${pattern.label} in Configuration`,
              );

              vulnerabilities.push({
                id: `config-hardcoded-${pattern.label.toLowerCase().replace(/\s+/g, '-')}`,
                title: `Hardcoded ${pattern.label} in Configuration`,
                description: `Hardcoded ${pattern.label} found in configuration file`,
                severity: 'high',
                location: relativeFilePath,
                line: lineNumber,
                code: this.maskSensitiveData(match[0]),
                recommendation:
                  'Use environment variables or a secure vault for sensitive data instead of hardcoding values',
                category: 'configuration',
              });
            }
          }

          // Check for insecure session configuration
          if (
            content.includes('cookie') &&
            content.includes('secure') &&
            content.includes('false')
          ) {
            // Format and colorize the vulnerability finding
            console.log(
              `${chalk.cyan('➤')} Found vulnerability in ${chalk.yellow(relativeFilePath)}: ` +
                `${chalk.yellow.bold('[MEDIUM]')} Insecure Cookie Configuration`,
            );

            vulnerabilities.push({
              id: 'config-insecure-cookie',
              title: 'Insecure Cookie Configuration',
              description: 'Cookies configured without the secure flag',
              severity: 'medium',
              location: relativeFilePath,
              recommendation: 'Set secure: true for cookies in production environments',
              category: 'configuration',
            });
          }
        } catch (error) {
          if (this.verbose) {
            console.error(`Error checking config file ${filePath}:`, error);
          }
        }
      }
    } catch (error) {
      if (this.verbose) {
        console.error('Error in checkConfigFiles:', error);
      }
    }

    return vulnerabilities;
  }

  private async checkPackageJson(): Promise<SecurityVulnerability[]> {
    const vulnerabilities: SecurityVulnerability[] = [];

    const packageJsonPath = path.join(this.projectPath, 'package.json');
    if (!fs.existsSync(packageJsonPath)) {
      this.log('No package.json file found');
      return vulnerabilities;
    }

    const relativePackageJsonPath = path.relative(this.projectPath, packageJsonPath);
    this.scannedFiles.push(relativePackageJsonPath);
    this.log(`Scanning package.json: ${relativePackageJsonPath}`);

    try {
      const packageJson = await fs.readJson(packageJsonPath);

      // Check for missing security-related dependencies
      const securityRecommendations = [
        {
          package: 'helmet',
          title: 'Missing Helmet Security Package',
          description: 'Helmet helps secure Express/NestJS apps by setting various HTTP headers',
          severity: 'medium',
          recommendation: 'Install and use helmet to secure HTTP headers: npm install helmet',
        },
        {
          package: 'class-validator',
          title: 'Missing Validation Package',
          description: 'No validation library found for validating input data',
          severity: 'medium',
          recommendation:
            'Install and use class-validator for input validation: npm install class-validator class-transformer',
        },
        {
          package: 'csurf',
          title: 'Missing CSRF Protection',
          description: 'No CSRF protection middleware found',
          severity: 'medium',
          recommendation: 'Install and use csurf for CSRF protection: npm install csurf',
        },
      ];

      const dependencies = { ...packageJson.dependencies, ...packageJson.devDependencies };

      for (const recommendation of securityRecommendations) {
        if (!dependencies[recommendation.package]) {
          // Format and colorize the vulnerability finding
          console.log(
            `${chalk.cyan('➤')} Found vulnerability in ${chalk.yellow('package.json')}: ` +
              `${chalk.yellow.bold('[MEDIUM]')} ${recommendation.title}`,
          );

          vulnerabilities.push({
            id: `config-missing-${recommendation.package}`,
            title: recommendation.title,
            description: recommendation.description,
            severity: recommendation.severity as any,
            location: 'package.json',
            recommendation: recommendation.recommendation,
            category: 'configuration',
          });
        }
      }
    } catch (error) {
      if (this.verbose) {
        console.error('Error checking package.json:', error);
      }
    }

    return vulnerabilities;
  }

  private async isFileInGitignore(filepath: string): Promise<boolean> {
    const gitignorePath = path.join(this.projectPath, '.gitignore');

    if (!fs.existsSync(gitignorePath)) {
      return false;
    }

    try {
      const gitignore = await fs.readFile(gitignorePath, 'utf8');
      const lines = gitignore.split('\n').map((line: string) => line.trim());

      // Check if the file is directly excluded
      if (lines.includes(filepath)) {
        return true;
      }

      // Check if the file is excluded by pattern
      const filename = path.basename(filepath);
      if (lines.includes(filename) || lines.includes(`*${path.extname(filepath)}`)) {
        return true;
      }

      // Check if it's in an excluded directory
      const dirname = path.dirname(filepath);
      if (lines.some((line: string) => dirname.startsWith(line.replace(/\/$/, '')))) {
        return true;
      }

      return false;
    } catch (error) {
      if (this.verbose) {
        console.error('Error checking .gitignore:', error);
      }
      return false;
    }
  }

  private getLineNumber(content: string, index: number): number {
    const textBeforeMatch = content.substring(0, index);
    return (textBeforeMatch.match(/\n/g) || []).length + 1;
  }

  private maskSensitiveData(text: string): string {
    // Find the equals sign or colon
    const separatorIndex = text.indexOf('=') >= 0 ? text.indexOf('=') : text.indexOf(':');

    if (separatorIndex < 0) {
      return text;
    }

    // Get the part before and after the separator
    const before = text.substring(0, separatorIndex + 1);
    const after = text.substring(separatorIndex + 1).trim();

    // If the value is wrapped in quotes, preserve the quotes but mask the content
    if (
      (after.startsWith("'") && after.endsWith("'")) ||
      (after.startsWith('"') && after.endsWith('"'))
    ) {
      const quote = after[0];
      return `${before} ${quote}********${quote}`;
    }

    // Otherwise just mask the value
    return `${before} ********`;
  }
}

import * as fs from 'fs-extra';
import * as path from 'path';
import { SecurityVulnerability, Scanner } from '../types';
import { promisify } from 'util';
import { exec } from 'child_process';
import * as globModule from 'glob';
import chalk from 'chalk';

const execPromise = promisify(exec);
// Use synchronous glob instead of trying to promisify
const globSync = globModule.sync;

export class CodeScanner implements Scanner {
  private projectPath: string;
  private vulnerabilities: SecurityVulnerability[] = [];
  private scannedFiles: string[] = [];
  private verbose: boolean;

  // Common security vulnerability patterns to look for
  private securityPatterns = [
    {
      regex: /TypeOrmModule\.forRoot\({[\s\S]*?synchronize:\s*true/gm,
      severity: 'high',
      title: 'Automatic Schema Synchronization in Production',
      description: 'TypeORM is configured with synchronize: true, which can cause data loss in production environments',
      recommendation: 'Set synchronize: false in production environments and use migrations instead',
    },
    {
      regex: /createConnection\({[\s\S]*?synchronize:\s*true/gm,
      severity: 'high',
      title: 'Automatic Schema Synchronization in Production',
      description: 'TypeORM is configured with synchronize: true, which can cause data loss in production environments',
      recommendation: 'Set synchronize: false in production environments and use migrations instead',
    },
    {
      regex: /@Body\(\s*\)(?!\s*@ValidateNested|\s*@UsePipes)/gm,
      severity: 'medium',
      title: 'Missing DTO Validation',
      description: 'Request body is used without validation, which can lead to data injection attacks',
      recommendation:
        'Apply validation using class-validator and class-transformer with ValidateNested or ValidationPipe',
    },
    {
      regex: /cors:\s*true/gm,
      severity: 'medium',
      title: 'Permissive CORS Policy',
      description: 'CORS is configured to allow all origins, which can lead to cross-site request forgery attacks',
      recommendation: 'Configure CORS with specific origins, methods, and credentials settings',
    },
    {
      regex: /new\s+JwtModule\.register\({[\s\S]*?secret:\s*['"]([^'"]+)['"]/gm,
      severity: 'high',
      title: 'Hardcoded JWT Secret',
      description: 'JWT secret is hardcoded in the source code, which is a security risk',
      recommendation: 'Use environment variables for JWT secrets and other sensitive configuration values',
    },
    {
      regex: /eval\s*\(/gm,
      severity: 'high',
      title: 'Use of eval() function',
      description: 'Using eval() can lead to code injection vulnerabilities',
      recommendation: 'Avoid using eval() and use safer alternatives like JSON.parse for JSON data',
    },
    {
      regex: /helmet\s*\(\s*\)/gm,
      severity: 'low',
      title: 'Default Helmet Configuration',
      description: 'Using default Helmet configuration may not provide optimal security for your specific application',
      recommendation: 'Configure Helmet with specific security options based on your application requirements',
    },
    {
      regex:
        /const\s+[a-zA-Z0-9_$]+\s*=\s*require\s*\(\s*['"]crypto['"]\s*\)[\s\S]*?createHash\s*\(\s*['"]md5['"]\s*\)/gm,
      severity: 'medium',
      title: 'Weak Hashing Algorithm (MD5)',
      description: 'MD5 is a cryptographically broken hashing algorithm',
      recommendation: 'Use stronger hash functions like SHA-256 or bcrypt/argon2 for passwords',
    },
  ];

  constructor(projectPath: string, verbose: boolean = false) {
    // Resolve the path to an absolute path to ensure consistency
    this.projectPath = path.resolve(projectPath);
    this.verbose = verbose;
    this.log(`CodeScanner initialized with resolved path: ${this.projectPath}`);
  }

  private log(message: string): void {
    if (this.verbose) {
      console.log(message);
    }
  }

  async scan(): Promise<{ vulnerabilities: SecurityVulnerability[]; scannedFiles: string[] }> {
    try {
      // Use glob pattern to directly find all TypeScript and JavaScript files
      this.log(`Using glob to scan for files in: ${this.projectPath}`);

      // Create an absolute path pattern with specific handling for Windows backslashes
      const normalizedPath = this.projectPath.replace(/\\/g, '/');
      const globPattern = `${normalizedPath}/src/**/*.{ts,js}`;
      this.log(`Glob pattern: ${globPattern}`);

      // Use globSync directly to avoid TypeScript issues with promisify
      const files = globSync(globPattern, {
        ignore: ['**/node_modules/**', '**/dist/**'],
        absolute: true,
      });
      this.log(`Found ${files.length} TypeScript/JavaScript files to scan`);

      // If no files found with the first approach, try an alternate pattern
      if (files.length === 0) {
        // Try with a different approach - find any .ts or .js files in any subdirectory
        this.log('No files found with first pattern, trying alternate pattern');
        const altPattern = `${normalizedPath}/**/*.{ts,js}`;
        this.log(`Alternate glob pattern: ${altPattern}`);

        const altFiles = globSync(altPattern, {
          ignore: ['**/node_modules/**', '**/dist/**'],
          absolute: true,
        });
        this.log(`Found ${altFiles.length} TypeScript/JavaScript files with alternate pattern`);

        // If files found with alternate pattern, process them
        if (altFiles.length > 0) {
          for (const filePath of altFiles) {
            this.log(`Found matching file: ${filePath}`);
            const relativePath = path.relative(this.projectPath, filePath);
            this.log(`Scanning file: ${relativePath}`);
            this.scannedFiles.push(relativePath);
            await this.scanFile(filePath);
          }
        } else {
          // As a last resort, try manual file listing
          this.log('Falling back to manual file listing');
          const manualFiles = this.findFilesRecursively(this.projectPath, ['.ts', '.js']);
          this.log(`Manually found ${manualFiles.length} files`);

          for (const filePath of manualFiles) {
            const relativePath = path.relative(this.projectPath, filePath);
            this.log(`Scanning manually found file: ${relativePath}`);
            this.scannedFiles.push(relativePath);
            await this.scanFile(filePath);
          }
        }
      } else {
        // Process each file found by glob
        for (const filePath of files) {
          const relativePath = path.relative(this.projectPath, filePath);
          this.log(`Scanning file: ${relativePath}`);
          this.scannedFiles.push(relativePath);
          await this.scanFile(filePath);
        }
      }

      this.log(
        `Code scanner completed. Scanned ${this.scannedFiles.length} files, found ${this.vulnerabilities.length} vulnerabilities`
      );

      // Always display the number of vulnerabilities found
      if (this.vulnerabilities.length > 0) {
        console.log(`Found ${this.vulnerabilities.length} code vulnerabilities`);
      }

      return {
        vulnerabilities: this.vulnerabilities,
        scannedFiles: this.scannedFiles,
      };
    } catch (error) {
      if (this.verbose) {
        console.error('Error scanning code:', error);
      }
      return { vulnerabilities: [], scannedFiles: this.scannedFiles };
    }
  }

  // Find files recursively - an alternative to glob that's more direct
  private findFilesRecursively(dir: string, extensions: string[]): string[] {
    this.log(`Searching directory: ${dir}`);

    if (!fs.existsSync(dir)) {
      this.log(`Directory not found: ${dir}`);
      return [];
    }

    let result: string[] = [];

    try {
      const entries = fs.readdirSync(dir);

      for (const entry of entries) {
        const fullPath = path.join(dir, entry);
        const isDirectory = fs.statSync(fullPath).isDirectory();

        if (isDirectory) {
          // Skip node_modules, dist, etc.
          if (entry !== 'node_modules' && entry !== 'dist') {
            const subDirFiles = this.findFilesRecursively(fullPath, extensions);
            result = result.concat(subDirFiles);
          }
        } else {
          const ext = path.extname(entry);
          if (extensions.includes(ext)) {
            this.log(`Found file: ${fullPath}`);
            result.push(fullPath);
          }
        }
      }
    } catch (error) {
      if (this.verbose) {
        console.error(`Error reading directory ${dir}:`, error);
      }
    }

    return result;
  }

  private async scanFile(filePath: string): Promise<void> {
    try {
      const content = await fs.readFile(filePath, 'utf8');
      const relativeFilePath = path.relative(this.projectPath, filePath);

      // Reset regex lastIndex before use
      for (const pattern of this.securityPatterns) {
        pattern.regex.lastIndex = 0;
      }

      // Check each security pattern
      for (const pattern of this.securityPatterns) {
        let match;
        while ((match = pattern.regex.exec(content)) !== null) {
          // Get the line number of the match
          const lineNumber = this.getLineNumber(content, match.index);
          const matchedCode = match[0];

          // Format and colorize the vulnerability finding
          const severityColor = this.getSeverityColor(pattern.severity);
          console.log(
            `${chalk.cyan('➤')} Found vulnerability in ${chalk.yellow(relativeFilePath)}:${chalk.yellow(
              lineNumber.toString()
            )}: ` + `${severityColor(`[${pattern.severity.toUpperCase()}]`)} ${chalk.bold(pattern.title)}`
          );

          this.vulnerabilities.push({
            id: `code-${pattern.title.toLowerCase().replace(/\s+/g, '-')}`,
            title: pattern.title,
            description: pattern.description,
            severity: pattern.severity as any,
            location: relativeFilePath,
            line: lineNumber,
            code: matchedCode.trim(),
            recommendation: pattern.recommendation,
            category: 'code',
          });
        }
      }
    } catch (error) {
      if (this.verbose) {
        console.error(`Error scanning file ${filePath}:`, error);
      }
    }
  }

  // Helper method to get color based on severity
  private getSeverityColor(severity: string): chalk.Chalk {
    switch (severity) {
      case 'high':
        return chalk.red.bold;
      case 'medium':
        return chalk.yellow.bold;
      case 'low':
        return chalk.blue.bold;
      default:
        return chalk.white;
    }
  }

  private getLineNumber(content: string, index: number): number {
    const textBeforeMatch = content.substring(0, index);
    return (textBeforeMatch.match(/\n/g) || []).length + 1;
  }
}

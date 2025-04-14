import * as fs from 'fs-extra';
import * as path from 'path';
import { execSync } from 'child_process';
import { DependencyScanner } from './scanners/dependency-scanner';
import { CodeScanner } from './scanners/code-scanner';
import { ConfigScanner } from './scanners/config-scanner';
import { RateLimitScanner } from './scanners/rate-limit-scanner';
import { AuthorizationScanner } from './scanners/authorization-scanner';
import { SecurityVulnerability, ScanResult, ScanOptions } from './types';
import chalk from 'chalk';

export class SecurityScanner {
  private options: ScanOptions;
  private vulnerabilities: SecurityVulnerability[] = [];
  private scannedFiles: Set<string> = new Set<string>();

  constructor(options: ScanOptions) {
    this.options = {
      projectPath: path.resolve(options.projectPath || process.cwd()),
      verbose: options.verbose || false,
      checkDependencies: options.checkDependencies !== false,
      checkCode: options.checkCode !== false,
      checkConfig: options.checkConfig !== false,
    };

    console.log(`Project path resolved to: ${this.options.projectPath}`);
  }

  private log(message: string): void {
    if (this.options.verbose) {
      console.log(message);
    }
  }

  private detectActualProjectDirectory(): string {
    const originalPath = this.options.projectPath;

    if (this.isValidNestjsProject(originalPath)) {
      return originalPath;
    }

    this.log(`Looking for valid NestJS project structure in ${originalPath}...`);

    const entries = fs.readdirSync(originalPath, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.isDirectory() && entry.name !== 'node_modules' && entry.name !== 'dist') {
        const subDir = path.join(originalPath, entry.name);
        if (this.isValidNestjsProject(subDir)) {
          this.log(`Found valid NestJS project in subdirectory: ${subDir}`);
          return subDir;
        }
      }
    }

    return originalPath;
  }

  private isValidNestjsProject(dir: string): boolean {
    const packageJsonPath = path.join(dir, 'package.json');
    if (!fs.existsSync(packageJsonPath)) {
      return false;
    }

    const srcPath = path.join(dir, 'src');
    if (!fs.existsSync(srcPath)) {
      return false;
    }

    const nestFiles = ['main.ts', 'app.module.ts', 'server.ts'];
    const srcFiles = fs.readdirSync(srcPath);
    const hasNestFiles = nestFiles.some((file) => srcFiles.includes(file));

    return hasNestFiles;
  }

  private validateProject(): boolean {
    try {
      if (!fs.existsSync(this.options.projectPath)) {
        throw new Error(`Project directory not found: ${this.options.projectPath}`);
      }

      if (this.options.verbose) {
        console.log('Project directory content:', fs.readdirSync(this.options.projectPath));
      }

      const packageJsonPath = path.join(this.options.projectPath, 'package.json');
      if (!fs.existsSync(packageJsonPath)) {
        throw new Error(`package.json not found in ${this.options.projectPath}`);
      }

      let packageJson;
      try {
        packageJson = fs.readJsonSync(packageJsonPath);
      } catch (e) {
        throw new Error(`Failed to parse package.json in ${this.options.projectPath}`);
      }

      const dependencies = { ...packageJson.dependencies, ...packageJson.devDependencies };

      if (!Object.keys(dependencies).some((dep) => dep.startsWith('@nestjs/'))) {
        throw new Error('This does not appear to be a NestJS project. No @nestjs/* dependencies found.');
      }

      if (this.options.verbose) {
        const srcPath = path.join(this.options.projectPath, 'src');
        if (fs.existsSync(srcPath)) {
          console.log('Found src directory:', srcPath);
          console.log('src directory content:', fs.readdirSync(srcPath));
        } else {
          console.log('src directory not found at:', srcPath);
        }
      }

      return true;
    } catch (error) {
      if (error instanceof Error) {
        console.error(`Error validating project: ${error.message}`);
      }
      return false;
    }
  }

  private scanSourceFiles(): string[] {
    const srcPath = path.join(this.options.projectPath, 'src');
    if (!fs.existsSync(srcPath)) {
      this.log(`Source directory not found at ${srcPath}`);
      return [];
    }

    const sourceFiles: string[] = [];
    this.scanDirectory(srcPath, sourceFiles, ['.ts', '.js']);

    this.log(`Found ${sourceFiles.length} source files to scan`);
    return sourceFiles;
  }

  private scanDirectory(dir: string, result: string[], extensions: string[]): void {
    if (!fs.existsSync(dir)) {
      return;
    }

    try {
      const entries = fs.readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);

        if (entry.isDirectory()) {
          if (entry.name !== 'node_modules' && entry.name !== 'dist' && entry.name !== 'test-nestjs-security') {
            this.scanDirectory(fullPath, result, extensions);
          }
        } else if (entry.isFile() && extensions.includes(path.extname(entry.name))) {
          this.log(`Found source file: ${fullPath}`);
          result.push(fullPath);
        }
      }
    } catch (error) {
      if (this.options.verbose) {
        console.error(`Error scanning directory ${dir}:`, error);
      }
    }
  }

  async scan(): Promise<ScanResult> {
    const detectedProjectPath = this.detectActualProjectDirectory();
    if (detectedProjectPath !== this.options.projectPath) {
      this.log(`Using detected project path: ${detectedProjectPath}`);
      this.options.projectPath = detectedProjectPath;
    }

    if (!this.validateProject()) {
      throw new Error('Project validation failed. Please check that this is a valid NestJS project.');
    }

    this.log(`Starting security scan of ${this.options.projectPath}`);

    const sourceFiles = this.scanSourceFiles();

    const startTime = Date.now();
    for (const filePath of sourceFiles) {
      const relativePath = path.relative(this.options.projectPath, filePath);
      this.log(`Directly scanning file: ${relativePath}`);

      this.scannedFiles.add(relativePath);

      try {
        const content = await fs.readFile(filePath, 'utf8');
        this.analyzeSecurity(filePath, content);
      } catch (error) {
        if (this.options.verbose) {
          console.error(`Error reading file ${filePath}:`, error);
        }
      }
    }
    const endTime = Date.now();
    this.log(`Direct scanning completed in ${endTime - startTime}ms`);

    let dependencyVulnerabilities: SecurityVulnerability[] = [];
    let codeVulnerabilities: SecurityVulnerability[] = [];
    let configVulnerabilities: SecurityVulnerability[] = [];
    let rateLimitVulnerabilities: SecurityVulnerability[] = [];
    let authorizationVulnerabilities: SecurityVulnerability[] = [];

    if (this.options.checkDependencies) {
      console.log('Scanning dependencies for vulnerabilities...');
      const dependencyScanner = new DependencyScanner(this.options.projectPath, this.options.verbose);
      const dependencyScanResult = await dependencyScanner.scan();
      dependencyVulnerabilities = dependencyScanResult.vulnerabilities;
      this.vulnerabilities.push(...dependencyVulnerabilities);

      dependencyScanResult.scannedFiles.forEach((file) => this.scannedFiles.add(file));
    }

    if (this.options.checkCode) {
      console.log('Scanning code for security issues...');
      const codeScanner = new CodeScanner(this.options.projectPath, this.options.verbose);
      const codeScanResult = await codeScanner.scan();
      codeVulnerabilities = codeScanResult.vulnerabilities;
      this.vulnerabilities.push(...codeVulnerabilities);

      codeScanResult.scannedFiles.forEach((file) => this.scannedFiles.add(file));

      // Run the rate limiting scanner
      console.log('Scanning for rate limiting issues...');
      const rateLimitScanner = new RateLimitScanner(this.options.projectPath, this.options.verbose);
      const rateLimitScanResult = await rateLimitScanner.scan();
      rateLimitVulnerabilities = rateLimitScanResult.vulnerabilities;
      this.vulnerabilities.push(...rateLimitVulnerabilities);

      rateLimitScanResult.scannedFiles.forEach((file) => this.scannedFiles.add(file));

      // Run the authorization scanner
      console.log('Scanning for authorization issues...');
      const authorizationScanner = new AuthorizationScanner(this.options.projectPath, this.options.verbose);
      const authorizationScanResult = await authorizationScanner.scan();
      authorizationVulnerabilities = authorizationScanResult.vulnerabilities;
      this.vulnerabilities.push(...authorizationVulnerabilities);

      authorizationScanResult.scannedFiles.forEach((file) => this.scannedFiles.add(file));
    }

    if (this.options.checkConfig) {
      console.log('Scanning configurations for security issues...');
      const configScanner = new ConfigScanner(this.options.projectPath, this.options.verbose);
      const configScanResult = await configScanner.scan();
      configVulnerabilities = configScanResult.vulnerabilities;
      this.vulnerabilities.push(...configVulnerabilities);

      configScanResult.scannedFiles.forEach((file) => this.scannedFiles.add(file));
    }

    const scannedFilesArray = Array.from(this.scannedFiles).sort();

    if (this.options.verbose) {
      console.log(`Total files scanned: ${scannedFilesArray.length}`);
    }

    const highSeverityCount = this.vulnerabilities.filter((v) => v.severity === 'high').length;
    const mediumSeverityCount = this.vulnerabilities.filter((v) => v.severity === 'medium').length;
    const lowSeverityCount = this.vulnerabilities.filter((v) => v.severity === 'low').length;

    return {
      vulnerabilities: this.vulnerabilities,
      totalVulnerabilities: this.vulnerabilities.length,
      highSeverityCount,
      mediumSeverityCount,
      lowSeverityCount,
      dependencyVulnerabilities,
      codeVulnerabilities,
      configVulnerabilities,
      scannedFiles: scannedFilesArray,
    };
  }

  private analyzeSecurity(filePath: string, content: string): void {
    const relativePath = path.relative(this.options.projectPath, filePath);

    const securityPatterns = [
      {
        regex: /TypeOrmModule\.forRoot\({[\s\S]*?synchronize:\s*true/gm,
        severity: 'high',
        title: 'Automatic Schema Synchronization in Production',
        description:
          'TypeORM is configured with synchronize: true, which can cause data loss in production environments',
        recommendation: 'Set synchronize: false in production environments and use migrations instead',
      },
      {
        regex: /createConnection\({[\s\S]*?synchronize:\s*true/gm,
        severity: 'high',
        title: 'Automatic Schema Synchronization in Production',
        description:
          'TypeORM is configured with synchronize: true, which can cause data loss in production environments',
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
        description:
          'Using default Helmet configuration may not provide optimal security for your specific application',
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
      {
        regex: /@Query\(\s*\)(?!\s*@ValidateNested|\s*@UsePipes)/gm,
        severity: 'medium',
        title: 'Missing Query Parameter Validation',
        description: 'Query parameters are used without validation, which can lead to data injection attacks',
        recommendation: 'Apply validation to query parameters using ValidationPipe or custom validators',
      },
      {
        regex: /@Param\(\s*\)(?!\s*@ValidateNested|\s*@UsePipes)/gm,
        severity: 'medium',
        title: 'Missing Route Parameter Validation',
        description: 'Route parameters are used without validation, which can lead to data injection attacks',
        recommendation: 'Apply validation to route parameters using ValidationPipe or custom validators',
      },
      {
        regex: /import\s+\{\s*[^}]*\bfs\b[^}]*\}\s+from\s+['"]fs['"]|require\s*\(\s*['"]fs['"]\s*\)/gm,
        severity: 'medium',
        title: 'Direct Filesystem Access',
        description: 'Direct filesystem access without validation might lead to path traversal vulnerabilities',
        recommendation: 'Validate and sanitize file paths, use path.resolve or path.join to normalize paths',
      },
      {
        regex: /\.set\(\s*['"]Authorization['"]|\.set\(\s*['"]Cookie['"]/gm,
        severity: 'medium',
        title: 'Setting Sensitive Headers in HTTP Client',
        description: 'Setting sensitive headers (Authorization, Cookie) directly in HTTP client calls',
        recommendation: 'Use secure, centralized HTTP interceptors for managing sensitive headers',
      },
      {
        regex: /\.createCipheriv\(\s*['"]des['"]/gm,
        severity: 'high',
        title: 'Weak Encryption Algorithm (DES)',
        description: 'DES is a weak encryption algorithm with small key size',
        recommendation: 'Use AES-256-GCM or other modern encryption algorithms',
      },
      {
        regex: /\.createHash\(\s*['"]sha1['"]/gm,
        severity: 'medium',
        title: 'Weak Hashing Algorithm (SHA-1)',
        description: 'SHA-1 is considered cryptographically weak and susceptible to collision attacks',
        recommendation: 'Use stronger hash functions like SHA-256 or bcrypt/argon2 for passwords',
      },
      {
        regex: /app\.enableCors\(\s*\{\s*origin\s*:\s*['"]?[*]|app\.enableCors\(\s*\{\s*origin\s*:\s*true/gm,
        severity: 'medium',
        title: 'Overly Permissive CORS Policy',
        description: 'CORS is configured to allow all origins with wildcard or true setting',
        recommendation: 'Specify explicit allowed origins rather than using a wildcard or true',
      },
      {
        regex: /\.sign\(\s*[^,]+,\s*['"][^'"]+['"](?!\s*,\s*\{\s*expiresIn)/gm,
        severity: 'medium',
        title: 'JWT Without Expiration',
        description: 'JWT tokens are being created without an expiration time',
        recommendation: 'Always include expiresIn option when signing JWTs to limit token lifetime',
      },
      {
        regex: /cookie-parser|cookieParser\((?!\s*\{\s*secure\s*:\s*true)/gm,
        severity: 'medium',
        title: 'Insecure Cookie Configuration',
        description: 'Cookies configured without secure flag may be transmitted over insecure HTTP',
        recommendation: 'Set secure: true and httpOnly: true for cookies in production environments',
      },
      {
        regex: /passport\.use\(new\s+LocalStrategy/gm,
        severity: 'low',
        title: 'Plain Local Authentication Strategy',
        description: 'Using local authentication strategy without additional security measures',
        recommendation: 'Consider implementing rate limiting and 2FA to protect login endpoints',
      },
      {
        regex: /new\s+MongoClient\(.*\{\s*useUnifiedTopology\s*:\s*true/gm,
        severity: 'low',
        title: 'MongoDB Without TLS/SSL',
        description: 'MongoDB connection without explicitly enabling TLS/SSL',
        recommendation: 'Use TLS/SSL for MongoDB connections by setting ssl: true in connection options',
      },
      {
        regex: /res\.writeHead\(.*['"]Access-Control-Allow-Origin['"]\s*,\s*['"]?\*/gm,
        severity: 'medium',
        title: 'Manual CORS Headers with Wildcard Origin',
        description: 'Manually setting Access-Control-Allow-Origin header with a wildcard',
        recommendation: 'Use NestJS CORS module with specific origins instead of manual CORS headers',
      },
      {
        regex: /\.innerJoin\(.*\bOR\b.*\)/gim,
        severity: 'medium',
        title: 'Potential SQL Injection in TypeORM Query',
        description: 'Using OR conditions in string format can lead to SQL injection if not properly escaped',
        recommendation: 'Use TypeORM query builder parameters or the where object syntax instead',
      },
      {
        regex: /validate:\s*false/gm,
        severity: 'medium',
        title: 'Validation Disabled in ORM Entity',
        description: 'Data validation is explicitly disabled in entity definition',
        recommendation: 'Enable validation in ORM entities and use class-validator decorators',
      },
    ];

    for (const pattern of securityPatterns) {
      pattern.regex.lastIndex = 0;
      let match;
      while ((match = pattern.regex.exec(content)) !== null) {
        const lineNumber = this.getLineNumber(content, match.index);
        const matchedCode = match[0];

        const severityColor = this.getSeverityColor(pattern.severity);
        console.log(
          `${chalk.cyan('➤')} Found vulnerability in ${chalk.yellow(relativePath)}:${chalk.yellow(
            lineNumber.toString()
          )}: ` + `${severityColor(`[${pattern.severity.toUpperCase()}]`)} ${chalk.bold(pattern.title)}`
        );

        this.vulnerabilities.push({
          id: `code-${pattern.title.toLowerCase().replace(/\s+/g, '-')}`,
          title: pattern.title,
          description: pattern.description,
          severity: pattern.severity as any,
          location: relativePath,
          line: lineNumber,
          code: matchedCode.trim(),
          recommendation: pattern.recommendation,
          category: 'code',
        });
      }
    }
  }

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

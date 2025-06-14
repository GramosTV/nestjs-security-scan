// filepath: c:\Users\gramo\Desktop\projects\nestjs-security-scan\src\scanners\rate-limit-scanner.ts
import * as fs from 'fs-extra';
import * as path from 'path';
import { SecurityVulnerability, Scanner } from '../types';
import * as globModule from 'glob';
import chalk from 'chalk';

// Use synchronous glob
const globSync = globModule.sync;

export class RateLimitScanner implements Scanner {
  private projectPath: string;
  private vulnerabilities: SecurityVulnerability[] = [];
  private scannedFiles: string[] = [];
  private verbose: boolean;
  private hasAuthEndpoints: boolean = false;
  private hasThrottlerModule: boolean = false;

  constructor(projectPath: string, verbose: boolean = false) {
    // Resolve the path to an absolute path to ensure consistency
    this.projectPath = path.resolve(projectPath);
    this.verbose = verbose;
    this.log(`RateLimitScanner initialized with resolved path: ${this.projectPath}`);
  }

  private log(message: string): void {
    if (this.verbose) {
      console.log(message);
    }
  }

  async scan(): Promise<{ vulnerabilities: SecurityVulnerability[]; scannedFiles: string[] }> {
    try {
      this.log('Starting rate limit scanner...');

      // Create an absolute path pattern with specific handling for Windows backslashes
      const normalizedPath = this.projectPath.replace(/\\/g, '/');
      const globPattern = `${normalizedPath}/src/**/*.{ts,js}`;
      this.log(`Glob pattern: ${globPattern}`);

      // Use globSync directly
      const files = globSync(globPattern, {
        ignore: ['**/node_modules/**', '**/dist/**', '**/*.spec.ts', '**/*.test.ts'],
        absolute: true,
      });
      this.log(`Found ${files.length} TypeScript/JavaScript files to scan`);

      // First pass: check if application has auth endpoints and if throttler is imported
      for (const filePath of files) {
        const relativePath = path.relative(this.projectPath, filePath);
        this.scannedFiles.push(relativePath);

        try {
          const content = await fs.readFile(filePath, 'utf8');

          // Check for auth endpoints
          if (
            content.includes('@Post') &&
            (content.includes('/login') ||
              content.includes('/auth') ||
              content.includes('/signin') ||
              content.includes('authenticate') ||
              content.includes('validateUser'))
          ) {
            this.hasAuthEndpoints = true;
            this.log(`Found auth endpoint in file: ${relativePath}`);
          }

          // Check for throttler module or custom rate limiting
          if (
            content.includes('ThrottlerModule') ||
            content.includes('throttle') ||
            content.includes('RateLimit') ||
            content.includes('rate-limit')
          ) {
            this.hasThrottlerModule = true;
            this.log(`Found rate limiting in file: ${relativePath}`);
          }
        } catch (error) {
          if (this.verbose) {
            console.error(`Error reading file ${filePath}:`, error);
          }
        }
      }

      // Second pass: detailed analysis of auth endpoints
      if (this.hasAuthEndpoints && !this.hasThrottlerModule) {
        this.log('Auth endpoints found but no rate limiting detected');

        console.log(
          `${chalk.cyan('➤')} Found vulnerability: ` +
            `${chalk.yellow.bold('[MEDIUM]')} ${chalk.bold('Missing Rate Limiting on Authentication Endpoints')}`,
        );

        this.vulnerabilities.push({
          id: 'auth-missing-rate-limit',
          title: 'Missing Rate Limiting on Authentication Endpoints',
          description:
            'Authentication endpoints are not protected with rate limiting, which makes them vulnerable to brute force attacks',
          severity: 'medium',
          location: 'Multiple authentication-related files',
          recommendation:
            'Implement rate limiting using @nestjs/throttler package or a similar rate limiting mechanism',
          category: 'code',
        });
      }

      // Check for main.ts to see if global throttler is applied
      const mainTsFiles = files.filter(file => path.basename(file) === 'main.ts');
      if (mainTsFiles.length > 0) {
        for (const mainFile of mainTsFiles) {
          const content = await fs.readFile(mainFile, 'utf8');
          const relativePath = path.relative(this.projectPath, mainFile);

          // Check if app.use() is present but no rate limiter
          if (
            content.includes('app.use(') &&
            !content.includes('throttler') &&
            !content.includes('rateLimit')
          ) {
            console.log(
              `${chalk.cyan('➤')} Found vulnerability in ${chalk.yellow(relativePath)}: ` +
                `${chalk.blue.bold('[LOW]')} ${chalk.bold('Consider Adding Global Rate Limiting')}`,
            );

            this.vulnerabilities.push({
              id: 'global-rate-limit-recommendation',
              title: 'Consider Adding Global Rate Limiting',
              description:
                "The application uses middleware but doesn't appear to have global rate limiting configured",
              severity: 'low',
              location: relativePath,
              recommendation:
                'Consider adding global rate limiting middleware to protect all endpoints from potential abuse',
              category: 'code',
            });
          }
        }
      }

      // Check for security-related decorators
      await this.checkForSecurityDecorators(files);

      // Check package.json for recommended security packages
      await this.checkPackageJson();

      this.log(
        `Rate limit scanner completed. Scanned ${this.scannedFiles.length} files, found ${this.vulnerabilities.length} vulnerabilities`,
      );

      if (this.vulnerabilities.length > 0) {
        console.log(`Found ${this.vulnerabilities.length} rate limiting vulnerabilities`);
      }

      return {
        vulnerabilities: this.vulnerabilities,
        scannedFiles: this.scannedFiles,
      };
    } catch (error) {
      if (this.verbose) {
        console.error('Error scanning for rate limiting:', error);
      }
      return { vulnerabilities: this.vulnerabilities, scannedFiles: this.scannedFiles };
    }
  }

  private async checkForSecurityDecorators(files: string[]): Promise<void> {
    for (const filePath of files) {
      try {
        const content = await fs.readFile(filePath, 'utf8');
        const relativePath = path.relative(this.projectPath, filePath);

        // Check for auth-related controllers without rate limiting
        if (
          (content.includes('@Controller') || content.includes('@Resolver')) &&
          (content.includes('@Post') || content.includes('@Mutation')) &&
          (content.includes('auth') || content.includes('login') || content.includes('user'))
        ) {
          // Check if this file has auth/login/user related endpoints but no throttling
          if (
            !content.includes('@Throttle') &&
            !content.includes('@SkipThrottle') &&
            !content.includes('RateLimit')
          ) {
            console.log(
              `${chalk.cyan('➤')} Found vulnerability in ${chalk.yellow(relativePath)}: ` +
                `${chalk.yellow.bold('[MEDIUM]')} ${chalk.bold('Authentication Controller Without Rate Limiting')}`,
            );

            this.vulnerabilities.push({
              id: 'auth-controller-missing-rate-limit',
              title: 'Authentication Controller Without Rate Limiting',
              description:
                'Controller handling authentication operations lacks rate limiting decorators',
              severity: 'medium',
              location: relativePath,
              recommendation:
                'Add @Throttle() decorator to sensitive authentication methods or apply rate limiting at the controller level',
              category: 'code',
            });
          }
        }
      } catch (error) {
        if (this.verbose) {
          console.error(`Error checking for security decorators in ${filePath}:`, error);
        }
      }
    }
  }

  private async checkPackageJson(): Promise<void> {
    const packageJsonPath = path.join(this.projectPath, 'package.json');
    if (fs.existsSync(packageJsonPath)) {
      try {
        const packageJson = await fs.readJson(packageJsonPath);
        const dependencies = { ...packageJson.dependencies, ...packageJson.devDependencies };
        this.scannedFiles.push('package.json');

        // Check for recommended security packages
        if (!dependencies['@nestjs/throttler'] && this.hasAuthEndpoints) {
          console.log(
            `${chalk.cyan('➤')} Found vulnerability in ${chalk.yellow('package.json')}: ` +
              `${chalk.yellow.bold('[MEDIUM]')} ${chalk.bold('Missing Throttler Package')}`,
          );

          this.vulnerabilities.push({
            id: 'missing-throttler-package',
            title: 'Missing Throttler Package',
            description:
              'Application has authentication endpoints but is missing the @nestjs/throttler package',
            severity: 'medium',
            location: 'package.json',
            recommendation:
              'Install @nestjs/throttler and configure it to protect authentication endpoints: npm install --save @nestjs/throttler',
            category: 'dependency',
          });
        }

        // Check for Express Rate Limit as an alternative
        if (
          !dependencies['express-rate-limit'] &&
          !dependencies['@nestjs/throttler'] &&
          this.hasAuthEndpoints
        ) {
          console.log(
            `${chalk.cyan('➤')} Found vulnerability in ${chalk.yellow('package.json')}: ` +
              `${chalk.blue.bold('[LOW]')} ${chalk.bold('No Rate Limiting Packages Detected')}`,
          );

          this.vulnerabilities.push({
            id: 'missing-rate-limit-packages',
            title: 'No Rate Limiting Packages Detected',
            description: 'No rate limiting packages were found in dependencies',
            severity: 'low',
            location: 'package.json',
            recommendation:
              'Consider installing either @nestjs/throttler or express-rate-limit to protect against brute force and DoS attacks',
            category: 'dependency',
          });
        }
      } catch (error) {
        if (this.verbose) {
          console.error('Error checking package.json:', error);
        }
      }
    }
  }
}

import * as path from 'path';
import { execSync } from 'child_process';
import { SecurityVulnerability, Scanner } from '../types';
import * as globModule from 'glob';
import chalk from 'chalk';

// Use synchronous glob
const globSync = globModule.sync;

export class DependencyScanner implements Scanner {
  private projectPath: string;
  private scannedFiles: string[] = [];
  private verbose: boolean;

  constructor(projectPath: string, verbose: boolean = false) {
    // Resolve the path to an absolute path to ensure consistency
    this.projectPath = path.resolve(projectPath);
    this.verbose = verbose;
    this.log(`DependencyScanner initialized with resolved path: ${this.projectPath}`);
  }

  private log(message: string): void {
    if (this.verbose) {
      console.log(message);
    }
  }

  async scan(): Promise<{ vulnerabilities: SecurityVulnerability[]; scannedFiles: string[] }> {
    const vulnerabilities: SecurityVulnerability[] = [];

    try {
      this.log('Starting dependency scanner...');

      // Find and track dependency files directly
      const pattern = path.join(this.projectPath, '{package.json,package-lock.json,yarn.lock}');
      this.log(`Searching for dependency files with pattern: ${pattern}`);

      let packageFiles: string[] = [];
      try {
        // Use sync glob directly
        packageFiles = globSync(pattern, {
          ignore: ['**/node_modules/**', '**/dist/**'],
        });
      } catch (error) {
        this.log('Error with sync glob');
        if (this.verbose) {
          console.log(error);
        }
      }

      for (const filePath of packageFiles) {
        const relativeFilePath = path.relative(this.projectPath, filePath);
        this.scannedFiles.push(relativeFilePath);
        this.log(`Found dependency file: ${relativeFilePath}`);
      }

      // Use npm audit to check for vulnerabilities
      try {
        this.log('Running npm audit...');
        const auditOutput = this.runNpmAudit();
        if (auditOutput.trim()) {
          this.log('npm audit returned results, parsing...');
          const parsedAudit = this.parseNpmAuditOutput(auditOutput);
          vulnerabilities.push(...parsedAudit);

          // Always show the number of vulnerabilities found from npm audit
          if (parsedAudit.length > 0) {
            console.log(`Found ${parsedAudit.length} vulnerabilities from npm audit`);
          }
        } else {
          this.log('npm audit returned no results');
        }
      } catch (error) {
        if (this.verbose) {
          console.error('Error running npm audit:', error);
        }
      }

      // Add Snyk scan if available
      try {
        this.log('Attempting to run Snyk test...');
        const snykOutput = this.runSnykTest();
        const parsedSnyk = this.parseSnykOutput(snykOutput);
        vulnerabilities.push(...parsedSnyk);

        // Always show the number of vulnerabilities found from Snyk
        if (parsedSnyk.length > 0) {
          console.log(`Found ${parsedSnyk.length} vulnerabilities from Snyk`);
        }
      } catch {
        // Snyk might not be authenticated or installed globally, so we'll just skip it
        this.log('Skipping Snyk scan (may not be installed or authenticated)');
      }

      this.log(
        `Dependency scanner completed. Scanned ${this.scannedFiles.length} files, found ${vulnerabilities.length} vulnerabilities`,
      );

      // Always display the total number of dependency vulnerabilities found
      if (vulnerabilities.length > 0) {
        console.log(`Found ${vulnerabilities.length} dependency vulnerabilities total`);
      }
    } catch (error) {
      // If there's an error scanning dependencies, return an empty array
      // We don't want to fail the entire scan if one scanner fails
      if (this.verbose) {
        console.error('Error scanning dependencies:', error);
      }
    }

    return { vulnerabilities, scannedFiles: this.scannedFiles };
  }

  private runNpmAudit(): string {
    try {
      this.log(`Running npm audit in directory: ${this.projectPath}`);
      return execSync('npm audit --json', {
        cwd: this.projectPath,
        encoding: 'utf8',
        stdio: ['pipe', 'pipe', 'pipe'],
      });
    } catch (error: unknown) {
      // npm audit exits with non-zero code when it finds vulnerabilities,
      // but we still want to capture the output
      const errorWithStdout = error as { stdout?: string };
      if (errorWithStdout && typeof errorWithStdout === 'object' && 'stdout' in errorWithStdout) {
        return errorWithStdout.stdout || '';
      }
      throw error;
    }
  }

  private parseNpmAuditOutput(output: string): SecurityVulnerability[] {
    try {
      if (!output || output.trim() === '') {
        this.log('Empty npm audit output, nothing to parse');
        return [];
      }

      const auditData = JSON.parse(output);
      const vulnerabilities: SecurityVulnerability[] = [];

      if (!auditData.vulnerabilities) {
        this.log('No vulnerabilities found in npm audit data');
        return vulnerabilities;
      }

      // Process each vulnerability found by npm audit
      Object.entries(auditData.vulnerabilities).forEach(
        ([packageName, vulnData]: [string, any]) => {
          const severity = this.mapNpmSeverity(vulnData.severity);
          const severityColor = this.getSeverityColor(severity);

          // Format and colorize the vulnerability finding
          console.log(
            `${chalk.cyan('➤')} Found vulnerability in ${chalk.yellow(packageName)}: ` +
              `${severityColor(`[${severity.toUpperCase()}]`)} ${chalk.bold(vulnData.name || packageName)}`,
          );

          vulnerabilities.push({
            id: `npm-${vulnData.name}-${vulnData.source || packageName}`,
            title: `Vulnerable dependency: ${packageName}`,
            description: vulnData.overview || `${packageName} has known security vulnerabilities`,
            severity,
            location: packageName,
            recommendation:
              vulnData.recommendation ||
              `Upgrade to ${vulnData.fixAvailable?.version || 'a newer version'}`,
            reference:
              vulnData.url ||
              'https://docs.npmjs.com/auditing-package-dependencies-for-security-vulnerabilities',
            category: 'dependency',
          });
        },
      );

      return vulnerabilities;
    } catch (error) {
      if (this.verbose) {
        console.error('Error parsing npm audit output:', error);
        // Log the problematic output for debugging
        console.error(
          'Problematic npm audit output:',
          output.substring(0, 500) + (output.length > 500 ? '...' : ''),
        );
      }
      return [];
    }
  }

  private runSnykTest(): string {
    try {
      this.log(`Running Snyk test in directory: ${this.projectPath}`);
      return execSync('npx snyk test --json', {
        cwd: this.projectPath,
        encoding: 'utf8',
        stdio: ['pipe', 'pipe', 'pipe'],
      });
    } catch (error: unknown) {
      // Snyk also exits with non-zero when finding vulnerabilities
      const errorWithStdout = error as { stdout?: string };
      if (errorWithStdout && typeof errorWithStdout === 'object' && 'stdout' in errorWithStdout) {
        return errorWithStdout.stdout || '';
      }
      throw error;
    }
  }

  private parseSnykOutput(output: string): SecurityVulnerability[] {
    try {
      if (!output || output.trim() === '') {
        this.log('Empty Snyk output, nothing to parse');
        return [];
      }

      const snykData = JSON.parse(output);
      const vulnerabilities: SecurityVulnerability[] = [];

      if (!snykData.vulnerabilities) {
        this.log('No vulnerabilities found in Snyk data');
        return vulnerabilities;
      }

      snykData.vulnerabilities.forEach((vuln: any) => {
        const severity = this.mapSnykSeverity(vuln.severity);
        const severityColor = this.getSeverityColor(severity);

        // Format and colorize the vulnerability finding
        console.log(
          `${chalk.cyan('➤')} Found vulnerability in ${chalk.yellow(vuln.packageName)}: ` +
            `${severityColor(`[${severity.toUpperCase()}]`)} ${chalk.bold(vuln.title || '')}`,
        );

        vulnerabilities.push({
          id: `snyk-${vuln.id}`,
          title: `Vulnerable dependency: ${vuln.packageName}`,
          description: vuln.title || `${vuln.packageName} has known security vulnerabilities`,
          severity,
          location: vuln.packageName,
          recommendation: vuln.fixedIn
            ? `Upgrade to ${vuln.packageName}@${vuln.fixedIn[0]}`
            : 'No fix available yet',
          reference: vuln.url || 'https://snyk.io/vuln/',
          category: 'dependency',
        });
      });

      return vulnerabilities;
    } catch (error) {
      if (this.verbose) {
        console.error('Error parsing Snyk output:', error);
      }
      return [];
    }
  }

  private mapNpmSeverity(npmSeverity: string): 'high' | 'medium' | 'low' {
    switch (npmSeverity.toLowerCase()) {
      case 'critical':
      case 'high':
        return 'high';
      case 'moderate':
        return 'medium';
      case 'low':
      default:
        return 'low';
    }
  }

  private mapSnykSeverity(snykSeverity: string): 'high' | 'medium' | 'low' {
    switch (snykSeverity.toLowerCase()) {
      case 'critical':
      case 'high':
        return 'high';
      case 'medium':
        return 'medium';
      case 'low':
      default:
        return 'low';
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
}

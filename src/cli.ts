#!/usr/bin/env node

import { Command } from 'commander';
import chalk from 'chalk';
import { SecurityScanner } from './scanner';
import { formatResults } from './formatter';
import { version } from '../package.json';

const program = new Command();

program
  .name('nestjs-security-scan')
  .description('Security vulnerability scanner for NestJS applications')
  .version(version)
  .option('-p, --path <path>', 'Path to NestJS application', process.cwd())
  .option('-v, --verbose', 'Show detailed output', false)
  .option('--no-deps', 'Skip dependency vulnerabilities check', false)
  .option('--no-code', 'Skip code security analysis', false)
  .option('--no-config', 'Skip configuration analysis', false)
  .option('-o, --output <format>', 'Output format (text, json)', 'text')
  .action(async (options) => {
    try {
      // Always show the starting message
      console.log(chalk.blue('🔍 Starting NestJS Security Check...'));

      const scanner = new SecurityScanner({
        projectPath: options.path,
        verbose: options.verbose,
        checkDependencies: options.deps,
        checkCode: options.code,
        checkConfig: options.config,
      });

      // Always show the scanning message
      console.log(chalk.yellow('🔎 Scanning for security vulnerabilities...'));

      const results = await scanner.scan();

      // Completion message only in verbose mode
      if (options.verbose) {
        console.log(chalk.green('✅ Scan complete!'));
      }

      formatResults(results, options.output, options.verbose);

      if (results.highSeverityCount > 0) {
        process.exit(1);
      }
    } catch (error) {
      console.error(chalk.red('❌ Error during security scan:'), error);
      process.exit(1);
    }
  });

program.parse();

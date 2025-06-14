#!/usr/bin/env node

import { Command } from 'commander';
import { SecurityScanner } from './scanner';
import { formatResults } from './formatter';
import { CONSTANTS } from './constants';
import { SecurityScannerError } from './errors';
import { Logger } from './utils/logger';
import { version } from '../package.json';

interface CliOptions {
  path: string;
  verbose: boolean;
  deps: boolean;
  code: boolean;
  config: boolean;
  output: 'text' | 'json';
}

const logger = Logger.createLogger(false, 'CLI');

const program = new Command();

program
  .name('nestjs-security-scan')
  .description('Security vulnerability scanner for NestJS applications')
  .version(version)
  .option('-p, --path <path>', 'Path to NestJS application', process.cwd())
  .option('-v, --verbose', 'Show detailed output', false)
  .option('--no-deps', 'Skip dependency vulnerabilities check')
  .option('--no-code', 'Skip code security analysis')
  .option('--no-config', 'Skip configuration analysis')
  .option('-o, --output <format>', 'Output format (text, json)', 'text')
  .action(async (options: CliOptions) => {
    try {
      // Update logger level based on verbose flag
      const scanLogger = Logger.createLogger(options.verbose, 'Scanner');

      scanLogger.info('Starting NestJS Security Check...');

      const scanner = new SecurityScanner({
        projectPath: options.path,
        verbose: options.verbose,
        checkDependencies: options.deps,
        checkCode: options.code,
        checkConfig: options.config,
      });

      scanLogger.progress('Scanning for security vulnerabilities...');

      const startTime = Date.now();
      const results = await scanner.scan();
      const endTime = Date.now();

      if (options.verbose) {
        scanLogger.success(`Scan completed in ${endTime - startTime}ms`);
      }

      formatResults(results, options.output, options.verbose);

      // Exit with appropriate code
      if (results.highSeverityCount > 0) {
        process.exit(CONSTANTS.EXIT_CODES.HIGH_SEVERITY_FOUND);
      } else {
        process.exit(CONSTANTS.EXIT_CODES.SUCCESS);
      }
    } catch (error) {
      if (error instanceof SecurityScannerError) {
        logger.error(`Security scan failed: ${error.message}`);
        if (options.verbose) {
          logger.error('Error details:', error);
        }
      } else if (error instanceof Error) {
        logger.error(`Unexpected error: ${error.message}`);
        if (options.verbose) {
          logger.error('Error details:', error);
        }
      } else {
        logger.error('An unknown error occurred during the security scan');
      }

      process.exit(CONSTANTS.EXIT_CODES.ERROR);
    }
  });

// Handle unhandled promise rejections
process.on('unhandledRejection', reason => {
  logger.error('Unhandled promise rejection:', reason as Error);
  process.exit(CONSTANTS.EXIT_CODES.ERROR);
});

// Handle uncaught exceptions
process.on('uncaughtException', error => {
  logger.error('Uncaught exception:', error);
  process.exit(CONSTANTS.EXIT_CODES.ERROR);
});

program.parse();

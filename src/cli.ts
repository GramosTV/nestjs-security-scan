#!/usr/bin/env node

import { Command } from 'commander';
import { SecurityScanner } from './scanner';
import { AiScanner } from './scanners/ai-scanner';
import { formatResults } from './formatter';
import { CONSTANTS } from './constants';
import { SecurityScannerError } from './errors';
import { Logger } from './utils/logger';
import { InteractiveCli } from './utils/interactive-cli';
import { version } from '../package.json';

interface CliOptions {
  path: string;
  verbose: boolean;
  deps: boolean;
  code: boolean;
  config: boolean;
  output: 'text' | 'json';
  interactive: boolean;
  aiModel?: string;
  aiKey?: string;
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
  .option('--no-interactive', 'Skip interactive prompts (use legacy scan)')
  .option(
    '--ai-model <model>',
    'AI model for AI scan (gemini-1.5-pro, gemini-1.5-flash, gemini-pro)',
  )
  .option('--ai-key <key>', 'Google AI API key for AI scan')
  .action(async (options: CliOptions) => {
    try {
      const logger = Logger.createLogger(options.verbose, 'CLI');
      const interactive = new InteractiveCli(options.verbose);

      let scanType: 'legacy' | 'ai' = 'legacy';
      let aiConfig: { model: string; apiKey: string } | null = null;

      // Determine scan type
      if (options.interactive !== false && !options.aiModel && !options.aiKey) {
        // Interactive mode - ask user
        const choice = await interactive.promptScanType();
        scanType = choice.type;

        if (scanType === 'ai') {
          interactive.displayAiScanInfo();
          interactive.displayApiKeyHelp();
          aiConfig = await interactive.promptAiConfiguration();

          const confirmed = await interactive.confirmAiScan(options.path, aiConfig.model);
          if (!confirmed) {
            logger.info('AI scan cancelled by user');
            process.exit(CONSTANTS.EXIT_CODES.SUCCESS);
          }
        }
      } else if (options.aiModel && options.aiKey) {
        // Non-interactive AI mode
        scanType = 'ai';
        aiConfig = {
          model: options.aiModel,
          apiKey: options.aiKey,
        };
      }

      const startTime = Date.now();
      let results;

      if (scanType === 'ai' && aiConfig) {
        // AI-powered scan
        logger.info('🤖 Starting AI-powered security scan...');

        const aiScanner = new AiScanner({
          projectPath: options.path,
          verbose: options.verbose,
          model: aiConfig.model,
          apiKey: aiConfig.apiKey,
        });

        const aiResults = await aiScanner.scan();

        // Convert AI results to ScanResult format
        results = {
          vulnerabilities: aiResults.vulnerabilities,
          totalVulnerabilities: aiResults.vulnerabilities.length,
          highSeverityCount: aiResults.vulnerabilities.filter(
            v => v.severity === CONSTANTS.SEVERITY_LEVELS.HIGH,
          ).length,
          mediumSeverityCount: aiResults.vulnerabilities.filter(
            v => v.severity === CONSTANTS.SEVERITY_LEVELS.MEDIUM,
          ).length,
          lowSeverityCount: aiResults.vulnerabilities.filter(
            v => v.severity === CONSTANTS.SEVERITY_LEVELS.LOW,
          ).length,
          dependencyVulnerabilities: aiResults.vulnerabilities.filter(
            v => v.category === CONSTANTS.SCAN_CATEGORIES.DEPENDENCY,
          ),
          codeVulnerabilities: aiResults.vulnerabilities.filter(
            v => v.category === CONSTANTS.SCAN_CATEGORIES.CODE,
          ),
          configVulnerabilities: aiResults.vulnerabilities.filter(
            v => v.category === CONSTANTS.SCAN_CATEGORIES.CONFIGURATION,
          ),
          scannedFiles: aiResults.scannedFiles,
          scanDuration: Date.now() - startTime,
          timestamp: new Date(),
        };
      } else {
        // Legacy scan
        logger.info('🔍 Starting traditional security scan...');

        const scanner = new SecurityScanner({
          projectPath: options.path,
          verbose: options.verbose,
          checkDependencies: options.deps,
          checkCode: options.code,
          checkConfig: options.config,
        });

        results = await scanner.scan();

        // Add timing information
        results = {
          ...results,
          scanDuration: Date.now() - startTime,
          timestamp: new Date(),
        };
      }

      const endTime = Date.now();

      if (options.verbose) {
        logger.success(`Scan completed in ${endTime - startTime}ms`);
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

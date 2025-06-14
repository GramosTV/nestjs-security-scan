import chalk from 'chalk';
import { ScanResult, SecurityVulnerability, VulnerabilitySeverity, OutputFormat } from './types';
import { CONSTANTS } from './constants';

type ChalkFunction = chalk.Chalk;

const getSeverityColor = (severity: VulnerabilitySeverity): ChalkFunction => {
  switch (severity) {
    case CONSTANTS.SEVERITY_LEVELS.HIGH:
      return chalk.red.bold;
    case CONSTANTS.SEVERITY_LEVELS.MEDIUM:
      return chalk.yellow.bold;
    case CONSTANTS.SEVERITY_LEVELS.LOW:
      return chalk.blue.bold;
    default:
      return chalk.white;
  }
};

const formatTextOutput = (result: ScanResult, verbose: boolean = false): void => {
  console.log('\n' + chalk.bold.underline('SECURITY SCAN SUMMARY'));
  console.log('─'.repeat(80));

  console.log(
    `Total Vulnerabilities: ${result.totalVulnerabilities} (` +
      `${chalk.red.bold(result.highSeverityCount)} High, ` +
      `${chalk.yellow.bold(result.mediumSeverityCount)} Medium, ` +
      `${chalk.blue.bold(result.lowSeverityCount)} Low)`,
  );

  if (result.scanDuration) {
    console.log(`Scan Duration: ${result.scanDuration}ms`);
  }

  console.log('─'.repeat(80));

  if (result.vulnerabilities.length === 0) {
    console.log(chalk.green('✅ No vulnerabilities found!'));
  } else {
    // Group vulnerabilities by category
    const groupedVulnerabilities = {
      [CONSTANTS.SCAN_CATEGORIES.DEPENDENCY]: result.dependencyVulnerabilities,
      [CONSTANTS.SCAN_CATEGORIES.CODE]: result.codeVulnerabilities,
      [CONSTANTS.SCAN_CATEGORIES.CONFIGURATION]: result.configVulnerabilities,
    };

    // Print vulnerabilities by category
    for (const [category, vulnerabilities] of Object.entries(groupedVulnerabilities)) {
      if (vulnerabilities.length > 0) {
        console.log(chalk.bold(`\n${category.toUpperCase()} VULNERABILITIES`));
        console.log('─'.repeat(80));

        vulnerabilities.forEach((vulnerability, index) => {
          formatVulnerability(vulnerability, index + 1);
        });
      }
    }
  }

  // Only print scanned files if verbose mode is enabled
  if (verbose && result.scannedFiles?.length > 0) {
    formatScannedFiles(result.scannedFiles);
  }
};

const formatVulnerability = (vulnerability: SecurityVulnerability, index: number): void => {
  const severityColor = getSeverityColor(vulnerability.severity);

  console.log(`${index}. ${chalk.bold(vulnerability.title)}`);
  console.log(
    `   ${severityColor(`[${vulnerability.severity.toUpperCase()}]`)} ${vulnerability.description}`,
  );

  if (vulnerability.location) {
    console.log(
      `   ${chalk.gray('Location:')} ${vulnerability.location}${
        vulnerability.line ? `:${vulnerability.line}` : ''
      }`,
    );
  }

  if (vulnerability.code) {
    console.log(`   ${chalk.gray('Code:')} ${chalk.italic(vulnerability.code)}`);
  }

  console.log(`   ${chalk.gray('Recommendation:')} ${vulnerability.recommendation}`);

  if (vulnerability.reference) {
    console.log(`   ${chalk.gray('Reference:')} ${vulnerability.reference}`);
  }

  console.log('');
};

const formatScannedFiles = (scannedFiles: readonly string[]): void => {
  console.log(chalk.bold('\nSCANNED FILES'));
  console.log('─'.repeat(80));
  console.log(`Total files scanned: ${chalk.cyan(scannedFiles.length)}`);
  console.log('');

  // Group files by directory for better organization
  const filesByDirectory: Record<string, string[]> = {};
  scannedFiles.forEach(file => {
    const directory = file.includes('/') ? file.substring(0, file.lastIndexOf('/')) : '';
    if (!filesByDirectory[directory]) {
      filesByDirectory[directory] = [];
    }
    const filename = file.includes('/') ? file.substring(file.lastIndexOf('/') + 1) : file;
    filesByDirectory[directory].push(filename);
  });

  // Print files by directory
  const directories = Object.keys(filesByDirectory).sort();
  directories.forEach(directory => {
    if (directory) {
      console.log(chalk.bold(`  ${directory}/`));
      filesByDirectory[directory].forEach(filename => {
        console.log(`    ${filename}`);
      });
    } else {
      console.log(chalk.bold('  Root files:'));
      filesByDirectory[directory].forEach(filename => {
        console.log(`    ${filename}`);
      });
    }
    console.log('');
  });
};

const formatJsonOutput = (result: ScanResult): void => {
  const jsonOutput = {
    summary: {
      totalVulnerabilities: result.totalVulnerabilities,
      highSeverityCount: result.highSeverityCount,
      mediumSeverityCount: result.mediumSeverityCount,
      lowSeverityCount: result.lowSeverityCount,
      scanDuration: result.scanDuration,
      timestamp: result.timestamp,
      scannedFilesCount: result.scannedFiles.length,
    },
    vulnerabilities: result.vulnerabilities,
    scannedFiles: result.scannedFiles,
  };

  console.log(JSON.stringify(jsonOutput, null, 2));
};

export const formatResults = (
  result: ScanResult,
  format: OutputFormat = CONSTANTS.OUTPUT_FORMATS.TEXT,
  verbose: boolean = false,
): void => {
  switch (format) {
    case CONSTANTS.OUTPUT_FORMATS.JSON:
      formatJsonOutput(result);
      break;
    case CONSTANTS.OUTPUT_FORMATS.TEXT:
    default:
      formatTextOutput(result, verbose);
      break;
  }
};

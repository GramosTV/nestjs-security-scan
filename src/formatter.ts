import chalk from 'chalk';
import { ScanResult, SecurityVulnerability, VulnerabilitySeverity } from './types';

// Fix TypeScript error by defining the ChalkFunction type
type ChalkFunction = chalk.Chalk;

const getSeverityColor = (severity: VulnerabilitySeverity): ChalkFunction => {
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
};

const formatTextOutput = (result: ScanResult, verbose: boolean = false): void => {
  // Always show the summary and vulnerabilities
  console.log('\n' + chalk.bold.underline('SECURITY SCAN SUMMARY'));
  console.log('─'.repeat(80));

  console.log(
    `Total Vulnerabilities: ${result.totalVulnerabilities} (` +
      `${chalk.red.bold(result.highSeverityCount)} High, ` +
      `${chalk.yellow.bold(result.mediumSeverityCount)} Medium, ` +
      `${chalk.blue.bold(result.lowSeverityCount)} Low)`
  );

  console.log('─'.repeat(80));

  if (result.vulnerabilities.length === 0) {
    console.log(chalk.green('✅ No vulnerabilities found!'));
  } else {
    // Group vulnerabilities by category
    const groupedVulnerabilities = {
      dependency: result.dependencyVulnerabilities,
      code: result.codeVulnerabilities,
      configuration: result.configVulnerabilities,
    };

    // Print vulnerabilities by category
    for (const [category, vulnerabilities] of Object.entries(groupedVulnerabilities)) {
      if (vulnerabilities.length > 0) {
        console.log(chalk.bold(`\n${category.toUpperCase()} VULNERABILITIES`));
        console.log('─'.repeat(80));

        vulnerabilities.forEach((vulnerability, index) => {
          const severityColor = getSeverityColor(vulnerability.severity);

          console.log(`${index + 1}. ${chalk.bold(vulnerability.title)}`);
          console.log(`   ${severityColor(`[${vulnerability.severity.toUpperCase()}]`)} ${vulnerability.description}`);

          if (vulnerability.location) {
            console.log(
              `   ${chalk.gray('Location:')} ${vulnerability.location}${
                vulnerability.line ? `:${vulnerability.line}` : ''
              }`
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
        });
      }
    }
  }

  // Only print scanned files if verbose mode is enabled
  if (verbose && result.scannedFiles && result.scannedFiles.length > 0) {
    console.log(chalk.bold('\nSCANNED FILES'));
    console.log('─'.repeat(80));
    console.log(`Total files scanned: ${chalk.cyan(result.scannedFiles.length)}`);
    console.log('');

    // Group files by directory for better organization
    const filesByDirectory: Record<string, string[]> = {};
    result.scannedFiles.forEach((file) => {
      const directory = file.includes('/') ? file.substring(0, file.lastIndexOf('/')) : '';
      if (!filesByDirectory[directory]) {
        filesByDirectory[directory] = [];
      }
      const filename = file.includes('/') ? file.substring(file.lastIndexOf('/') + 1) : file;
      filesByDirectory[directory].push(filename);
    });

    // Print files by directory
    const directories = Object.keys(filesByDirectory).sort();
    directories.forEach((directory) => {
      if (directory) {
        console.log(chalk.cyan(`${directory}/`));
      }
      filesByDirectory[directory].sort().forEach((file) => {
        console.log(directory ? `  ${file}` : file);
      });
    });
  }
};

const formatJsonOutput = (result: ScanResult): void => {
  console.log(JSON.stringify(result, null, 2));
};

export const formatResults = (result: ScanResult, format: string, verbose: boolean = false): void => {
  switch (format.toLowerCase()) {
    case 'json':
      formatJsonOutput(result);
      break;
    case 'text':
    default:
      formatTextOutput(result, verbose);
      break;
  }
};

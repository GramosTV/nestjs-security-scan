import { CONSTANTS } from './constants';

export interface ScanOptions {
  readonly projectPath: string;
  readonly verbose?: boolean;
  readonly checkDependencies?: boolean;
  readonly checkCode?: boolean;
  readonly checkConfig?: boolean;
}

export type VulnerabilitySeverity =
  (typeof CONSTANTS.SEVERITY_LEVELS)[keyof typeof CONSTANTS.SEVERITY_LEVELS];
export type ScanCategory =
  (typeof CONSTANTS.SCAN_CATEGORIES)[keyof typeof CONSTANTS.SCAN_CATEGORIES];
export type OutputFormat = (typeof CONSTANTS.OUTPUT_FORMATS)[keyof typeof CONSTANTS.OUTPUT_FORMATS];

export interface SecurityVulnerability {
  readonly id: string;
  readonly title: string;
  readonly description: string;
  readonly severity: VulnerabilitySeverity;
  readonly location?: string; // File or package containing the vulnerability
  readonly line?: number; // Line number where vulnerability was found (for code vulnerabilities)
  readonly column?: number; // Column number where vulnerability was found (for code vulnerabilities)
  readonly code?: string; // The vulnerable code snippet
  readonly recommendation: string; // How to fix the vulnerability
  readonly reference?: string; // URL or other reference to learn more about this vulnerability
  readonly category: ScanCategory;
}

export interface ScanResult {
  readonly vulnerabilities: readonly SecurityVulnerability[];
  readonly totalVulnerabilities: number;
  readonly highSeverityCount: number;
  readonly mediumSeverityCount: number;
  readonly lowSeverityCount: number;
  readonly dependencyVulnerabilities: readonly SecurityVulnerability[];
  readonly codeVulnerabilities: readonly SecurityVulnerability[];
  readonly configVulnerabilities: readonly SecurityVulnerability[];
  readonly scannedFiles: readonly string[]; // List of all files examined during the scan
  readonly scanDuration?: number; // Scan duration in milliseconds
  readonly timestamp?: Date; // When the scan was performed
}

// Interface for scanner classes
export interface Scanner {
  scan(): Promise<ScannerResult>;
}

export interface ScannerResult {
  readonly vulnerabilities: SecurityVulnerability[];
  readonly scannedFiles: string[];
}

// Security pattern interface for code analysis
export interface SecurityPattern {
  readonly regex: RegExp;
  readonly severity: VulnerabilitySeverity;
  readonly title: string;
  readonly description: string;
  readonly recommendation: string;
  readonly reference?: string;
  readonly category?: ScanCategory;
}

// Package vulnerability interface for dependency scanning
export interface PackageVulnerability {
  readonly name: string;
  readonly version: string;
  readonly severity: VulnerabilitySeverity;
  readonly title: string;
  readonly description: string;
  readonly recommendation: string;
  readonly reference?: string;
  readonly cwe?: string[];
  readonly cvss?: number;
}

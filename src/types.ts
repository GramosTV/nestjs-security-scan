export interface ScanOptions {
  projectPath: string;
  verbose?: boolean;
  checkDependencies?: boolean;
  checkCode?: boolean;
  checkConfig?: boolean;
}

export type VulnerabilitySeverity = 'high' | 'medium' | 'low';

export interface SecurityVulnerability {
  id: string;
  title: string;
  description: string;
  severity: VulnerabilitySeverity;
  location?: string; // File or package containing the vulnerability
  line?: number; // Line number where vulnerability was found (for code vulnerabilities)
  column?: number; // Column number where vulnerability was found (for code vulnerabilities)
  code?: string; // The vulnerable code snippet
  recommendation: string; // How to fix the vulnerability
  reference?: string; // URL or other reference to learn more about this vulnerability
  category: 'dependency' | 'code' | 'configuration';
}

export interface ScanResult {
  vulnerabilities: SecurityVulnerability[];
  totalVulnerabilities: number;
  highSeverityCount: number;
  mediumSeverityCount: number;
  lowSeverityCount: number;
  dependencyVulnerabilities: SecurityVulnerability[];
  codeVulnerabilities: SecurityVulnerability[];
  configVulnerabilities: SecurityVulnerability[];
  scannedFiles: string[]; // List of all files examined during the scan
}

// Interface for scanner classes
export interface Scanner {
  scan(): Promise<{ vulnerabilities: SecurityVulnerability[]; scannedFiles: string[] }>;
}

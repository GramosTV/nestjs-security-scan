/**
 * Custom error classes for the security scanner
 */

export class SecurityScannerError extends Error {
  constructor(
    message: string,
    public readonly code: string,
  ) {
    super(message);
    this.name = 'SecurityScannerError';
    Error.captureStackTrace(this, this.constructor);
  }
}

export class ProjectValidationError extends SecurityScannerError {
  constructor(message: string) {
    super(message, 'PROJECT_VALIDATION_ERROR');
    this.name = 'ProjectValidationError';
  }
}

export class FileReadError extends SecurityScannerError {
  constructor(
    message: string,
    public readonly filePath: string,
  ) {
    super(message, 'FILE_READ_ERROR');
    this.name = 'FileReadError';
  }
}

export class DependencyScanError extends SecurityScannerError {
  constructor(message: string) {
    super(message, 'DEPENDENCY_SCAN_ERROR');
    this.name = 'DependencyScanError';
  }
}

export class ConfigurationError extends SecurityScannerError {
  constructor(message: string) {
    super(message, 'CONFIGURATION_ERROR');
    this.name = 'ConfigurationError';
  }
}

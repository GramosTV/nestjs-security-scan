/**
 * Constants used throughout the security scanner
 */

export const CONSTANTS = {
  EXIT_CODES: {
    SUCCESS: 0,
    HIGH_SEVERITY_FOUND: 1,
    ERROR: 2,
  } as const,

  FILE_EXTENSIONS: {
    TYPESCRIPT: ['.ts'],
    JAVASCRIPT: ['.js'],
    SOURCE_FILES: ['.ts', '.js'],
    CONFIG_FILES: ['.json', '.yml', '.yaml', '.env'],
  } as const,

  DIRECTORIES: {
    EXCLUDED: ['node_modules', 'dist', 'test-nestjs-security', '.git', 'coverage'],
    SOURCE: 'src',
  } as const,

  PATTERNS: {
    PACKAGE_FILES: '{package.json,package-lock.json,yarn.lock}',
    ENV_FILES: '**/.env*',
    CONFIG_FILES: '**/config/**/*.{json,yml,yaml}',
  } as const,

  SEVERITY_LEVELS: {
    HIGH: 'high',
    MEDIUM: 'medium',
    LOW: 'low',
  } as const,

  SCAN_CATEGORIES: {
    DEPENDENCY: 'dependency',
    CODE: 'code',
    CONFIGURATION: 'configuration',
  } as const,

  OUTPUT_FORMATS: {
    TEXT: 'text',
    JSON: 'json',
  } as const,
} as const;

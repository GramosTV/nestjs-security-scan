import * as fs from 'fs-extra';
import * as path from 'path';
import * as glob from 'glob';
import { CONSTANTS } from '../constants';
import { FileReadError } from '../errors';
import { Logger } from './logger';

export interface FileSearchOptions {
  extensions?: readonly string[];
  excludeDirectories?: readonly string[];
  includePattern?: string;
  maxDepth?: number;
}

export class FileUtils {
  private static readonly logger = Logger.createLogger(false, 'FileUtils');

  /**
   * Checks if a file exists and is readable
   */
  static async isReadableFile(filePath: string): Promise<boolean> {
    try {
      await fs.access(filePath, fs.constants.R_OK);
      const stats = await fs.stat(filePath);
      return stats.isFile();
    } catch {
      return false;
    }
  }

  /**
   * Checks if a directory exists and is readable
   */
  static async isReadableDirectory(dirPath: string): Promise<boolean> {
    try {
      await fs.access(dirPath, fs.constants.R_OK);
      const stats = await fs.stat(dirPath);
      return stats.isDirectory();
    } catch {
      return false;
    }
  }

  /**
   * Safely reads a file with proper error handling
   */
  static async readFile(filePath: string): Promise<string> {
    try {
      if (!(await this.isReadableFile(filePath))) {
        throw new FileReadError(`File is not readable: ${filePath}`, filePath);
      }
      return await fs.readFile(filePath, 'utf8');
    } catch (error) {
      if (error instanceof FileReadError) {
        throw error;
      }
      throw new FileReadError(`Failed to read file: ${filePath}`, filePath);
    }
  }

  /**
   * Safely reads and parses a JSON file
   */
  static async readJsonFile<T = any>(filePath: string): Promise<T> {
    try {
      const content = await this.readFile(filePath);
      return JSON.parse(content) as T;
    } catch (error) {
      if (error instanceof FileReadError) {
        throw error;
      }
      throw new FileReadError(`Failed to parse JSON file: ${filePath}`, filePath);
    }
  }

  /**
   * Finds files matching the given pattern with proper error handling
   */
  static async findFiles(
    baseDir: string,
    pattern: string,
    options: FileSearchOptions = {},
  ): Promise<string[]> {
    const {
      extensions = CONSTANTS.FILE_EXTENSIONS.SOURCE_FILES,
      excludeDirectories = CONSTANTS.DIRECTORIES.EXCLUDED,
    } = options;

    try {
      const normalizedPattern = path.posix.join(baseDir.replace(/\\/g, '/'), pattern);

      const files = glob.sync(normalizedPattern, {
        ignore: excludeDirectories.map(dir => `**/${dir}/**`),
        absolute: true,
        nodir: true,
      }); // Filter by extensions if specified
      const filteredFiles =
        extensions.length > 0
          ? files.filter(file => extensions.includes(path.extname(file) as any))
          : files;

      this.logger.debug(`Found ${filteredFiles.length} files matching pattern: ${pattern}`);
      return filteredFiles;
    } catch (error) {
      this.logger.error(`Error finding files with pattern ${pattern}:`, error as Error);
      return [];
    }
  }

  /**
   * Recursively scans a directory for files with specified extensions
   */
  static async scanDirectory(dirPath: string, options: FileSearchOptions = {}): Promise<string[]> {
    const {
      extensions = CONSTANTS.FILE_EXTENSIONS.SOURCE_FILES,
      excludeDirectories = CONSTANTS.DIRECTORIES.EXCLUDED,
    } = options;

    if (!(await this.isReadableDirectory(dirPath))) {
      this.logger.warn(`Directory is not readable: ${dirPath}`);
      return [];
    }

    const pattern =
      extensions.length === 1
        ? `**/*${extensions[0]}`
        : `**/*.{${extensions.map(ext => ext.slice(1)).join(',')}}`;

    return this.findFiles(dirPath, pattern, { excludeDirectories: [...excludeDirectories] });
  }

  /**
   * Gets the relative path from a base directory
   */
  static getRelativePath(basePath: string, filePath: string): string {
    return path.relative(basePath, filePath).replace(/\\/g, '/');
  }

  /**
   * Normalizes path separators for cross-platform compatibility
   */
  static normalizePath(filePath: string): string {
    return filePath.replace(/\\/g, '/');
  }

  /**
   * Checks if a path is within a directory (prevents path traversal)
   */
  static isPathWithinDirectory(basePath: string, targetPath: string): boolean {
    const normalizedBase = path.resolve(basePath);
    const normalizedTarget = path.resolve(targetPath);
    return normalizedTarget.startsWith(normalizedBase);
  }
}

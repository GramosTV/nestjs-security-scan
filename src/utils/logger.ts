import chalk from 'chalk';

export enum LogLevel {
  ERROR = 0,
  WARN = 1,
  INFO = 2,
  DEBUG = 3,
}

export interface LoggerOptions {
  level: LogLevel;
  prefix?: string;
}

export class Logger {
  private readonly level: LogLevel;
  private readonly prefix: string;

  constructor(options: LoggerOptions = { level: LogLevel.INFO }) {
    this.level = options.level;
    this.prefix = options.prefix ? `[${options.prefix}] ` : '';
  }

  error(message: string, error?: Error): void {
    if (this.level >= LogLevel.ERROR) {
      console.error(chalk.red(`${this.prefix}❌ ${message}`));
      if (error && this.level >= LogLevel.DEBUG) {
        console.error(chalk.red(error.stack || error.message));
      }
    }
  }

  warn(message: string): void {
    if (this.level >= LogLevel.WARN) {
      console.warn(chalk.yellow(`${this.prefix}⚠️  ${message}`));
    }
  }

  info(message: string): void {
    if (this.level >= LogLevel.INFO) {
      console.log(chalk.blue(`${this.prefix}ℹ️  ${message}`));
    }
  }

  success(message: string): void {
    if (this.level >= LogLevel.INFO) {
      console.log(chalk.green(`${this.prefix}✅ ${message}`));
    }
  }

  debug(message: string): void {
    if (this.level >= LogLevel.DEBUG) {
      console.log(chalk.gray(`${this.prefix}🐛 ${message}`));
    }
  }

  progress(message: string): void {
    if (this.level >= LogLevel.INFO) {
      console.log(chalk.cyan(`${this.prefix}🔄 ${message}`));
    }
  }

  static createLogger(verbose: boolean, prefix?: string): Logger {
    return new Logger({
      level: verbose ? LogLevel.DEBUG : LogLevel.INFO,
      prefix,
    });
  }
}

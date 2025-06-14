import { GoogleGenAI } from '@google/genai';
import {
  SecurityVulnerability,
  Scanner,
  ScannerResult,
  VulnerabilitySeverity,
  ScanCategory,
} from '../types';
import { FileUtils } from '../utils/file-utils';
import { Logger } from '../utils/logger';
import { CONSTANTS } from '../constants';
import * as path from 'path';

export interface AiScanOptions {
  projectPath: string;
  verbose: boolean;
  model: string;
  apiKey: string;
}

export class AiScanner implements Scanner {
  private readonly projectPath: string;
  private readonly verbose: boolean;
  private readonly genAI: GoogleGenAI;
  private readonly modelName: string;
  private readonly logger: Logger;

  constructor(options: AiScanOptions) {
    this.projectPath = path.resolve(options.projectPath);
    this.verbose = options.verbose;
    this.modelName = options.model;
    this.logger = Logger.createLogger(this.verbose, 'AI-Scanner');

    this.genAI = new GoogleGenAI({ apiKey: options.apiKey });
  }

  async scan(): Promise<ScannerResult> {
    this.logger.info('🤖 Starting AI-powered security analysis...');

    const vulnerabilities: SecurityVulnerability[] = [];
    const scannedFiles: string[] = [];

    try {
      // Find relevant NestJS files
      const files = await this.findRelevantFiles();
      this.logger.info(`Found ${files.length} relevant files for AI analysis`);

      // Analyze files in batches to avoid API limits
      const batchSize = 5;
      for (let i = 0; i < files.length; i += batchSize) {
        const batch = files.slice(i, i + batchSize);
        this.logger.progress(
          `Analyzing batch ${Math.floor(i / batchSize) + 1}/${Math.ceil(files.length / batchSize)}`,
        );

        const batchVulnerabilities = await this.analyzeBatch(batch);
        vulnerabilities.push(...batchVulnerabilities);
        scannedFiles.push(...batch.map(f => FileUtils.getRelativePath(this.projectPath, f)));
      }

      // Perform holistic analysis
      const holisticVulnerabilities = await this.performHolisticAnalysis(files);
      vulnerabilities.push(...holisticVulnerabilities);

      this.logger.success(
        `AI analysis completed. Found ${vulnerabilities.length} potential issues`,
      );

      return {
        vulnerabilities,
        scannedFiles,
      };
    } catch (error) {
      this.logger.error('AI analysis failed:', error as Error);
      throw error;
    }
  }

  private async findRelevantFiles(): Promise<string[]> {
    const patterns = [
      '**/*.ts',
      '**/*.js',
      '**/package.json',
      '**/*.env.example',
      '**/docker-compose.yml',
      '**/Dockerfile',
    ];

    const excludePatterns = [
      '**/node_modules/**',
      '**/dist/**',
      '**/*.spec.ts',
      '**/*.test.ts',
      '**/test/**',
      '**/__tests__/**',
      '**/*.d.ts',
      '**/coverage/**',
      '**/.git/**',
    ];
    // eslint-disable-next-line prefer-const
    let allFiles: string[] = [];

    for (const pattern of patterns) {
      const files = await FileUtils.findFiles(this.projectPath, pattern, {
        excludeDirectories: excludePatterns,
      });
      allFiles.push(...files);
    }

    // Remove duplicates and sort
    return [...new Set(allFiles)].sort();
  }

  private async analyzeBatch(files: string[]): Promise<SecurityVulnerability[]> {
    const vulnerabilities: SecurityVulnerability[] = [];

    for (const filePath of files) {
      try {
        const fileVulns = await this.analyzeFile(filePath);
        vulnerabilities.push(...fileVulns);
      } catch (error) {
        this.logger.error(`Failed to analyze ${filePath}:`, error as Error);
      }
    }

    return vulnerabilities;
  }
  private async analyzeFile(filePath: string): Promise<SecurityVulnerability[]> {
    const relativePath = FileUtils.getRelativePath(this.projectPath, filePath);
    this.logger.debug(`Analyzing file: ${relativePath}`);

    try {
      const content = await FileUtils.readFile(filePath);
      const fileName = path.basename(filePath);

      const prompt = this.buildSecurityAnalysisPrompt(fileName, relativePath, content);
      const result = await this.genAI.models.generateContent({
        model: this.modelName,
        contents: prompt,
      });
      const analysisText = result.text || '';

      return this.parseAiResponse(analysisText, relativePath);
    } catch (error) {
      this.logger.error(`Error analyzing ${relativePath}:`, error as Error);
      return [];
    }
  }

  private buildSecurityAnalysisPrompt(
    fileName: string,
    relativePath: string,
    content: string,
  ): string {
    return `
You are a security expert analyzing a NestJS application file for vulnerabilities. 

File: ${fileName}
Path: ${relativePath}
Content:
\`\`\`
${content}
\`\`\`

Please analyze this file for security vulnerabilities and provide your findings in the following JSON format:
{
  "vulnerabilities": [
    {
      "title": "Brief title of the vulnerability",
      "description": "Detailed description of the security issue",
      "severity": "high|medium|low",
      "line": 0,
      "code": "vulnerable code snippet",
      "recommendation": "How to fix this vulnerability",
      "category": "authentication|authorization|input-validation|cryptography|configuration|injection|data-exposure|rate-limiting|cors|other"
    }
  ]
}

Focus on:
1. Authentication and authorization issues
2. Input validation vulnerabilities
3. SQL/NoSQL injection risks
4. XSS vulnerabilities
5. Insecure configurations
6. Cryptographic issues
7. Data exposure risks
8. Rate limiting issues
9. CORS misconfigurations
10. Business logic flaws
11. API security issues specific to NestJS

Only include real security vulnerabilities. Do not include code style or performance issues.
If no vulnerabilities are found, return an empty vulnerabilities array.
Provide specific line numbers when possible and include the vulnerable code snippet.
`;
  }
  private async performHolisticAnalysis(files: string[]): Promise<SecurityVulnerability[]> {
    this.logger.info('🔍 Performing holistic security analysis...');

    try {
      // Analyze architecture and configuration
      const configFiles = files.filter(
        f =>
          f.includes('package.json') ||
          f.includes('.env') ||
          f.includes('docker') ||
          f.includes('main.ts') ||
          f.includes('app.module.ts'),
      );

      if (configFiles.length === 0) {
        return [];
      }

      const configContents = await Promise.all(
        configFiles.map(async f => ({
          path: FileUtils.getRelativePath(this.projectPath, f),
          content: await FileUtils.readFile(f),
        })),
      );

      const prompt = this.buildHolisticAnalysisPrompt(configContents);
      const result = await this.genAI.models.generateContent({
        model: this.modelName,
        contents: prompt,
      });
      const analysisText = result.text || '';

      return this.parseAiResponse(analysisText, 'Application Architecture');
    } catch (error) {
      this.logger.error('Holistic analysis failed:', error as Error);
      return [];
    }
  }

  private buildHolisticAnalysisPrompt(configFiles: { path: string; content: string }[]): string {
    const fileContents = configFiles
      .map(f => `File: ${f.path}\n\`\`\`\n${f.content}\n\`\`\``)
      .join('\n\n');

    return `
You are a security expert performing a holistic security analysis of a NestJS application architecture.

Configuration Files:
${fileContents}

Please analyze the overall application security posture and identify systemic vulnerabilities in the following JSON format:
{
  "vulnerabilities": [
    {
      "title": "Brief title of the vulnerability",
      "description": "Detailed description of the architectural security issue",
      "severity": "high|medium|low",
      "line": 0,
      "code": "relevant configuration or code",
      "recommendation": "How to fix this architectural vulnerability",
      "category": "configuration|architecture|deployment|dependencies|other"
    }
  ]
}

Focus on:
1. Missing security middleware (helmet, CORS, rate limiting)
2. Insecure dependency configurations
3. Environment variable security
4. Database connection security
5. Authentication/authorization architecture flaws
6. Logging and monitoring security
7. Docker/deployment security issues
8. API versioning and documentation security
9. Overall application security architecture

Only include real security vulnerabilities at the architectural level.
If no vulnerabilities are found, return an empty vulnerabilities array.
`;
  }

  private parseAiResponse(response: string, location: string): SecurityVulnerability[] {
    try {
      // Extract JSON from the response (AI might include extra text)
      const jsonMatch = response.match(/\{[\s\S]*\}/);
      if (!jsonMatch) {
        this.logger.warn(`No JSON found in AI response for ${location}`);
        return [];
      }

      const parsed = JSON.parse(jsonMatch[0]);
      const vulnerabilities: SecurityVulnerability[] = [];

      if (parsed.vulnerabilities && Array.isArray(parsed.vulnerabilities)) {
        for (const vuln of parsed.vulnerabilities) {
          vulnerabilities.push({
            id: `ai-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
            title: vuln.title || 'AI-detected vulnerability',
            description: vuln.description || 'Security issue detected by AI analysis',
            severity: this.mapSeverity(vuln.severity),
            location: location,
            line: vuln.line || undefined,
            code: vuln.code || undefined,
            recommendation: vuln.recommendation || 'Review and address this security concern',
            category: this.mapCategory(vuln.category),
          });
        }
      }

      return vulnerabilities;
    } catch (error) {
      this.logger.error(`Failed to parse AI response for ${location}:`, error as Error);
      return [];
    }
  }

  private mapSeverity(severity: string): VulnerabilitySeverity {
    const normalizedSeverity = severity?.toLowerCase();
    switch (normalizedSeverity) {
      case 'high':
        return CONSTANTS.SEVERITY_LEVELS.HIGH;
      case 'medium':
        return CONSTANTS.SEVERITY_LEVELS.MEDIUM;
      case 'low':
        return CONSTANTS.SEVERITY_LEVELS.LOW;
      default:
        return CONSTANTS.SEVERITY_LEVELS.MEDIUM;
    }
  }
  private mapCategory(category: string): ScanCategory {
    const categoryMap: Record<string, ScanCategory> = {
      authentication: CONSTANTS.SCAN_CATEGORIES.CODE,
      authorization: CONSTANTS.SCAN_CATEGORIES.CODE,
      'input-validation': CONSTANTS.SCAN_CATEGORIES.CODE,
      cryptography: CONSTANTS.SCAN_CATEGORIES.CODE,
      configuration: CONSTANTS.SCAN_CATEGORIES.CONFIGURATION,
      injection: CONSTANTS.SCAN_CATEGORIES.CODE,
      'data-exposure': CONSTANTS.SCAN_CATEGORIES.CODE,
      'rate-limiting': CONSTANTS.SCAN_CATEGORIES.CODE,
      cors: CONSTANTS.SCAN_CATEGORIES.CONFIGURATION,
      architecture: CONSTANTS.SCAN_CATEGORIES.CONFIGURATION,
      deployment: CONSTANTS.SCAN_CATEGORIES.CONFIGURATION,
      dependencies: CONSTANTS.SCAN_CATEGORIES.DEPENDENCY,
    };

    return categoryMap[category?.toLowerCase()] || CONSTANTS.SCAN_CATEGORIES.CODE;
  }
}

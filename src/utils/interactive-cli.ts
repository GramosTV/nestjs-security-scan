import inquirer from 'inquirer';
import { GoogleGenAI } from '@google/genai';
import { Logger } from './logger';

export interface ScanChoice {
  type: 'legacy' | 'ai';
}

export interface AiScanConfig {
  model: string;
  apiKey: string;
}

interface AvailableModel {
  name: string;
  displayName: string;
  description?: string;
}

export class InteractiveCli {
  private readonly logger: Logger;

  constructor(verbose: boolean = false) {
    this.logger = Logger.createLogger(verbose, 'Interactive');
  }

  async promptScanType(): Promise<ScanChoice> {
    this.logger.info('🚀 Welcome to NestJS Security Scanner');

    const choices = [
      {
        name: '🔍 Legacy Scan - Traditional rule-based security analysis',
        value: 'legacy',
        short: 'Legacy Scan',
      },
      {
        name: '🤖 AI Scan - Intelligent analysis powered by Google Gemini',
        value: 'ai',
        short: 'AI Scan',
      },
    ];

    const answers = await inquirer.prompt([
      {
        type: 'list',
        name: 'scanType',
        message: 'Choose your scanning method:',
        choices,
        default: 'legacy',
      },
    ]);

    return { type: answers.scanType };
  }
  async promptAiConfiguration(): Promise<AiScanConfig> {
    this.logger.info('🤖 Configuring AI-powered security scan');

    // First get API key
    const apiKeyAnswer = await inquirer.prompt([
      {
        type: 'password',
        name: 'apiKey',
        message: 'Enter your Google AI API key:',
        validate: (input: string): string | boolean => {
          if (!input || input.trim().length === 0) {
            return 'API key is required. Get yours at https://aistudio.google.com/apikey';
          }
          if (!input.startsWith('AIza')) {
            return 'Invalid API key format. Google AI API keys typically start with "AIza"';
          }
          return true;
        },
      },
    ]);

    const apiKey = apiKeyAnswer.apiKey.trim();

    // Fetch available models dynamically
    this.logger.info('🔍 Fetching available models...');
    const availableModels = await this.fetchAvailableModels(apiKey);

    let modelChoices;
    if (availableModels.length > 0) {
      // Use dynamically fetched models
      modelChoices = availableModels
        .filter(model => model.name.includes('gemini'))
        .map(model => ({
          name: `${model.displayName || model.name}${model.description ? ` - ${model.description}` : ''}`,
          value: model.name,
          short: model.displayName || model.name,
        }));

      // Add fallback if no models found
      if (modelChoices.length === 0) {
        modelChoices = this.getFallbackModelChoices();
      }
    } else {
      // Fallback to static choices if API fails
      this.logger.warn('⚠️  Could not fetch models dynamically, using fallback options');
      modelChoices = this.getFallbackModelChoices();
    }

    const modelAnswer = await inquirer.prompt([
      {
        type: 'list',
        name: 'model',
        message: 'Select Gemini model:',
        choices: modelChoices,
        default: modelChoices[0]?.value || 'gemini-1.5-pro',
      },
    ]);

    return {
      model: modelAnswer.model,
      apiKey,
    };
  }

  private async fetchAvailableModels(apiKey: string): Promise<AvailableModel[]> {
    try {
      const genAI = new GoogleGenAI({ apiKey });
      const modelsPager = await genAI.models.list();

      const models: AvailableModel[] = [];
      for await (const model of modelsPager) {
        if (model.name && model.name.includes('gemini')) {
          models.push({
            name: model.name,
            displayName: model.displayName || model.name,
            description: model.description,
          });
        }
      }

      return models;
    } catch (error) {
      this.logger.error('Failed to fetch models:', error as Error);
      return [];
    }
  }

  private getFallbackModelChoices(): Array<{ name: string; value: string; short: string }> {
    return [
      {
        name: 'gemini-1.5-pro - Most advanced model (recommended)',
        value: 'gemini-1.5-pro',
        short: 'Gemini 1.5 Pro',
      },
      {
        name: 'gemini-1.5-flash - Faster, lightweight model',
        value: 'gemini-1.5-flash',
        short: 'Gemini 1.5 Flash',
      },
      {
        name: 'gemini-pro - Standard model',
        value: 'gemini-pro',
        short: 'Gemini Pro',
      },
    ];
  }

  async confirmAiScan(projectPath: string, model: string): Promise<boolean> {
    this.logger.info(`📁 Project: ${projectPath}`);
    this.logger.info(`🤖 Model: ${model}`);
    this.logger.warn('⚠️  AI scan will analyze your code and send it to Google AI services');
    this.logger.warn("⚠️  Ensure you comply with your organization's data policies");

    const answers = await inquirer.prompt([
      {
        type: 'confirm',
        name: 'proceed',
        message: 'Do you want to proceed with the AI scan?',
        default: false,
      },
    ]);

    return answers.proceed;
  }
  displayApiKeyHelp(): void {
    this.logger.info('📋 How to get your Google AI API key:');
    console.log('');
    console.log('1. Visit: https://aistudio.google.com/apikey');
    console.log('2. Sign in with your Google account');
    console.log('3. Click "Create API key"');
    console.log('4. Copy the generated API key');
    console.log('5. Paste it when prompted');
    console.log('');
    this.logger.warn('⚠️  Keep your API key secure and never commit it to version control');
  }

  displayAiScanInfo(): void {
    this.logger.info('🤖 About AI Scan:');
    console.log('');
    console.log('• Uses Google Gemini AI for intelligent code analysis');
    console.log('• Identifies complex security patterns and business logic flaws');
    console.log('• Provides contextual recommendations');
    console.log('• Analyzes architectural security issues');
    console.log('• Excludes test files and irrelevant files automatically');
    console.log('');
    this.logger.info('⚡ AI scan may take longer but provides deeper insights');
  }
}

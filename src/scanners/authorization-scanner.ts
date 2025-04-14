// filepath: c:\Users\gramo\Desktop\projects\nestjs-security-scan\src\scanners\authorization-scanner.ts
import * as fs from 'fs-extra';
import * as path from 'path';
import { SecurityVulnerability, Scanner } from '../types';
import * as globModule from 'glob';
import chalk from 'chalk';

// Use synchronous glob
const globSync = globModule.sync;

export class AuthorizationScanner implements Scanner {
  private projectPath: string;
  private vulnerabilities: SecurityVulnerability[] = [];
  private scannedFiles: string[] = [];
  private verbose: boolean;
  private hasGuards: boolean = false;
  private hasRoles: boolean = false;
  private hasUserEntity: boolean = false;
  private endpoints: Map<
    string,
    {
      hasAuth: boolean;
      path: string;
      method: string;
      line: number;
    }[]
  > = new Map();

  constructor(projectPath: string, verbose: boolean = false) {
    // Resolve the path to an absolute path to ensure consistency
    this.projectPath = path.resolve(projectPath);
    this.verbose = verbose;
    this.log(`AuthorizationScanner initialized with resolved path: ${this.projectPath}`);
  }

  private log(message: string): void {
    if (this.verbose) {
      console.log(message);
    }
  }

  async scan(): Promise<{ vulnerabilities: SecurityVulnerability[]; scannedFiles: string[] }> {
    try {
      this.log('Starting authorization scanner...');

      // Create an absolute path pattern with specific handling for Windows backslashes
      const normalizedPath = this.projectPath.replace(/\\/g, '/');
      const globPattern = `${normalizedPath}/src/**/*.{ts,js}`;
      this.log(`Glob pattern: ${globPattern}`);

      // Use globSync directly
      const files = globSync(globPattern, {
        ignore: ['**/node_modules/**', '**/dist/**', '**/*.spec.ts', '**/*.test.ts'],
        absolute: true,
      });
      this.log(`Found ${files.length} TypeScript/JavaScript files to scan`);

      // First pass: collect information about guards, roles, and user entities
      await this.collectProjectStructure(files);

      // Second pass: analyze authorization patterns
      await this.analyzeAuthorization(files);

      this.log(
        `Authorization scanner completed. Scanned ${this.scannedFiles.length} files, found ${this.vulnerabilities.length} vulnerabilities`
      );

      if (this.vulnerabilities.length > 0) {
        console.log(`Found ${this.vulnerabilities.length} authorization vulnerabilities`);
      }

      return {
        vulnerabilities: this.vulnerabilities,
        scannedFiles: this.scannedFiles,
      };
    } catch (error) {
      if (this.verbose) {
        console.error('Error scanning for authorization issues:', error);
      }
      return { vulnerabilities: this.vulnerabilities, scannedFiles: this.scannedFiles };
    }
  }

  private async collectProjectStructure(files: string[]): Promise<void> {
    for (const filePath of files) {
      const relativePath = path.relative(this.projectPath, filePath);
      this.scannedFiles.push(relativePath);

      try {
        const content = await fs.readFile(filePath, 'utf8');

        // Check for Guards implementation
        if (
          content.includes('@Injectable') &&
          (content.includes('CanActivate') || content.includes('implements Guard'))
        ) {
          this.hasGuards = true;
          this.log(`Found guard implementation in: ${relativePath}`);
        }

        // Check for Roles or Permissions
        if (
          content.includes('@SetMetadata') ||
          content.includes('Role') ||
          content.includes('Permission') ||
          content.includes('RBAC')
        ) {
          this.hasRoles = true;
          this.log(`Found roles/permissions in: ${relativePath}`);
        }

        // Check for User entity
        if (
          (content.includes('@Entity') || content.includes('extends BaseEntity')) &&
          (content.includes('User') || content.includes('user'))
        ) {
          this.hasUserEntity = true;
          this.log(`Found user entity in: ${relativePath}`);
        }

        // Collect endpoints
        this.collectEndpoints(content, relativePath);
      } catch (error) {
        if (this.verbose) {
          console.error(`Error reading file ${filePath}:`, error);
        }
      }
    }
  }

  private collectEndpoints(content: string, filePath: string): void {
    const endpoints: {
      hasAuth: boolean;
      path: string;
      method: string;
      line: number;
    }[] = [];

    // Check for controller methods
    const httpMethods = ['@Get', '@Post', '@Put', '@Delete', '@Patch', '@Options', '@Head', '@All'];

    for (const method of httpMethods) {
      const regex = new RegExp(`${method}\\s*\\(['"\`]?([^\\)'"]*?)['"\`]?\\)`, 'g');
      let match;

      while ((match = regex.exec(content)) !== null) {
        const lineNumber = this.getLineNumber(content, match.index);
        const path = match[1] || '/';
        const methodName = method.substring(1); // remove the @ symbol

        // Determine if this endpoint has auth decorators
        const contextStart = Math.max(0, match.index - 200); // Look back ~200 chars
        const contextEnd = match.index;
        const context = content.substring(contextStart, contextEnd);

        const hasAuth = this.hasAuthDecorator(context);

        endpoints.push({
          hasAuth,
          path,
          method: methodName,
          line: lineNumber,
        });

        this.log(`Found ${methodName} endpoint: ${path} (auth: ${hasAuth}) in ${filePath}:${lineNumber}`);
      }
    }

    if (endpoints.length > 0) {
      this.endpoints.set(filePath, endpoints);
    }
  }

  private hasAuthDecorator(context: string): boolean {
    return (
      context.includes('@UseGuards') ||
      context.includes('@Roles') ||
      context.includes('@RequiresPermissions') ||
      context.includes('@Authorized') ||
      context.includes('@Auth') ||
      context.includes('@RequireAuth') ||
      context.includes('@RequirePermission')
    );
  }

  private async analyzeAuthorization(files: string[]): Promise<void> {
    // Analyze if guards/roles are applied consistently
    this.checkForMissingGuards();

    // Analyze controllers for potential IDOR issues
    for (const [filePath, _] of this.endpoints) {
      await this.checkForIdorVulnerabilities(filePath);
    }

    // Check for missing authorization libraries
    await this.checkPackageJson();
  }

  private checkForMissingGuards(): void {
    for (const [filePath, endpoints] of this.endpoints) {
      // Get controller base path by reading the file
      const controllerInfo = {
        basePath: '',
        isAuthController: filePath.includes('auth') || filePath.includes('login'),
        isAdminController: filePath.includes('admin'),
        isSecuredResource: filePath.includes('user') || filePath.includes('profile') || filePath.includes('account'),
      };

      // Find endpoints with missing auth
      const endpointsWithoutAuth = endpoints.filter((endpoint) => !endpoint.hasAuth);

      // Skip health check or public endpoints
      const skipEndpoints = (endpoint: string): boolean => {
        return (
          endpoint.includes('health') || endpoint.includes('status') || endpoint.includes('public') || endpoint === '/'
        );
      };

      // Filtered endpoints that need attention
      const vulnerableEndpoints = endpointsWithoutAuth.filter(
        (e) =>
          !skipEndpoints(e.path) &&
          (e.method !== 'Get' || controllerInfo.isSecuredResource || controllerInfo.isAdminController)
      );

      if (vulnerableEndpoints.length > 0) {
        // For DELETE, PUT, PATCH on resources without auth, this is a higher risk
        for (const endpoint of vulnerableEndpoints) {
          const isWriteOperation = ['Post', 'Put', 'Delete', 'Patch'].includes(endpoint.method);
          const severity = isWriteOperation ? 'high' : 'medium';

          console.log(
            `${chalk.cyan('➤')} Found vulnerability in ${chalk.yellow(filePath)}:${chalk.yellow(
              endpoint.line.toString()
            )}: ` +
              `${severity === 'high' ? chalk.red.bold('[HIGH]') : chalk.yellow.bold('[MEDIUM]')} ${chalk.bold(
                `${endpoint.method} Endpoint Without Authorization Guards`
              )}`
          );

          this.vulnerabilities.push({
            id: `missing-auth-guard-${endpoint.method.toLowerCase()}`,
            title: `${endpoint.method} Endpoint Without Authorization Guards`,
            description: `The ${endpoint.method.toUpperCase()} ${
              endpoint.path
            } endpoint doesn't have authorization guards, allowing potential unauthorized access`,
            severity: severity as any,
            location: filePath,
            line: endpoint.line,
            recommendation: 'Apply @UseGuards() decorator with appropriate authentication and authorization guards',
            category: 'code',
          });
        }
      }
    }
  }

  private async checkForIdorVulnerabilities(filePath: string): Promise<void> {
    try {
      const content = await fs.readFile(filePath, 'utf8');

      // Check for req.params.id or similar without user ID validation
      if (
        (content.includes('params.id') || content.includes('params.userId') || content.includes('params["id"]')) &&
        !content.includes('user.id') &&
        !content.includes('req.user') &&
        (content.includes('findOne') || content.includes('findById'))
      ) {
        console.log(
          `${chalk.cyan('➤')} Found vulnerability in ${chalk.yellow(filePath)}: ` +
            `${chalk.red.bold('[HIGH]')} ${chalk.bold('Potential Insecure Direct Object Reference (IDOR)')}`
        );

        this.vulnerabilities.push({
          id: 'potential-idor',
          title: 'Potential Insecure Direct Object Reference (IDOR)',
          description:
            'The code uses route parameters to query resources without validating if the current user has permission to access them',
          severity: 'high',
          location: filePath,
          recommendation:
            'Validate that the requesting user has proper permissions to access the requested resource by comparing user IDs or roles',
          category: 'code',
        });
      }

      // Check for Repository/Entity.findOne({id}) without user check
      if (
        (content.includes('Repository') || content.includes('Service')) &&
        content.includes('findOne') &&
        content.includes('id:') &&
        !content.includes('user.id') &&
        !content.includes('userId') &&
        !content.includes('getUserId')
      ) {
        // Only flag this if the controller doesn't have class-level guards
        if (!content.includes('@UseGuards') || content.indexOf('@UseGuards') > content.indexOf('findOne')) {
          console.log(
            `${chalk.cyan('➤')} Found vulnerability in ${chalk.yellow(filePath)}: ` +
              `${chalk.yellow.bold('[MEDIUM]')} ${chalk.bold('Data Access Without Owner Validation')}`
          );

          this.vulnerabilities.push({
            id: 'data-access-no-owner-check',
            title: 'Data Access Without Owner Validation',
            description:
              'Data is retrieved by ID without validating if the current user is the owner or has permission to access it',
            severity: 'medium',
            location: filePath,
            recommendation:
              'Add owner validation by checking if the requesting user ID matches the resource owner ID or has appropriate permissions',
            category: 'code',
          });
        }
      }
    } catch (error) {
      if (this.verbose) {
        console.error(`Error checking for IDOR in ${filePath}:`, error);
      }
    }
  }

  private async checkPackageJson(): Promise<void> {
    const packageJsonPath = path.join(this.projectPath, 'package.json');
    if (fs.existsSync(packageJsonPath)) {
      try {
        const packageJson = await fs.readJson(packageJsonPath);
        const dependencies = { ...packageJson.dependencies, ...packageJson.devDependencies };

        // If we have user entity but no guards/roles and no auth packages
        if (
          this.hasUserEntity &&
          (!this.hasGuards || !this.hasRoles) &&
          !dependencies['@nestjs/passport'] &&
          !dependencies['passport'] &&
          !dependencies['@nestjs/jwt'] &&
          !dependencies['@casl/ability']
        ) {
          console.log(
            `${chalk.cyan('➤')} Found vulnerability in ${chalk.yellow('package.json')}: ` +
              `${chalk.yellow.bold('[MEDIUM]')} ${chalk.bold('Missing Authorization Packages')}`
          );

          this.vulnerabilities.push({
            id: 'missing-auth-packages',
            title: 'Missing Authorization Packages',
            description: 'The application implements a user entity but lacks standard authorization packages',
            severity: 'medium',
            location: 'package.json',
            recommendation:
              'Install and implement authorization using packages like @nestjs/passport, @nestjs/jwt, or @casl/ability for role-based access control',
            category: 'dependency',
          });
        }

        // Recommend CASL for RBAC if handling roles without it
        if (this.hasRoles && !dependencies['@casl/ability'] && !dependencies['nest-access-control']) {
          console.log(
            `${chalk.cyan('➤')} Found vulnerability in ${chalk.yellow('package.json')}: ` +
              `${chalk.blue.bold('[LOW]')} ${chalk.bold('Consider Using RBAC Library')}`
          );

          this.vulnerabilities.push({
            id: 'missing-rbac-library',
            title: 'Consider Using RBAC Library',
            description: 'Role-based access control is implemented without a dedicated RBAC library',
            severity: 'low',
            location: 'package.json',
            recommendation:
              'Consider using @casl/ability or nest-access-control for more robust role-based access control',
            category: 'dependency',
          });
        }
      } catch (error) {
        if (this.verbose) {
          console.error('Error checking package.json:', error);
        }
      }
    }
  }

  private getLineNumber(content: string, index: number): number {
    const textBeforeMatch = content.substring(0, index);
    return (textBeforeMatch.match(/\n/g) || []).length + 1;
  }
}

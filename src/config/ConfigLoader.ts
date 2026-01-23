/**
 * Configuration Loader
 * Loads FDMS configuration from various sources
 */

import * as fs from 'fs';
import * as path from 'path';
import {
  FdmsConfig,
  ResolvedFdmsConfig,
  FdmsEnvironment,
  FDMS_BASE_URLS,
  CONFIG_DEFAULTS,
  ENV_VAR_MAPPING,
  ConfigFileOptions,
} from './FdmsConfig';
import { ConfigValidator } from './ConfigValidator';
import { FdmsError } from '../errors/FdmsError';

/**
 * ConfigLoader class
 * Provides multiple ways to load and merge configuration
 */
export class ConfigLoader {
  private validator: ConfigValidator;

  constructor() {
    this.validator = new ConfigValidator();
  }

  /**
   * Load configuration from a JSON file
   * @param options - File path and options
   * @returns Loaded configuration
   */
  public fromFile(options: ConfigFileOptions | string): Partial<FdmsConfig> {
    const filePath = typeof options === 'string' ? options : options.path;
    const resolvedPath = path.resolve(filePath);

    if (!fs.existsSync(resolvedPath)) {
      throw new FdmsError(`Configuration file not found: ${resolvedPath}`, 'CONFIG_FILE_NOT_FOUND');
    }

    try {
      const content = fs.readFileSync(resolvedPath, 'utf-8');
      const config = JSON.parse(content) as Partial<FdmsConfig>;
      return this.processCertificatePaths(config, path.dirname(resolvedPath));
    } catch (error) {
      if (error instanceof SyntaxError) {
        throw new FdmsError(
          `Invalid JSON in configuration file: ${resolvedPath}`,
          'CONFIG_PARSE_ERROR'
        );
      }
      throw error;
    }
  }

  /**
   * Load configuration from environment variables
   * @returns Configuration from environment variables
   */
  public fromEnvironment(): Partial<FdmsConfig> {
    const config: Partial<FdmsConfig> = {};

    for (const [envVar, configKey] of Object.entries(ENV_VAR_MAPPING)) {
      const value = process.env[envVar];
      if (value !== undefined && value !== '') {
        // Handle type conversions
        (config as Record<string, unknown>)[configKey] = this.parseEnvValue(configKey, value);
      }
    }

    return config;
  }

  /**
   * Load configuration programmatically
   * @param config - Configuration object
   * @returns Validated configuration
   */
  public fromObject(config: FdmsConfig): FdmsConfig {
    return { ...config };
  }

  /**
   * Merge multiple configuration sources
   * Priority: programmatic > environment > file > defaults
   * @param sources - Configuration sources in order of increasing priority
   * @returns Merged configuration
   */
  public merge(...sources: Partial<FdmsConfig>[]): Partial<FdmsConfig> {
    return sources.reduce((merged, source) => {
      return { ...merged, ...this.filterUndefined(source) };
    }, {});
  }

  /**
   * Resolve configuration with defaults and validation
   * @param config - Partial configuration
   * @returns Fully resolved configuration
   */
  public resolve(config: Partial<FdmsConfig>): ResolvedFdmsConfig {
    // Validate before resolving
    this.validator.validateOrThrow(config);

    const environment = config.environment ?? CONFIG_DEFAULTS.environment;

    const resolved: ResolvedFdmsConfig = {
      // Required fields (validated to exist)
      deviceId: config.deviceId!,
      deviceSerialNo: config.deviceSerialNo!,
      activationKey: config.activationKey!,
      deviceModelName: config.deviceModelName!,
      deviceModelVersion: config.deviceModelVersion!,
      certificate: config.certificate!,
      privateKey: config.privateKey!,

      // Optional with potential value
      privateKeyPassword: config.privateKeyPassword,

      // Optional with defaults
      environment,
      baseUrl: config.baseUrl ?? FDMS_BASE_URLS[environment],
      timeout: config.timeout ?? CONFIG_DEFAULTS.timeout,
      retryAttempts: config.retryAttempts ?? CONFIG_DEFAULTS.retryAttempts,
      retryDelay: config.retryDelay ?? CONFIG_DEFAULTS.retryDelay,
      enableAuditLog: config.enableAuditLog ?? CONFIG_DEFAULTS.enableAuditLog,
      auditLogPath: config.auditLogPath,
      stateStorePath: config.stateStorePath,
    };

    return resolved;
  }

  /**
   * Load, merge, and resolve configuration from multiple sources
   * @param options - Loading options
   * @returns Fully resolved configuration
   */
  public load(options: {
    file?: string | ConfigFileOptions;
    env?: boolean;
    config?: Partial<FdmsConfig>;
  }): ResolvedFdmsConfig {
    const sources: Partial<FdmsConfig>[] = [];

    // Load from file if specified
    if (options.file) {
      sources.push(this.fromFile(options.file));
    }

    // Load from environment if enabled
    if (options.env !== false) {
      sources.push(this.fromEnvironment());
    }

    // Add programmatic config
    if (options.config) {
      sources.push(options.config);
    }

    // Merge and resolve
    const merged = this.merge(...sources);
    return this.resolve(merged);
  }

  /**
   * Create a configuration template file
   * @param filePath - Path to write template
   * @param includeComments - Whether to include description comments
   */
  public createTemplate(filePath: string, includeComments = true): void {
    const template = {
      deviceId: 'YOUR_DEVICE_ID',
      deviceSerialNo: 'YOUR_SERIAL_NUMBER',
      activationKey: 'YOUR_ACTIVATION_KEY',
      deviceModelName: 'YOUR_MODEL_NAME',
      deviceModelVersion: '1.0.0',
      certificate: './certs/device.pem',
      privateKey: './certs/device.key',
      privateKeyPassword: '',
      environment: 'test',
      timeout: 30000,
      retryAttempts: 3,
      retryDelay: 1000,
      enableAuditLog: true,
      auditLogPath: './logs/audit.log',
      stateStorePath: './data/fiscal-state.json',
    };

    const content = JSON.stringify(template, null, 2);
    fs.writeFileSync(filePath, content, 'utf-8');
  }

  /**
   * Parse environment variable value to appropriate type
   */
  private parseEnvValue(key: string, value: string): unknown {
    // Boolean fields
    if (key === 'enableAuditLog') {
      return value.toLowerCase() === 'true' || value === '1';
    }

    // Numeric fields
    if (['timeout', 'retryAttempts', 'retryDelay'].includes(key)) {
      const num = parseInt(value, 10);
      return isNaN(num) ? value : num;
    }

    // Environment field
    if (key === 'environment') {
      return value as FdmsEnvironment;
    }

    return value;
  }

  /**
   * Process certificate paths relative to config file
   */
  private processCertificatePaths(
    config: Partial<FdmsConfig>,
    basePath: string
  ): Partial<FdmsConfig> {
    const processed = { ...config };

    // Resolve certificate path if it's a relative path
    if (typeof processed.certificate === 'string' && !processed.certificate.includes('-----BEGIN')) {
      const certPath = processed.certificate;
      if (!path.isAbsolute(certPath)) {
        processed.certificate = path.resolve(basePath, certPath);
      }
    }

    // Resolve private key path if it's a relative path
    if (typeof processed.privateKey === 'string' && !processed.privateKey.includes('-----BEGIN')) {
      const keyPath = processed.privateKey;
      if (!path.isAbsolute(keyPath)) {
        processed.privateKey = path.resolve(basePath, keyPath);
      }
    }

    return processed;
  }

  /**
   * Filter out undefined values from config object
   */
  private filterUndefined(config: Partial<FdmsConfig>): Partial<FdmsConfig> {
    const filtered: Partial<FdmsConfig> = {};
    for (const [key, value] of Object.entries(config)) {
      if (value !== undefined) {
        (filtered as Record<string, unknown>)[key] = value;
      }
    }
    return filtered;
  }
}

/**
 * Configuration Validator
 * Validates FDMS configuration with clear error messages
 */

import { FdmsConfig, FdmsEnvironment } from './FdmsConfig';
import { ValidationError } from '../errors/ValidationError';

/**
 * Validation result interface
 */
export interface ValidationResult {
  valid: boolean;
  errors: ValidationErrorDetail[];
}

/**
 * Validation error detail
 */
export interface ValidationErrorDetail {
  field: string;
  message: string;
  value?: unknown;
}

/**
 * ConfigValidator class
 * Provides comprehensive validation for FDMS configuration
 */
export class ConfigValidator {
  private errors: ValidationErrorDetail[] = [];

  /**
   * Validate the entire configuration object
   * @param config - Configuration to validate
   * @returns Validation result with any errors
   */
  public validate(config: Partial<FdmsConfig>): ValidationResult {
    this.errors = [];

    // Validate required fields
    this.validateRequired(config);

    // Validate field formats
    this.validateFormats(config);

    // Validate numeric ranges
    this.validateRanges(config);

    // Validate environment
    this.validateEnvironment(config);

    // Validate certificate configuration
    this.validateCertificateConfig(config);

    return {
      valid: this.errors.length === 0,
      errors: this.errors,
    };
  }

  /**
   * Validate and throw if invalid
   * @param config - Configuration to validate
   * @throws ValidationError if configuration is invalid
   */
  public validateOrThrow(config: Partial<FdmsConfig>): void {
    const result = this.validate(config);
    if (!result.valid) {
      const errorMessages = result.errors
        .map((e) => `${e.field}: ${e.message}`)
        .join('; ');
      throw new ValidationError(`Configuration validation failed: ${errorMessages}`);
    }
  }

  /**
   * Validate required fields are present and non-empty
   */
  private validateRequired(config: Partial<FdmsConfig>): void {
    const requiredFields: (keyof FdmsConfig)[] = [
      'deviceId',
      'deviceSerialNo',
      'activationKey',
      'deviceModelName',
      'deviceModelVersion',
      'certificate',
      'privateKey',
    ];

    for (const field of requiredFields) {
      const value = config[field];
      if (value === undefined || value === null) {
        this.errors.push({
          field,
          message: `${field} is required`,
        });
      } else if (typeof value === 'string' && value.trim() === '') {
        this.errors.push({
          field,
          message: `${field} cannot be empty`,
          value,
        });
      }
    }
  }

  /**
   * Validate field formats
   */
  private validateFormats(config: Partial<FdmsConfig>): void {
    // Device ID should be numeric string or number
    if (config.deviceId !== undefined) {
      const deviceIdStr = String(config.deviceId);
      if (!/^\d+$/.test(deviceIdStr)) {
        this.errors.push({
          field: 'deviceId',
          message: 'deviceId must be a numeric value',
          value: config.deviceId,
        });
      }
    }

    // Validate URL format if baseUrl is provided
    if (config.baseUrl !== undefined && config.baseUrl !== '') {
      try {
        new URL(config.baseUrl);
      } catch {
        this.errors.push({
          field: 'baseUrl',
          message: 'baseUrl must be a valid URL',
          value: config.baseUrl,
        });
      }
    }

    // Validate audit log path format
    if (config.auditLogPath !== undefined && config.auditLogPath !== '') {
      if (typeof config.auditLogPath !== 'string') {
        this.errors.push({
          field: 'auditLogPath',
          message: 'auditLogPath must be a string',
          value: config.auditLogPath,
        });
      }
    }

    // Validate state store path format
    if (config.stateStorePath !== undefined && config.stateStorePath !== '') {
      if (typeof config.stateStorePath !== 'string') {
        this.errors.push({
          field: 'stateStorePath',
          message: 'stateStorePath must be a string',
          value: config.stateStorePath,
        });
      }
    }
  }

  /**
   * Validate numeric ranges
   */
  private validateRanges(config: Partial<FdmsConfig>): void {
    // Timeout must be positive
    if (config.timeout !== undefined) {
      if (typeof config.timeout !== 'number' || config.timeout <= 0) {
        this.errors.push({
          field: 'timeout',
          message: 'timeout must be a positive number (milliseconds)',
          value: config.timeout,
        });
      } else if (config.timeout < 1000) {
        this.errors.push({
          field: 'timeout',
          message: 'timeout should be at least 1000ms for reliable operation',
          value: config.timeout,
        });
      } else if (config.timeout > 300000) {
        this.errors.push({
          field: 'timeout',
          message: 'timeout should not exceed 300000ms (5 minutes)',
          value: config.timeout,
        });
      }
    }

    // Retry attempts must be non-negative
    if (config.retryAttempts !== undefined) {
      if (typeof config.retryAttempts !== 'number' || config.retryAttempts < 0) {
        this.errors.push({
          field: 'retryAttempts',
          message: 'retryAttempts must be a non-negative number',
          value: config.retryAttempts,
        });
      } else if (config.retryAttempts > 10) {
        this.errors.push({
          field: 'retryAttempts',
          message: 'retryAttempts should not exceed 10',
          value: config.retryAttempts,
        });
      }
    }

    // Retry delay must be positive
    if (config.retryDelay !== undefined) {
      if (typeof config.retryDelay !== 'number' || config.retryDelay <= 0) {
        this.errors.push({
          field: 'retryDelay',
          message: 'retryDelay must be a positive number (milliseconds)',
          value: config.retryDelay,
        });
      } else if (config.retryDelay > 60000) {
        this.errors.push({
          field: 'retryDelay',
          message: 'retryDelay should not exceed 60000ms (1 minute)',
          value: config.retryDelay,
        });
      }
    }
  }

  /**
   * Validate environment setting
   */
  private validateEnvironment(config: Partial<FdmsConfig>): void {
    if (config.environment !== undefined) {
      const validEnvironments: FdmsEnvironment[] = ['test', 'production'];
      if (!validEnvironments.includes(config.environment)) {
        this.errors.push({
          field: 'environment',
          message: `environment must be one of: ${validEnvironments.join(', ')}`,
          value: config.environment,
        });
      }
    }
  }

  /**
   * Validate certificate configuration
   */
  private validateCertificateConfig(config: Partial<FdmsConfig>): void {
    // Certificate validation
    if (config.certificate !== undefined) {
      if (typeof config.certificate === 'string') {
        // Check if it looks like a file path or PEM content
        const isPemContent =
          config.certificate.includes('-----BEGIN') ||
          config.certificate.includes('-----END');
        const isFilePath =
          config.certificate.endsWith('.pem') ||
          config.certificate.endsWith('.crt') ||
          config.certificate.endsWith('.cer') ||
          config.certificate.endsWith('.der');

        if (!isPemContent && !isFilePath && config.certificate.length < 100) {
          this.errors.push({
            field: 'certificate',
            message:
              'certificate must be a valid file path (.pem, .crt, .cer, .der) or PEM-encoded content',
            value: `${config.certificate.substring(0, 50)}...`,
          });
        }
      } else if (!Buffer.isBuffer(config.certificate)) {
        this.errors.push({
          field: 'certificate',
          message: 'certificate must be a string (path or PEM) or Buffer',
        });
      }
    }

    // Private key validation
    if (config.privateKey !== undefined) {
      if (typeof config.privateKey === 'string') {
        const isPemContent =
          config.privateKey.includes('-----BEGIN') ||
          config.privateKey.includes('-----END');
        const isFilePath =
          config.privateKey.endsWith('.pem') ||
          config.privateKey.endsWith('.key') ||
          config.privateKey.endsWith('.der');

        if (!isPemContent && !isFilePath && config.privateKey.length < 100) {
          this.errors.push({
            field: 'privateKey',
            message:
              'privateKey must be a valid file path (.pem, .key, .der) or PEM-encoded content',
            value: '[REDACTED]',
          });
        }
      } else if (!Buffer.isBuffer(config.privateKey)) {
        this.errors.push({
          field: 'privateKey',
          message: 'privateKey must be a string (path or PEM) or Buffer',
        });
      }
    }
  }
}

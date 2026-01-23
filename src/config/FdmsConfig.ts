/**
 * ZIMRA FDMS Configuration Types
 * Type-safe configuration objects for the FDMS SDK
 */

/**
 * FDMS Environment types
 */
export type FdmsEnvironment = 'test' | 'production';

/**
 * Base URLs for FDMS environments
 */
export const FDMS_BASE_URLS: Record<FdmsEnvironment, string> = {
  test: 'https://fdmsapitest.zimra.co.zw',
  production: 'https://fdmsapi.zimra.co.zw',
};

/**
 * Default configuration values
 */
export const CONFIG_DEFAULTS = {
  environment: 'test' as FdmsEnvironment,
  timeout: 30000,
  retryAttempts: 3,
  retryDelay: 1000,
  enableAuditLog: true,
} as const;

/**
 * Main FDMS Configuration interface
 * Defines all configuration options for the FDMS SDK
 */
export interface FdmsConfig {
  // Required - Device identification
  /** Device ID assigned by ZIMRA */
  deviceId: string;
  /** Manufacturer serial number */
  deviceSerialNo: string;
  /** Activation key from ZIMRA registration portal */
  activationKey: string;
  /** Device model name registered with ZIMRA */
  deviceModelName: string;
  /** Device model version registered with ZIMRA */
  deviceModelVersion: string;

  // Required - Certificate configuration
  /** X.509 certificate (PEM/DER format) - file path or content */
  certificate: string | Buffer;
  /** RSA private key (PEM/DER format) - file path or content */
  privateKey: string | Buffer;
  /** Password for encrypted private key (optional) */
  privateKeyPassword?: string;

  // Optional - Environment settings
  /** Environment: 'test' or 'production' (default: 'test') */
  environment?: FdmsEnvironment;
  /** Override default base URL */
  baseUrl?: string;
  /** Request timeout in milliseconds (default: 30000) */
  timeout?: number;
  /** Number of retry attempts (default: 3) */
  retryAttempts?: number;
  /** Base delay between retries in milliseconds (default: 1000) */
  retryDelay?: number;

  // Optional - Audit logging
  /** Enable audit logging (default: true) */
  enableAuditLog?: boolean;
  /** File path for audit logs */
  auditLogPath?: string;

  // Optional - State persistence
  /** Path to store fiscal state/counters */
  stateStorePath?: string;
}

/**
 * Resolved configuration with all defaults applied
 * All optional fields become required with their default values
 */
export interface ResolvedFdmsConfig {
  deviceId: string;
  deviceSerialNo: string;
  activationKey: string;
  deviceModelName: string;
  deviceModelVersion: string;
  certificate: string | Buffer;
  privateKey: string | Buffer;
  privateKeyPassword?: string;
  environment: FdmsEnvironment;
  baseUrl: string;
  timeout: number;
  retryAttempts: number;
  retryDelay: number;
  enableAuditLog: boolean;
  auditLogPath?: string;
  stateStorePath?: string;
}

/**
 * Configuration for file-based config loading
 */
export interface ConfigFileOptions {
  /** Path to JSON configuration file */
  path: string;
  /** Whether to watch for file changes */
  watch?: boolean;
}

/**
 * Environment variable mapping for configuration
 */
export const ENV_VAR_MAPPING: Record<string, keyof FdmsConfig> = {
  FDMS_DEVICE_ID: 'deviceId',
  FDMS_DEVICE_SERIAL_NO: 'deviceSerialNo',
  FDMS_ACTIVATION_KEY: 'activationKey',
  FDMS_DEVICE_MODEL_NAME: 'deviceModelName',
  FDMS_DEVICE_MODEL_VERSION: 'deviceModelVersion',
  FDMS_CERTIFICATE: 'certificate',
  FDMS_PRIVATE_KEY: 'privateKey',
  FDMS_PRIVATE_KEY_PASSWORD: 'privateKeyPassword',
  FDMS_ENVIRONMENT: 'environment',
  FDMS_BASE_URL: 'baseUrl',
  FDMS_TIMEOUT: 'timeout',
  FDMS_RETRY_ATTEMPTS: 'retryAttempts',
  FDMS_RETRY_DELAY: 'retryDelay',
  FDMS_ENABLE_AUDIT_LOG: 'enableAuditLog',
  FDMS_AUDIT_LOG_PATH: 'auditLogPath',
  FDMS_STATE_STORE_PATH: 'stateStorePath',
} as const;

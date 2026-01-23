/**
 * Configuration Examples for ZIMRA FDMS SDK
 * Demonstrates various ways to configure the SDK
 */

import { ConfigLoader, FdmsConfig, ResolvedFdmsConfig } from '../src/config';

// =============================================================================
// Example 1: Programmatic Configuration
// =============================================================================

function programmaticConfigExample(): ResolvedFdmsConfig {
  const loader = new ConfigLoader();

  const config: FdmsConfig = {
    // Required device information
    deviceId: '12345',
    deviceSerialNo: 'SN-2024-001',
    activationKey: 'your-activation-key-from-zimra',
    deviceModelName: 'MyPOS-Terminal',
    deviceModelVersion: '1.0.0',

    // Certificate configuration
    certificate: '/path/to/device-certificate.pem',
    privateKey: '/path/to/private-key.pem',
    privateKeyPassword: 'optional-key-password',

    // Environment settings
    environment: 'test', // Use 'production' for live environment
    timeout: 30000,
    retryAttempts: 3,
    retryDelay: 1000,

    // Audit logging
    enableAuditLog: true,
    auditLogPath: './logs/fdms-audit.log',

    // State persistence
    stateStorePath: './data/fiscal-state.json',
  };

  return loader.load({ config });
}

// =============================================================================
// Example 2: File-based Configuration
// =============================================================================

function fileConfigExample(): ResolvedFdmsConfig {
  const loader = new ConfigLoader();

  // Load from JSON file (see fdms-config.example.json)
  return loader.load({
    file: './config/fdms-config.json',
    env: true, // Also check environment variables (can override file)
  });
}

// =============================================================================
// Example 3: Environment Variables Configuration
// =============================================================================

function envConfigExample(): ResolvedFdmsConfig {
  /**
   * Set these environment variables before running:
   *
   * export FDMS_DEVICE_ID="12345"
   * export FDMS_DEVICE_SERIAL_NO="SN-2024-001"
   * export FDMS_ACTIVATION_KEY="your-activation-key"
   * export FDMS_DEVICE_MODEL_NAME="MyPOS-Terminal"
   * export FDMS_DEVICE_MODEL_VERSION="1.0.0"
   * export FDMS_CERTIFICATE="/path/to/cert.pem"
   * export FDMS_PRIVATE_KEY="/path/to/key.pem"
   * export FDMS_ENVIRONMENT="test"
   * export FDMS_ENABLE_AUDIT_LOG="true"
   */

  const loader = new ConfigLoader();
  return loader.load({ env: true });
}

// =============================================================================
// Example 4: Merged Configuration (File + Environment + Programmatic)
// =============================================================================

function mergedConfigExample(): ResolvedFdmsConfig {
  const loader = new ConfigLoader();

  // Priority: programmatic > environment > file
  // This allows base settings in file, overrides via env vars,
  // and runtime-specific settings programmatically
  return loader.load({
    file: './config/fdms-config.json',
    env: true,
    config: {
      // Override specific settings at runtime
      timeout: 60000, // Longer timeout for slow connections
    },
  });
}

// =============================================================================
// Example 5: Inline Certificate Content
// =============================================================================

function inlineCertificateExample(): ResolvedFdmsConfig {
  const loader = new ConfigLoader();

  const certificatePem = `-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHBfpEgcMFvMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnVu
dXNlZDAeFw0yNDAxMjMwMDAwMDBaFw0yNTAxMjMwMDAwMDBaMBExDzANBgNVBAMM
BnVudXNlZDBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQC5lKUH7MN7z1A2Z5lBz0lM
W0KqTNZL6j8P9DxC0Z5dV5FGZuDQB5+x1qH7BqIrL7t3AFn6eH0vDq6LqL1ZbE0t
AgMBAAGjUzBRMB0GA1UdDgQWBBRj1Hv2J5t3A6L7y8d3zJpvVqzMqTAfBgNVHSME
GDAWgBRj1Hv2J5t3A6L7y8d3zJpvVqzMqTAPBgNVHRMBAf8EBTADAQH/MA0GCSqG
SIb3DQEBCwUAA0EAjQ7lGzXf8Z2mKl7cYl8v5y0fCIo2H6qL8bL9k3L5F3l2zUlG
-----END CERTIFICATE-----`;

  const privateKeyPem = `-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBALmUpQfsw3vPUDZnmUHPSUxbQqpM1kvqPw/0PELRnl1XkUZm4NAH
n7HWofsGoiovu3cAWfp4fS8OrouovVlsTS0CAwEAAQJAYJl8W8gXk2P5t3J5y8W7
Z8n5J6k8S8K9F9l9K3H7Y8K9F9l9K3H7Y8K9F9l9K3H7Y8K9F9l9K3H7Y8K9F9l9
-----END RSA PRIVATE KEY-----`;

  const config: FdmsConfig = {
    deviceId: '12345',
    deviceSerialNo: 'SN-2024-001',
    activationKey: 'your-activation-key',
    deviceModelName: 'MyPOS-Terminal',
    deviceModelVersion: '1.0.0',

    // Inline certificate and key content
    certificate: certificatePem,
    privateKey: privateKeyPem,

    environment: 'test',
  };

  return loader.load({ config });
}

// =============================================================================
// Example 6: Creating a Configuration Template
// =============================================================================

function createConfigTemplateExample(): void {
  const loader = new ConfigLoader();

  // Create a template configuration file
  loader.createTemplate('./config/fdms-config.template.json');

  console.log('Configuration template created at ./config/fdms-config.template.json');
}

// =============================================================================
// Example 7: Configuration Validation
// =============================================================================

import { ConfigValidator } from '../src/config';

function validationExample(): void {
  const validator = new ConfigValidator();

  const partialConfig = {
    deviceId: '12345',
    // Missing required fields...
  };

  const result = validator.validate(partialConfig);

  if (!result.valid) {
    console.log('Configuration validation failed:');
    for (const error of result.errors) {
      console.log(`  - ${error.field}: ${error.message}`);
    }
  }
}

// =============================================================================
// Run Examples
// =============================================================================

if (require.main === module) {
  console.log('=== ZIMRA FDMS Configuration Examples ===\n');

  // Example 7: Validation
  console.log('7. Configuration Validation:');
  validationExample();
  console.log();

  // Example 6: Create template
  console.log('6. Create Configuration Template:');
  createConfigTemplateExample();
}

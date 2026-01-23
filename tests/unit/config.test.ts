/**
 * Configuration Module Unit Tests
 */

import { ConfigLoader, ConfigValidator, FdmsConfig, CONFIG_DEFAULTS } from '../../src/config';
import { ValidationError } from '../../src/errors/ValidationError';

describe('ConfigValidator', () => {
  let validator: ConfigValidator;

  beforeEach(() => {
    validator = new ConfigValidator();
  });

  const validConfig: FdmsConfig = {
    deviceId: '12345',
    deviceSerialNo: 'SN-001',
    activationKey: 'test-key',
    deviceModelName: 'TestModel',
    deviceModelVersion: '1.0.0',
    certificate: '-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----',
    privateKey: '-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----',
  };

  describe('validate', () => {
    it('should pass with valid configuration', () => {
      const result = validator.validate(validConfig);
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('should fail when deviceId is missing', () => {
      const config = { ...validConfig };
      delete (config as Partial<FdmsConfig>).deviceId;

      const result = validator.validate(config);
      expect(result.valid).toBe(false);
      expect(result.errors).toContainEqual(
        expect.objectContaining({ field: 'deviceId' })
      );
    });

    it('should fail when deviceId is empty', () => {
      const config = { ...validConfig, deviceId: '' };

      const result = validator.validate(config);
      expect(result.valid).toBe(false);
      expect(result.errors).toContainEqual(
        expect.objectContaining({ field: 'deviceId', message: expect.stringContaining('empty') })
      );
    });

    it('should fail when deviceId is not numeric', () => {
      const config = { ...validConfig, deviceId: 'abc123' };

      const result = validator.validate(config);
      expect(result.valid).toBe(false);
      expect(result.errors).toContainEqual(
        expect.objectContaining({ field: 'deviceId', message: expect.stringContaining('numeric') })
      );
    });

    it('should fail with invalid environment', () => {
      const config = { ...validConfig, environment: 'invalid' as any };

      const result = validator.validate(config);
      expect(result.valid).toBe(false);
      expect(result.errors).toContainEqual(
        expect.objectContaining({ field: 'environment' })
      );
    });

    it('should fail with invalid timeout', () => {
      const config = { ...validConfig, timeout: -1000 };

      const result = validator.validate(config);
      expect(result.valid).toBe(false);
      expect(result.errors).toContainEqual(
        expect.objectContaining({ field: 'timeout' })
      );
    });

    it('should fail with timeout too low', () => {
      const config = { ...validConfig, timeout: 100 };

      const result = validator.validate(config);
      expect(result.valid).toBe(false);
      expect(result.errors).toContainEqual(
        expect.objectContaining({ field: 'timeout', message: expect.stringContaining('1000ms') })
      );
    });

    it('should fail with invalid baseUrl', () => {
      const config = { ...validConfig, baseUrl: 'not-a-url' };

      const result = validator.validate(config);
      expect(result.valid).toBe(false);
      expect(result.errors).toContainEqual(
        expect.objectContaining({ field: 'baseUrl' })
      );
    });

    it('should accept valid baseUrl', () => {
      const config = { ...validConfig, baseUrl: 'https://example.com' };

      const result = validator.validate(config);
      expect(result.valid).toBe(true);
    });

    it('should accept certificate as file path', () => {
      const config = { ...validConfig, certificate: '/path/to/cert.pem' };

      const result = validator.validate(config);
      expect(result.valid).toBe(true);
    });

    it('should accept certificate as Buffer', () => {
      const config = { ...validConfig, certificate: Buffer.from('cert-content') };

      const result = validator.validate(config);
      expect(result.valid).toBe(true);
    });
  });

  describe('validateOrThrow', () => {
    it('should not throw with valid configuration', () => {
      expect(() => validator.validateOrThrow(validConfig)).not.toThrow();
    });

    it('should throw ValidationError with invalid configuration', () => {
      const config = { ...validConfig };
      delete (config as Partial<FdmsConfig>).deviceId;

      expect(() => validator.validateOrThrow(config)).toThrow(ValidationError);
    });
  });
});

describe('ConfigLoader', () => {
  let loader: ConfigLoader;

  beforeEach(() => {
    loader = new ConfigLoader();
  });

  const validConfig: FdmsConfig = {
    deviceId: '12345',
    deviceSerialNo: 'SN-001',
    activationKey: 'test-key',
    deviceModelName: 'TestModel',
    deviceModelVersion: '1.0.0',
    certificate: '-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----',
    privateKey: '-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----',
  };

  describe('fromObject', () => {
    it('should return a copy of the configuration', () => {
      const result = loader.fromObject(validConfig);
      expect(result).toEqual(validConfig);
      expect(result).not.toBe(validConfig);
    });
  });

  describe('fromEnvironment', () => {
    const originalEnv = process.env;

    beforeEach(() => {
      process.env = { ...originalEnv };
    });

    afterEach(() => {
      process.env = originalEnv;
    });

    it('should load configuration from environment variables', () => {
      process.env.FDMS_DEVICE_ID = '67890';
      process.env.FDMS_DEVICE_SERIAL_NO = 'SN-ENV';
      process.env.FDMS_ENVIRONMENT = 'production';
      process.env.FDMS_TIMEOUT = '60000';
      process.env.FDMS_ENABLE_AUDIT_LOG = 'false';

      const result = loader.fromEnvironment();

      expect(result.deviceId).toBe('67890');
      expect(result.deviceSerialNo).toBe('SN-ENV');
      expect(result.environment).toBe('production');
      expect(result.timeout).toBe(60000);
      expect(result.enableAuditLog).toBe(false);
    });

    it('should parse boolean values correctly', () => {
      process.env.FDMS_ENABLE_AUDIT_LOG = 'true';
      let result = loader.fromEnvironment();
      expect(result.enableAuditLog).toBe(true);

      process.env.FDMS_ENABLE_AUDIT_LOG = '1';
      result = loader.fromEnvironment();
      expect(result.enableAuditLog).toBe(true);

      process.env.FDMS_ENABLE_AUDIT_LOG = 'false';
      result = loader.fromEnvironment();
      expect(result.enableAuditLog).toBe(false);
    });
  });

  describe('merge', () => {
    it('should merge multiple configurations with priority', () => {
      const base = { deviceId: '111', deviceSerialNo: 'SN-BASE' };
      const override = { deviceId: '222', timeout: 5000 };

      const result = loader.merge(base, override);

      expect(result.deviceId).toBe('222');
      expect(result.deviceSerialNo).toBe('SN-BASE');
      expect(result.timeout).toBe(5000);
    });

    it('should not include undefined values from overrides', () => {
      const base = { deviceId: '111', timeout: 30000 };
      const override = { deviceId: '222', timeout: undefined };

      const result = loader.merge(base, override);

      expect(result.deviceId).toBe('222');
      expect(result.timeout).toBe(30000);
    });
  });

  describe('resolve', () => {
    it('should apply default values', () => {
      const result = loader.resolve(validConfig);

      expect(result.environment).toBe(CONFIG_DEFAULTS.environment);
      expect(result.timeout).toBe(CONFIG_DEFAULTS.timeout);
      expect(result.retryAttempts).toBe(CONFIG_DEFAULTS.retryAttempts);
      expect(result.retryDelay).toBe(CONFIG_DEFAULTS.retryDelay);
      expect(result.enableAuditLog).toBe(CONFIG_DEFAULTS.enableAuditLog);
    });

    it('should set baseUrl based on environment', () => {
      const testResult = loader.resolve({ ...validConfig, environment: 'test' });
      expect(testResult.baseUrl).toBe('https://fdmsapitest.zimra.co.zw');

      const prodResult = loader.resolve({ ...validConfig, environment: 'production' });
      expect(prodResult.baseUrl).toBe('https://fdmsapi.zimra.co.zw');
    });

    it('should allow custom baseUrl', () => {
      const result = loader.resolve({
        ...validConfig,
        baseUrl: 'https://custom.example.com',
      });

      expect(result.baseUrl).toBe('https://custom.example.com');
    });

    it('should preserve optional values when provided', () => {
      const result = loader.resolve({
        ...validConfig,
        timeout: 60000,
        retryAttempts: 5,
        auditLogPath: '/custom/path.log',
      });

      expect(result.timeout).toBe(60000);
      expect(result.retryAttempts).toBe(5);
      expect(result.auditLogPath).toBe('/custom/path.log');
    });
  });

  describe('load', () => {
    it('should load and resolve configuration from object', () => {
      const result = loader.load({ config: validConfig });

      expect(result.deviceId).toBe(validConfig.deviceId);
      expect(result.environment).toBe('test');
      expect(result.baseUrl).toBe('https://fdmsapitest.zimra.co.zw');
    });
  });
});

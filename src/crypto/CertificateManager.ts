/**
 * X.509 certificate management
 * Handles certificate loading, validation, CSR generation, and storage
 * 
 * @module crypto/CertificateManager
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { FdmsError } from '../errors/FdmsError';

/**
 * Certificate format types
 */
export type CertificateFormat = 'PEM' | 'DER';

/**
 * Certificate information extracted from X.509
 */
export interface CertificateInfo {
  /** Certificate subject distinguished name */
  subject: CertificateSubject;
  /** Certificate issuer distinguished name */
  issuer: CertificateSubject;
  /** Certificate serial number */
  serialNumber: string;
  /** Certificate validity start date */
  validFrom: Date;
  /** Certificate validity end date */
  validTo: Date;
  /** Days until certificate expires */
  daysUntilExpiry: number;
  /** Whether the certificate is currently valid */
  isValid: boolean;
  /** Whether the certificate is expired */
  isExpired: boolean;
  /** Whether the certificate expires within warning threshold */
  expiresWithinWarningPeriod: boolean;
  /** Certificate fingerprint (SHA-256) */
  fingerprint: string;
  /** Public key algorithm */
  publicKeyAlgorithm: string;
  /** Key size in bits */
  keySize: number;
}

/**
 * Certificate subject/issuer details
 */
export interface CertificateSubject {
  commonName?: string;
  organization?: string;
  organizationalUnit?: string;
  country?: string;
  state?: string;
  locality?: string;
}

/**
 * CSR (Certificate Signing Request) generation options
 */
export interface CsrOptions {
  /** Common Name (CN) - typically device identifier */
  commonName: string;
  /** Organization (O) - company name */
  organization?: string;
  /** Organizational Unit (OU) */
  organizationalUnit?: string;
  /** Country (C) - 2-letter ISO code */
  country?: string;
  /** State/Province (ST) */
  state?: string;
  /** Locality/City (L) */
  locality?: string;
  /** Email address */
  emailAddress?: string;
}

/**
 * Key pair generation options
 */
export interface KeyPairOptions {
  /** Key size in bits (minimum 2048, recommended 4096) */
  keySize?: number;
  /** Public exponent (default: 65537) */
  publicExponent?: number;
}

/**
 * Certificate storage options
 */
export interface CertificateStorageOptions {
  /** Directory path for certificate storage */
  storagePath: string;
  /** File permissions (default: 0o600 for private keys) */
  filePermissions?: number;
  /** Whether to encrypt private key at rest */
  encryptPrivateKey?: boolean;
  /** Encryption password (required if encryptPrivateKey is true) */
  encryptionPassword?: string;
}

/**
 * Default configuration constants
 */
const CERTIFICATE_DEFAULTS = {
  /** Default RSA key size */
  KEY_SIZE: 4096,
  /** Default public exponent */
  PUBLIC_EXPONENT: 65537,
  /** Days before expiry to start warning */
  EXPIRY_WARNING_DAYS: 30,
  /** Default file permissions for certificates */
  CERT_FILE_PERMISSIONS: 0o644,
  /** Default file permissions for private keys */
  KEY_FILE_PERMISSIONS: 0o600,
} as const;

/**
 * CertificateManager handles X.509 certificate operations for ZIMRA FDMS
 * 
 * Features:
 * - Load certificates from PEM/DER formats
 * - Load private keys with optional password protection
 * - Generate RSA key pairs
 * - Generate Certificate Signing Requests (CSRs)
 * - Validate certificate expiry and chain
 * - Secure certificate/key storage
 * 
 * @example
 * ```typescript
 * const manager = new CertificateManager();
 * 
 * // Load existing certificate
 * const cert = await manager.loadCertificate('./cert.pem');
 * const key = await manager.loadPrivateKey('./key.pem', 'password');
 * 
 * // Generate new key pair and CSR
 * const { publicKey, privateKey } = await manager.generateKeyPair();
 * const csr = await manager.generateCsr(privateKey, { commonName: 'DEVICE123' });
 * ```
 */
export class CertificateManager {
  private certificate: crypto.X509Certificate | null = null;
  private privateKey: crypto.KeyObject | null = null;
  private publicKey: crypto.KeyObject | null = null;
  private readonly expiryWarningDays: number;

  /**
   * Create a new CertificateManager instance
   * 
   * @param expiryWarningDays - Days before expiry to trigger warning (default: 30)
   */
  constructor(expiryWarningDays: number = CERTIFICATE_DEFAULTS.EXPIRY_WARNING_DAYS) {
    this.expiryWarningDays = expiryWarningDays;
  }

  /**
   * Load an X.509 certificate from file path or content
   * Supports both PEM and DER formats
   * 
   * @param certificateInput - File path or certificate content (string or Buffer)
   * @returns Loaded X509Certificate object
   * @throws FdmsError if certificate loading fails
   */
  public async loadCertificate(
    certificateInput: string | Buffer
  ): Promise<crypto.X509Certificate> {
    try {
      const certData = await this.resolveCertificateInput(certificateInput);
      const certBuffer = this.normalizeCertificateData(certData);
      
      this.certificate = new crypto.X509Certificate(certBuffer);
      this.publicKey = this.certificate.publicKey;
      
      return this.certificate;
    } catch (error) {
      throw new FdmsError(
        `Failed to load certificate: ${error instanceof Error ? error.message : 'Unknown error'}`,
        'CRYPTO01',
        undefined,
        { cause: error instanceof Error ? error : undefined }
      );
    }
  }

  /**
   * Load a private key from file path or content
   * Supports PEM and DER formats with optional password protection
   * 
   * @param keyInput - File path or key content (string or Buffer)
   * @param password - Password for encrypted private keys
   * @returns Loaded KeyObject
   * @throws FdmsError if private key loading fails
   */
  public async loadPrivateKey(
    keyInput: string | Buffer,
    password?: string
  ): Promise<crypto.KeyObject> {
    try {
      const keyData = await this.resolveKeyInput(keyInput);
      
      const keyOptions: crypto.PrivateKeyInput = {
        key: keyData,
        format: this.detectKeyFormat(keyData),
        type: this.detectKeyType(keyData),
      };

      if (password) {
        keyOptions.passphrase = password;
      }

      this.privateKey = crypto.createPrivateKey(keyOptions);
      
      // Validate key type (must be RSA for FDMS)
      if (this.privateKey.asymmetricKeyType !== 'rsa') {
        throw new Error(`Unsupported key type: ${this.privateKey.asymmetricKeyType}. Only RSA keys are supported.`);
      }

      return this.privateKey;
    } catch (error) {
      // Handle specific password errors
      if (error instanceof Error && error.message.includes('bad decrypt')) {
        throw new FdmsError(
          'Invalid private key password',
          'CRYPTO02',
          undefined,
          { cause: error }
        );
      }
      
      throw new FdmsError(
        `Failed to load private key: ${error instanceof Error ? error.message : 'Unknown error'}`,
        'CRYPTO03',
        undefined,
        { cause: error instanceof Error ? error : undefined }
      );
    }
  }

  /**
   * Generate a new RSA key pair
   * 
   * @param options - Key generation options
   * @returns Object containing public and private KeyObjects
   * @throws FdmsError if key generation fails
   */
  public async generateKeyPair(
    options: KeyPairOptions = {}
  ): Promise<{ publicKey: crypto.KeyObject; privateKey: crypto.KeyObject }> {
    const keySize = options.keySize ?? CERTIFICATE_DEFAULTS.KEY_SIZE;
    
    // Validate key size (minimum 2048 as per FDMS spec)
    if (keySize < 2048) {
      throw new FdmsError(
        'Key size must be at least 2048 bits for FDMS compliance',
        'CRYPTO04'
      );
    }

    return new Promise((resolve, reject) => {
      crypto.generateKeyPair(
        'rsa',
        {
          modulusLength: keySize,
          publicExponent: options.publicExponent ?? CERTIFICATE_DEFAULTS.PUBLIC_EXPONENT,
          publicKeyEncoding: {
            type: 'spki',
            format: 'pem',
          },
          privateKeyEncoding: {
            type: 'pkcs8',
            format: 'pem',
          },
        },
        (err, publicKeyPem, privateKeyPem) => {
          if (err) {
            reject(
              new FdmsError(
                `Failed to generate key pair: ${err.message}`,
                'CRYPTO05',
                undefined,
                { cause: err }
              )
            );
            return;
          }

          try {
            const publicKey = crypto.createPublicKey(publicKeyPem);
            const privateKey = crypto.createPrivateKey(privateKeyPem);
            
            this.publicKey = publicKey;
            this.privateKey = privateKey;

            resolve({ publicKey, privateKey });
          } catch (parseErr) {
            reject(
              new FdmsError(
                `Failed to parse generated keys: ${parseErr instanceof Error ? parseErr.message : 'Unknown error'}`,
                'CRYPTO06',
                undefined,
                { cause: parseErr instanceof Error ? parseErr : undefined }
              )
            );
          }
        }
      );
    });
  }

  /**
   * Generate a Certificate Signing Request (CSR) for FDMS device registration
   * 
   * @param privateKey - Private key to sign the CSR (or use loaded key)
   * @param options - CSR subject options
   * @returns CSR in PEM format
   * @throws FdmsError if CSR generation fails
   */
  public generateCsr(
    privateKey: crypto.KeyObject | null = null,
    options: CsrOptions
  ): string {
    const key = privateKey ?? this.privateKey;
    
    if (!key) {
      throw new FdmsError(
        'No private key available. Load or generate a private key first.',
        'CRYPTO07'
      );
    }

    if (!options.commonName) {
      throw new FdmsError(
        'Common Name (CN) is required for CSR generation',
        'CRYPTO08'
      );
    }

    try {
      // Build subject DN (Distinguished Name)
      const subjectParts: string[] = [];
      
      if (options.country) {
        subjectParts.push(`C=${options.country}`);
      }
      if (options.state) {
        subjectParts.push(`ST=${options.state}`);
      }
      if (options.locality) {
        subjectParts.push(`L=${options.locality}`);
      }
      if (options.organization) {
        subjectParts.push(`O=${options.organization}`);
      }
      if (options.organizationalUnit) {
        subjectParts.push(`OU=${options.organizationalUnit}`);
      }
      subjectParts.push(`CN=${options.commonName}`);
      
      const subject = subjectParts.join(', ');

      // Create CSR using Node.js crypto
      // Note: Node.js doesn't have native CSR generation, so we use a manual approach
      const csr = this.createCsrManually(key, subject, options.emailAddress);
      
      return csr;
    } catch (error) {
      throw new FdmsError(
        `Failed to generate CSR: ${error instanceof Error ? error.message : 'Unknown error'}`,
        'CRYPTO09',
        undefined,
        { cause: error instanceof Error ? error : undefined }
      );
    }
  }

  /**
   * Get detailed information about the loaded certificate
   * 
   * @returns Certificate information object
   * @throws FdmsError if no certificate is loaded
   */
  public getCertificateInfo(): CertificateInfo {
    if (!this.certificate) {
      throw new FdmsError(
        'No certificate loaded. Load a certificate first.',
        'CRYPTO10'
      );
    }

    const now = new Date();
    const validFrom = new Date(this.certificate.validFrom);
    const validTo = new Date(this.certificate.validTo);
    const daysUntilExpiry = Math.floor(
      (validTo.getTime() - now.getTime()) / (1000 * 60 * 60 * 24)
    );

    return {
      subject: this.parseDistinguishedName(this.certificate.subject),
      issuer: this.parseDistinguishedName(this.certificate.issuer),
      serialNumber: this.certificate.serialNumber,
      validFrom,
      validTo,
      daysUntilExpiry,
      isValid: now >= validFrom && now <= validTo,
      isExpired: now > validTo,
      expiresWithinWarningPeriod: daysUntilExpiry <= this.expiryWarningDays,
      fingerprint: this.certificate.fingerprint256,
      publicKeyAlgorithm: this.certificate.publicKey.asymmetricKeyType ?? 'unknown',
      keySize: this.getKeySize(this.certificate.publicKey),
    };
  }

  /**
   * Validate the loaded certificate
   * Checks expiry, key size, and algorithm requirements
   * 
   * @returns Validation result with any issues found
   */
  public validateCertificate(): {
    valid: boolean;
    issues: string[];
    warnings: string[];
  } {
    const issues: string[] = [];
    const warnings: string[] = [];

    if (!this.certificate) {
      return {
        valid: false,
        issues: ['No certificate loaded'],
        warnings: [],
      };
    }

    const info = this.getCertificateInfo();

    // Check if expired
    if (info.isExpired) {
      issues.push(`Certificate expired on ${info.validTo.toISOString()}`);
    }

    // Check if not yet valid
    if (new Date() < info.validFrom) {
      issues.push(`Certificate not yet valid. Valid from ${info.validFrom.toISOString()}`);
    }

    // Check expiry warning
    if (!info.isExpired && info.expiresWithinWarningPeriod) {
      warnings.push(
        `Certificate expires in ${info.daysUntilExpiry} days (${info.validTo.toISOString()})`
      );
    }

    // Check key algorithm
    if (info.publicKeyAlgorithm !== 'rsa') {
      issues.push(
        `Unsupported key algorithm: ${info.publicKeyAlgorithm}. Only RSA is supported.`
      );
    }

    // Check key size (minimum 2048 bits)
    if (info.keySize < 2048) {
      issues.push(
        `Key size ${info.keySize} bits is below minimum requirement of 2048 bits`
      );
    }

    // Warn if key size is less than recommended
    if (info.keySize >= 2048 && info.keySize < 4096) {
      warnings.push(
        `Key size ${info.keySize} bits is acceptable but 4096 bits is recommended`
      );
    }

    return {
      valid: issues.length === 0,
      issues,
      warnings,
    };
  }

  /**
   * Verify that the loaded private key matches the loaded certificate
   * 
   * @returns True if key pair matches
   * @throws FdmsError if certificate or private key not loaded
   */
  public verifyKeyPairMatch(): boolean {
    if (!this.certificate || !this.privateKey) {
      throw new FdmsError(
        'Both certificate and private key must be loaded to verify match',
        'CRYPTO11'
      );
    }

    try {
      // Create a test message and sign/verify to confirm key match
      const testData = crypto.randomBytes(32);
      
      const signature = crypto.sign('sha256', testData, this.privateKey);
      const isValid = crypto.verify(
        'sha256',
        testData,
        this.certificate.publicKey,
        signature
      );

      return isValid;
    } catch {
      return false;
    }
  }

  /**
   * Store certificate to file with proper permissions
   * 
   * @param certificate - Certificate to store (or use loaded certificate)
   * @param filePath - Destination file path
   * @param format - Output format (PEM or DER)
   */
  public async storeCertificate(
    certificate: crypto.X509Certificate | null = null,
    filePath: string,
    format: CertificateFormat = 'PEM'
  ): Promise<void> {
    const cert = certificate ?? this.certificate;
    
    if (!cert) {
      throw new FdmsError(
        'No certificate to store. Load or provide a certificate.',
        'CRYPTO12'
      );
    }

    try {
      // Ensure directory exists
      const dir = path.dirname(filePath);
      await fs.promises.mkdir(dir, { recursive: true });

      let content: string | Buffer;
      if (format === 'PEM') {
        content = cert.toString();
      } else {
        content = Buffer.from(cert.raw);
      }

      await fs.promises.writeFile(filePath, content);
      await fs.promises.chmod(filePath, CERTIFICATE_DEFAULTS.CERT_FILE_PERMISSIONS);
    } catch (error) {
      throw new FdmsError(
        `Failed to store certificate: ${error instanceof Error ? error.message : 'Unknown error'}`,
        'CRYPTO13',
        undefined,
        { cause: error instanceof Error ? error : undefined }
      );
    }
  }

  /**
   * Store private key to file with secure permissions (0600)
   * 
   * @param privateKey - Private key to store (or use loaded key)
   * @param filePath - Destination file path
   * @param password - Optional password to encrypt the key
   */
  public async storePrivateKey(
    privateKey: crypto.KeyObject | null = null,
    filePath: string,
    password?: string
  ): Promise<void> {
    const key = privateKey ?? this.privateKey;
    
    if (!key) {
      throw new FdmsError(
        'No private key to store. Load or provide a private key.',
        'CRYPTO14'
      );
    }

    try {
      // Ensure directory exists
      const dir = path.dirname(filePath);
      await fs.promises.mkdir(dir, { recursive: true });

      const exportOptions: crypto.KeyExportOptions<'pem'> = {
        type: 'pkcs8',
        format: 'pem',
      };

      if (password) {
        exportOptions.cipher = 'aes-256-cbc';
        exportOptions.passphrase = password;
      }

      const keyPem = key.export(exportOptions);

      await fs.promises.writeFile(filePath, keyPem);
      // Set restrictive permissions (owner read/write only)
      await fs.promises.chmod(filePath, CERTIFICATE_DEFAULTS.KEY_FILE_PERMISSIONS);
    } catch (error) {
      throw new FdmsError(
        `Failed to store private key: ${error instanceof Error ? error.message : 'Unknown error'}`,
        'CRYPTO15',
        undefined,
        { cause: error instanceof Error ? error : undefined }
      );
    }
  }

  /**
   * Export public key in PEM format
   * 
   * @returns Public key in PEM format
   */
  public exportPublicKey(): string {
    if (!this.publicKey) {
      throw new FdmsError(
        'No public key available. Load a certificate or generate a key pair.',
        'CRYPTO16'
      );
    }

    return this.publicKey.export({
      type: 'spki',
      format: 'pem',
    }) as string;
  }

  /**
   * Export private key in PEM format (optionally encrypted)
   * 
   * @param password - Optional password to encrypt the key
   * @returns Private key in PEM format
   */
  public exportPrivateKey(password?: string): string {
    if (!this.privateKey) {
      throw new FdmsError(
        'No private key available. Load or generate a private key.',
        'CRYPTO17'
      );
    }

    const exportOptions: crypto.KeyExportOptions<'pem'> = {
      type: 'pkcs8',
      format: 'pem',
    };

    if (password) {
      exportOptions.cipher = 'aes-256-cbc';
      exportOptions.passphrase = password;
    }

    return this.privateKey.export(exportOptions) as string;
  }

  /**
   * Get the loaded certificate
   */
  public getCertificate(): crypto.X509Certificate | null {
    return this.certificate;
  }

  /**
   * Get the loaded private key
   */
  public getPrivateKey(): crypto.KeyObject | null {
    return this.privateKey;
  }

  /**
   * Get the public key (from certificate or generated key pair)
   */
  public getPublicKey(): crypto.KeyObject | null {
    return this.publicKey;
  }

  /**
   * Check if certificate needs renewal (within warning period)
   */
  public needsRenewal(): boolean {
    if (!this.certificate) {
      return false;
    }
    
    const info = this.getCertificateInfo();
    return info.isExpired || info.expiresWithinWarningPeriod;
  }

  /**
   * Clear all loaded certificates and keys from memory
   */
  public clear(): void {
    this.certificate = null;
    this.privateKey = null;
    this.publicKey = null;
  }

  // ============ Private Helper Methods ============

  /**
   * Resolve certificate input to actual certificate data
   */
  private async resolveCertificateInput(input: string | Buffer): Promise<Buffer> {
    if (Buffer.isBuffer(input)) {
      return input;
    }

    // Check if it's a file path
    if (this.isFilePath(input)) {
      return fs.promises.readFile(input);
    }

    // Assume it's certificate content
    return Buffer.from(input, 'utf-8');
  }

  /**
   * Resolve key input to actual key data
   */
  private async resolveKeyInput(input: string | Buffer): Promise<Buffer> {
    if (Buffer.isBuffer(input)) {
      return input;
    }

    // Check if it's a file path
    if (this.isFilePath(input)) {
      return fs.promises.readFile(input);
    }

    // Assume it's key content
    return Buffer.from(input, 'utf-8');
  }

  /**
   * Check if input string is a file path
   */
  private isFilePath(input: string): boolean {
    // Check for PEM headers - if present, it's content, not a path
    if (input.includes('-----BEGIN')) {
      return false;
    }
    
    // Check for common certificate/key file extensions
    const extensions = ['.pem', '.der', '.crt', '.cer', '.key', '.p8', '.pkcs8'];
    const ext = path.extname(input).toLowerCase();
    
    if (extensions.includes(ext)) {
      return true;
    }

    // Check if file exists
    try {
      fs.accessSync(input, fs.constants.R_OK);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Normalize certificate data (handle PEM/DER format detection)
   */
  private normalizeCertificateData(data: Buffer): Buffer {
    const str = data.toString('utf-8');
    
    // If it's PEM format, return as-is
    if (str.includes('-----BEGIN CERTIFICATE-----')) {
      return data;
    }

    // If it looks like base64 without headers, wrap it in PEM format
    if (/^[A-Za-z0-9+/=\s]+$/.test(str.trim())) {
      const base64 = str.replace(/\s/g, '');
      return Buffer.from(
        `-----BEGIN CERTIFICATE-----\n${base64}\n-----END CERTIFICATE-----`,
        'utf-8'
      );
    }

    // Assume it's DER format
    return data;
  }

  /**
   * Detect key format from key data
   */
  private detectKeyFormat(data: Buffer): 'pem' | 'der' {
    const str = data.toString('utf-8');
    return str.includes('-----BEGIN') ? 'pem' : 'der';
  }

  /**
   * Detect key type from key data
   */
  private detectKeyType(data: Buffer): 'pkcs1' | 'pkcs8' | 'sec1' {
    const str = data.toString('utf-8');
    
    if (str.includes('BEGIN RSA PRIVATE KEY')) {
      return 'pkcs1';
    }
    if (str.includes('BEGIN EC PRIVATE KEY')) {
      return 'sec1';
    }
    
    // Default to PKCS#8
    return 'pkcs8';
  }

  /**
   * Parse Distinguished Name string into components
   */
  private parseDistinguishedName(dn: string): CertificateSubject {
    const result: CertificateSubject = {};
    
    // Parse DN components (format: "CN=name, O=org, ...")
    const parts = dn.split(/,\s*/);
    
    for (const part of parts) {
      const [key, ...valueParts] = part.split('=');
      const value = valueParts.join('=').trim();
      
      switch (key?.trim().toUpperCase()) {
        case 'CN':
          result.commonName = value;
          break;
        case 'O':
          result.organization = value;
          break;
        case 'OU':
          result.organizationalUnit = value;
          break;
        case 'C':
          result.country = value;
          break;
        case 'ST':
          result.state = value;
          break;
        case 'L':
          result.locality = value;
          break;
      }
    }
    
    return result;
  }

  /**
   * Get key size from a KeyObject
   */
  private getKeySize(key: crypto.KeyObject): number {
    // Export public key to get details
    const keyDetails = key.asymmetricKeyDetails;
    return keyDetails?.modulusLength ?? 0;
  }

  /**
   * Create CSR manually using Node.js crypto
   * This builds a PKCS#10 CSR structure
   */
  private createCsrManually(
    privateKey: crypto.KeyObject,
    subject: string,
    emailAddress?: string
  ): string {
    // Build the subject DN in ASN.1 format
    const subjectDer = this.buildSubjectDer(subject, emailAddress);
    
    // Get public key from private key
    const publicKey = crypto.createPublicKey(privateKey);
    const publicKeyDer = publicKey.export({ type: 'spki', format: 'der' });
    
    // Build CSR Info structure
    const csrInfo = this.buildCsrInfo(subjectDer, publicKeyDer as Buffer);
    
    // Sign the CSR Info
    const signature = crypto.sign('sha256', csrInfo, privateKey);
    
    // Build final CSR structure
    const csr = this.buildCsrStructure(csrInfo, signature);
    
    // Convert to PEM
    const base64 = csr.toString('base64');
    const pemLines = base64.match(/.{1,64}/g) ?? [];
    
    return [
      '-----BEGIN CERTIFICATE REQUEST-----',
      ...pemLines,
      '-----END CERTIFICATE REQUEST-----',
    ].join('\n');
  }

  /**
   * Build subject DN in DER format
   */
  private buildSubjectDer(subject: string, emailAddress?: string): Buffer {
    const rdnSequence: Buffer[] = [];
    const parts = subject.split(/,\s*/);
    
    for (const part of parts) {
      const [key, ...valueParts] = part.split('=');
      const value = valueParts.join('=').trim();
      const oid = this.getAttributeOid(key?.trim() ?? '');
      
      if (oid && value) {
        rdnSequence.push(this.buildRdn(oid, value));
      }
    }
    
    if (emailAddress) {
      rdnSequence.push(this.buildRdn([1, 2, 840, 113549, 1, 9, 1], emailAddress, true));
    }
    
    // Combine all RDNs into a SEQUENCE
    return this.asn1Sequence(Buffer.concat(rdnSequence));
  }

  /**
   * Get OID for attribute type
   */
  private getAttributeOid(attr: string): number[] | null {
    const oids: Record<string, number[]> = {
      'C': [2, 5, 4, 6],
      'ST': [2, 5, 4, 8],
      'L': [2, 5, 4, 7],
      'O': [2, 5, 4, 10],
      'OU': [2, 5, 4, 11],
      'CN': [2, 5, 4, 3],
    };
    return oids[attr.toUpperCase()] ?? null;
  }

  /**
   * Build a single RDN (Relative Distinguished Name)
   */
  private buildRdn(oid: number[], value: string, isIA5String: boolean = false): Buffer {
    const oidBuffer = this.encodeOid(oid);
    const valueBuffer = isIA5String 
      ? this.asn1IA5String(value)
      : this.asn1Utf8String(value);
    
    const attrTypeAndValue = this.asn1Sequence(
      Buffer.concat([oidBuffer, valueBuffer])
    );
    
    return this.asn1Set(attrTypeAndValue);
  }

  /**
   * Build CSR Info structure
   */
  private buildCsrInfo(subjectDer: Buffer, publicKeyDer: Buffer): Buffer {
    // Version (0)
    const version = Buffer.from([0x02, 0x01, 0x00]);
    
    // Attributes (empty SET)
    const attributes = Buffer.from([0xa0, 0x00]);
    
    return this.asn1Sequence(
      Buffer.concat([version, subjectDer, publicKeyDer, attributes])
    );
  }

  /**
   * Build final CSR structure with signature
   */
  private buildCsrStructure(csrInfo: Buffer, signature: Buffer): Buffer {
    // Signature algorithm (SHA256 with RSA)
    const signatureAlgorithm = this.asn1Sequence(
      Buffer.concat([
        this.encodeOid([1, 2, 840, 113549, 1, 1, 11]), // sha256WithRSAEncryption
        Buffer.from([0x05, 0x00]), // NULL
      ])
    );
    
    // Signature as BIT STRING
    const signatureBitString = this.asn1BitString(signature);
    
    return this.asn1Sequence(
      Buffer.concat([csrInfo, signatureAlgorithm, signatureBitString])
    );
  }

  // ASN.1 encoding helpers
  
  private asn1Sequence(content: Buffer): Buffer {
    return this.asn1Wrap(0x30, content);
  }

  private asn1Set(content: Buffer): Buffer {
    return this.asn1Wrap(0x31, content);
  }

  private asn1Utf8String(str: string): Buffer {
    return this.asn1Wrap(0x0c, Buffer.from(str, 'utf-8'));
  }

  private asn1IA5String(str: string): Buffer {
    return this.asn1Wrap(0x16, Buffer.from(str, 'ascii'));
  }

  private asn1BitString(content: Buffer): Buffer {
    // Add leading zero byte for unused bits count
    const withPadding = Buffer.concat([Buffer.from([0x00]), content]);
    return this.asn1Wrap(0x03, withPadding);
  }

  private asn1Wrap(tag: number, content: Buffer): Buffer {
    const length = this.encodeLength(content.length);
    return Buffer.concat([Buffer.from([tag]), length, content]);
  }

  private encodeLength(length: number): Buffer {
    if (length < 128) {
      return Buffer.from([length]);
    }
    
    const bytes: number[] = [];
    let remaining = length;
    
    while (remaining > 0) {
      bytes.unshift(remaining & 0xff);
      remaining = remaining >> 8;
    }
    
    return Buffer.from([0x80 | bytes.length, ...bytes]);
  }

  private encodeOid(oid: number[]): Buffer {
    if (oid.length < 2) {
      throw new Error('Invalid OID');
    }
    
    const bytes: number[] = [];
    
    // First two components
    bytes.push(oid[0] * 40 + oid[1]);
    
    // Remaining components
    for (let i = 2; i < oid.length; i++) {
      const value = oid[i];
      if (value < 128) {
        bytes.push(value);
      } else {
        const encoded: number[] = [];
        let v = value;
        encoded.unshift(v & 0x7f);
        v = v >> 7;
        while (v > 0) {
          encoded.unshift((v & 0x7f) | 0x80);
          v = v >> 7;
        }
        bytes.push(...encoded);
      }
    }
    
    return this.asn1Wrap(0x06, Buffer.from(bytes));
  }
}

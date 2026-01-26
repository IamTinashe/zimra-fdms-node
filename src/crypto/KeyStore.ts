/**
 * Secure key storage
 * Manages private keys with proper security practices
 * 
 * @module crypto/KeyStore
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { FdmsError } from '../errors/FdmsError';

/**
 * Key store entry metadata
 */
export interface KeyStoreEntry {
  /** Unique alias for the key */
  alias: string;
  /** Type of entry (privateKey, certificate, or both) */
  type: 'privateKey' | 'certificate' | 'keypair';
  /** Creation timestamp */
  createdAt: Date;
  /** Last modified timestamp */
  modifiedAt: Date;
  /** Certificate subject CN if available */
  commonName?: string;
  /** Certificate expiry date if available */
  expiryDate?: Date;
}

/**
 * Key store configuration options
 */
export interface KeyStoreOptions {
  /** Path to the key store file */
  storePath: string;
  /** Password to encrypt/decrypt the key store */
  password: string;
  /** Key derivation iterations (default: 100000) */
  iterations?: number;
  /** Auto-save on changes (default: true) */
  autoSave?: boolean;
}

/**
 * Stored key data structure
 */
interface StoredKeyData {
  /** Encrypted private key (if present) */
  encryptedPrivateKey?: string;
  /** Initialization vector for private key encryption */
  privateKeyIv?: string;
  /** Auth tag for private key encryption (GCM mode) */
  privateKeyAuthTag?: string;
  /** Certificate in PEM format (not encrypted) */
  certificate?: string;
  /** Entry metadata */
  metadata: {
    alias: string;
    type: 'privateKey' | 'certificate' | 'keypair';
    createdAt: string;
    modifiedAt: string;
    commonName?: string;
    expiryDate?: string;
  };
}

/**
 * Key store file format
 */
interface KeyStoreData {
  version: number;
  salt: string;
  entries: Record<string, StoredKeyData>;
}

/**
 * Default configuration constants
 */
const KEYSTORE_DEFAULTS = {
  VERSION: 1,
  ITERATIONS: 100000,
  KEY_LENGTH: 32,
  SALT_LENGTH: 32,
  IV_LENGTH: 16,
  ALGORITHM: 'aes-256-gcm',
  HASH_ALGORITHM: 'sha512',
  FILE_PERMISSIONS: 0o600,
} as const;

/**
 * KeyStore provides secure storage for private keys and certificates
 * 
 * Features:
 * - AES-256-GCM encryption for private keys
 * - PBKDF2 key derivation with configurable iterations
 * - Secure file permissions (0600)
 * - Atomic file writes to prevent corruption
 * - Support for multiple key aliases
 * 
 * Security Notes:
 * - Private keys are encrypted at rest
 * - Certificates are stored unencrypted (public data)
 * - Master password is never stored
 * - Salt is unique per key store
 * 
 * @example
 * ```typescript
 * const keyStore = new KeyStore({
 *   storePath: './keystore.json',
 *   password: 'secure-password'
 * });
 * 
 * await keyStore.load();
 * await keyStore.setKeyPair('device-123', privateKey, certificate);
 * await keyStore.save();
 * ```
 */
export class KeyStore {
  private readonly storePath: string;
  private readonly password: string;
  private readonly iterations: number;
  private readonly autoSave: boolean;
  private data: KeyStoreData | null = null;
  private derivedKey: Buffer | null = null;
  private isLoaded: boolean = false;

  /**
   * Create a new KeyStore instance
   * 
   * @param options - Key store configuration options
   */
  constructor(options: KeyStoreOptions) {
    if (!options.storePath) {
      throw new FdmsError('Key store path is required', 'CRYPTO20');
    }
    if (!options.password) {
      throw new FdmsError('Key store password is required', 'CRYPTO21');
    }
    if (options.password.length < 8) {
      throw new FdmsError('Key store password must be at least 8 characters', 'CRYPTO22');
    }

    this.storePath = path.resolve(options.storePath);
    this.password = options.password;
    this.iterations = options.iterations ?? KEYSTORE_DEFAULTS.ITERATIONS;
    this.autoSave = options.autoSave ?? true;
  }

  /**
   * Load an existing key store or create a new one
   * 
   * @throws FdmsError if key store cannot be loaded or decrypted
   */
  public async load(): Promise<void> {
    try {
      const exists = await this.fileExists(this.storePath);

      if (exists) {
        const content = await fs.promises.readFile(this.storePath, 'utf-8');
        this.data = JSON.parse(content) as KeyStoreData;

        // Validate version
        if (this.data.version !== KEYSTORE_DEFAULTS.VERSION) {
          throw new Error(`Unsupported key store version: ${this.data.version}`);
        }

        // Derive encryption key from password and stored salt
        this.derivedKey = await this.deriveKey(
          this.password,
          Buffer.from(this.data.salt, 'hex')
        );
      } else {
        // Create new key store
        const salt = crypto.randomBytes(KEYSTORE_DEFAULTS.SALT_LENGTH);
        this.derivedKey = await this.deriveKey(this.password, salt);

        this.data = {
          version: KEYSTORE_DEFAULTS.VERSION,
          salt: salt.toString('hex'),
          entries: {},
        };

        if (this.autoSave) {
          await this.save();
        }
      }

      this.isLoaded = true;
    } catch (error) {
      if (error instanceof FdmsError) {
        throw error;
      }
      throw new FdmsError(
        `Failed to load key store: ${error instanceof Error ? error.message : 'Unknown error'}`,
        'CRYPTO23',
        undefined,
        { cause: error instanceof Error ? error : undefined }
      );
    }
  }

  /**
   * Save the key store to disk
   * Uses atomic write to prevent corruption
   * 
   * @throws FdmsError if save fails
   */
  public async save(): Promise<void> {
    if (!this.data) {
      throw new FdmsError('Key store not initialized. Call load() first.', 'CRYPTO24');
    }

    try {
      const dir = path.dirname(this.storePath);
      await fs.promises.mkdir(dir, { recursive: true });

      // Atomic write: write to temp file, then rename
      const tempPath = `${this.storePath}.tmp`;
      const content = JSON.stringify(this.data, null, 2);

      await fs.promises.writeFile(tempPath, content, 'utf-8');
      await fs.promises.chmod(tempPath, KEYSTORE_DEFAULTS.FILE_PERMISSIONS);
      await fs.promises.rename(tempPath, this.storePath);
    } catch (error) {
      throw new FdmsError(
        `Failed to save key store: ${error instanceof Error ? error.message : 'Unknown error'}`,
        'CRYPTO25',
        undefined,
        { cause: error instanceof Error ? error : undefined }
      );
    }
  }

  /**
   * Store a private key in the key store
   * 
   * @param alias - Unique identifier for the key
   * @param privateKey - Private key to store
   * @param overwrite - Whether to overwrite existing entry (default: false)
   */
  public async setPrivateKey(
    alias: string,
    privateKey: crypto.KeyObject,
    overwrite: boolean = false
  ): Promise<void> {
    this.ensureLoaded();
    
    if (!overwrite && this.data!.entries[alias]) {
      throw new FdmsError(
        `Entry with alias '${alias}' already exists. Set overwrite=true to replace.`,
        'CRYPTO26'
      );
    }

    const encrypted = this.encryptPrivateKey(privateKey);
    const now = new Date();

    const existingEntry = this.data!.entries[alias];
    
    this.data!.entries[alias] = {
      encryptedPrivateKey: encrypted.ciphertext,
      privateKeyIv: encrypted.iv,
      privateKeyAuthTag: encrypted.authTag,
      certificate: existingEntry?.certificate,
      metadata: {
        alias,
        type: existingEntry?.certificate ? 'keypair' : 'privateKey',
        createdAt: existingEntry?.metadata.createdAt ?? now.toISOString(),
        modifiedAt: now.toISOString(),
        commonName: existingEntry?.metadata.commonName,
        expiryDate: existingEntry?.metadata.expiryDate,
      },
    };

    if (this.autoSave) {
      await this.save();
    }
  }

  /**
   * Store a certificate in the key store
   * 
   * @param alias - Unique identifier for the certificate
   * @param certificate - X.509 certificate to store
   * @param overwrite - Whether to overwrite existing entry (default: false)
   */
  public async setCertificate(
    alias: string,
    certificate: crypto.X509Certificate,
    overwrite: boolean = false
  ): Promise<void> {
    this.ensureLoaded();
    
    if (!overwrite && this.data!.entries[alias]?.certificate) {
      throw new FdmsError(
        `Certificate with alias '${alias}' already exists. Set overwrite=true to replace.`,
        'CRYPTO27'
      );
    }

    const now = new Date();
    const existingEntry = this.data!.entries[alias];
    const certInfo = this.extractCertificateInfo(certificate);

    this.data!.entries[alias] = {
      encryptedPrivateKey: existingEntry?.encryptedPrivateKey,
      privateKeyIv: existingEntry?.privateKeyIv,
      privateKeyAuthTag: existingEntry?.privateKeyAuthTag,
      certificate: certificate.toString(),
      metadata: {
        alias,
        type: existingEntry?.encryptedPrivateKey ? 'keypair' : 'certificate',
        createdAt: existingEntry?.metadata.createdAt ?? now.toISOString(),
        modifiedAt: now.toISOString(),
        commonName: certInfo.commonName,
        expiryDate: certInfo.expiryDate?.toISOString(),
      },
    };

    if (this.autoSave) {
      await this.save();
    }
  }

  /**
   * Store both private key and certificate together
   * 
   * @param alias - Unique identifier for the key pair
   * @param privateKey - Private key to store
   * @param certificate - X.509 certificate to store
   * @param overwrite - Whether to overwrite existing entry (default: false)
   */
  public async setKeyPair(
    alias: string,
    privateKey: crypto.KeyObject,
    certificate: crypto.X509Certificate,
    overwrite: boolean = false
  ): Promise<void> {
    this.ensureLoaded();
    
    if (!overwrite && this.data!.entries[alias]) {
      throw new FdmsError(
        `Entry with alias '${alias}' already exists. Set overwrite=true to replace.`,
        'CRYPTO28'
      );
    }

    const encrypted = this.encryptPrivateKey(privateKey);
    const certInfo = this.extractCertificateInfo(certificate);
    const now = new Date();

    this.data!.entries[alias] = {
      encryptedPrivateKey: encrypted.ciphertext,
      privateKeyIv: encrypted.iv,
      privateKeyAuthTag: encrypted.authTag,
      certificate: certificate.toString(),
      metadata: {
        alias,
        type: 'keypair',
        createdAt: now.toISOString(),
        modifiedAt: now.toISOString(),
        commonName: certInfo.commonName,
        expiryDate: certInfo.expiryDate?.toISOString(),
      },
    };

    if (this.autoSave) {
      await this.save();
    }
  }

  /**
   * Retrieve a private key from the key store
   * 
   * @param alias - Alias of the key to retrieve
   * @returns Decrypted private key
   * @throws FdmsError if key not found or decryption fails
   */
  public getPrivateKey(alias: string): crypto.KeyObject {
    this.ensureLoaded();

    const entry = this.data!.entries[alias];
    if (!entry?.encryptedPrivateKey) {
      throw new FdmsError(
        `Private key not found for alias '${alias}'`,
        'CRYPTO29'
      );
    }

    return this.decryptPrivateKey(
      entry.encryptedPrivateKey,
      entry.privateKeyIv!,
      entry.privateKeyAuthTag!
    );
  }

  /**
   * Retrieve a certificate from the key store
   * 
   * @param alias - Alias of the certificate to retrieve
   * @returns X.509 certificate
   * @throws FdmsError if certificate not found
   */
  public getCertificate(alias: string): crypto.X509Certificate {
    this.ensureLoaded();

    const entry = this.data!.entries[alias];
    if (!entry?.certificate) {
      throw new FdmsError(
        `Certificate not found for alias '${alias}'`,
        'CRYPTO30'
      );
    }

    return new crypto.X509Certificate(entry.certificate);
  }

  /**
   * Check if an entry exists in the key store
   * 
   * @param alias - Alias to check
   * @returns True if entry exists
   */
  public hasEntry(alias: string): boolean {
    this.ensureLoaded();
    return alias in this.data!.entries;
  }

  /**
   * Check if a private key exists for the given alias
   * 
   * @param alias - Alias to check
   * @returns True if private key exists
   */
  public hasPrivateKey(alias: string): boolean {
    this.ensureLoaded();
    return !!this.data!.entries[alias]?.encryptedPrivateKey;
  }

  /**
   * Check if a certificate exists for the given alias
   * 
   * @param alias - Alias to check
   * @returns True if certificate exists
   */
  public hasCertificate(alias: string): boolean {
    this.ensureLoaded();
    return !!this.data!.entries[alias]?.certificate;
  }

  /**
   * Delete an entry from the key store
   * 
   * @param alias - Alias of the entry to delete
   * @returns True if entry was deleted, false if not found
   */
  public async deleteEntry(alias: string): Promise<boolean> {
    this.ensureLoaded();

    if (!(alias in this.data!.entries)) {
      return false;
    }

    delete this.data!.entries[alias];

    if (this.autoSave) {
      await this.save();
    }

    return true;
  }

  /**
   * List all entries in the key store
   * 
   * @returns Array of entry metadata
   */
  public listEntries(): KeyStoreEntry[] {
    this.ensureLoaded();

    return Object.values(this.data!.entries).map((entry) => ({
      alias: entry.metadata.alias,
      type: entry.metadata.type,
      createdAt: new Date(entry.metadata.createdAt),
      modifiedAt: new Date(entry.metadata.modifiedAt),
      commonName: entry.metadata.commonName,
      expiryDate: entry.metadata.expiryDate
        ? new Date(entry.metadata.expiryDate)
        : undefined,
    }));
  }

  /**
   * Get entries that will expire within the specified number of days
   * 
   * @param days - Number of days to check
   * @returns Array of entries expiring soon
   */
  public getExpiringEntries(days: number): KeyStoreEntry[] {
    const now = new Date();
    const threshold = new Date(now.getTime() + days * 24 * 60 * 60 * 1000);

    return this.listEntries().filter((entry) => {
      if (!entry.expiryDate) {
        return false;
      }
      return entry.expiryDate <= threshold;
    });
  }

  /**
   * Change the key store password
   * Re-encrypts all private keys with the new password
   * 
   * @param newPassword - New password (minimum 8 characters)
   */
  public async changePassword(newPassword: string): Promise<void> {
    this.ensureLoaded();

    if (newPassword.length < 8) {
      throw new FdmsError(
        'New password must be at least 8 characters',
        'CRYPTO31'
      );
    }

    // Decrypt all private keys with old password
    const decryptedKeys: Map<string, crypto.KeyObject> = new Map();
    for (const [alias, entry] of Object.entries(this.data!.entries)) {
      if (entry.encryptedPrivateKey) {
        decryptedKeys.set(alias, this.decryptPrivateKey(
          entry.encryptedPrivateKey,
          entry.privateKeyIv!,
          entry.privateKeyAuthTag!
        ));
      }
    }

    // Generate new salt and derive new key
    const newSalt = crypto.randomBytes(KEYSTORE_DEFAULTS.SALT_LENGTH);
    this.derivedKey = await this.deriveKey(newPassword, newSalt);
    this.data!.salt = newSalt.toString('hex');

    // Re-encrypt all private keys with new password
    for (const [alias, privateKey] of decryptedKeys) {
      const encrypted = this.encryptPrivateKey(privateKey);
      this.data!.entries[alias].encryptedPrivateKey = encrypted.ciphertext;
      this.data!.entries[alias].privateKeyIv = encrypted.iv;
      this.data!.entries[alias].privateKeyAuthTag = encrypted.authTag;
    }

    await this.save();
  }

  /**
   * Export the key store to a new location
   * 
   * @param exportPath - Path to export to
   * @param newPassword - Optional new password for the export
   */
  public async export(exportPath: string, newPassword?: string): Promise<void> {
    this.ensureLoaded();

    if (newPassword) {
      // Create a temporary key store with new password
      const tempStore = new KeyStore({
        storePath: exportPath,
        password: newPassword,
        iterations: this.iterations,
        autoSave: false,
      });

      // Initialize with new salt
      const salt = crypto.randomBytes(KEYSTORE_DEFAULTS.SALT_LENGTH);
      tempStore.derivedKey = await this.deriveKey(newPassword, salt);
      tempStore.data = {
        version: KEYSTORE_DEFAULTS.VERSION,
        salt: salt.toString('hex'),
        entries: {},
      };
      tempStore.isLoaded = true;

      // Copy and re-encrypt entries
      for (const [alias, entry] of Object.entries(this.data!.entries)) {
        if (entry.encryptedPrivateKey) {
          const privateKey = this.decryptPrivateKey(
            entry.encryptedPrivateKey,
            entry.privateKeyIv!,
            entry.privateKeyAuthTag!
          );
          const encrypted = tempStore.encryptPrivateKey(privateKey);
          tempStore.data!.entries[alias] = {
            ...entry,
            encryptedPrivateKey: encrypted.ciphertext,
            privateKeyIv: encrypted.iv,
            privateKeyAuthTag: encrypted.authTag,
          };
        } else {
          tempStore.data!.entries[alias] = { ...entry };
        }
      }

      await tempStore.save();
    } else {
      // Simple copy with same password
      const content = JSON.stringify(this.data, null, 2);
      const dir = path.dirname(exportPath);
      await fs.promises.mkdir(dir, { recursive: true });
      await fs.promises.writeFile(exportPath, content, 'utf-8');
      await fs.promises.chmod(exportPath, KEYSTORE_DEFAULTS.FILE_PERMISSIONS);
    }
  }

  /**
   * Clear all entries from the key store
   */
  public async clear(): Promise<void> {
    this.ensureLoaded();
    this.data!.entries = {};
    
    if (this.autoSave) {
      await this.save();
    }
  }

  /**
   * Get the number of entries in the key store
   */
  public get size(): number {
    if (!this.data) {
      return 0;
    }
    return Object.keys(this.data.entries).length;
  }

  /**
   * Check if the key store has been loaded
   */
  public get loaded(): boolean {
    return this.isLoaded;
  }

  // ============ Private Helper Methods ============

  /**
   * Ensure the key store is loaded before operations
   */
  private ensureLoaded(): void {
    if (!this.isLoaded || !this.data || !this.derivedKey) {
      throw new FdmsError(
        'Key store not loaded. Call load() first.',
        'CRYPTO32'
      );
    }
  }

  /**
   * Derive encryption key from password using PBKDF2
   */
  private async deriveKey(password: string, salt: Buffer): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      crypto.pbkdf2(
        password,
        salt,
        this.iterations,
        KEYSTORE_DEFAULTS.KEY_LENGTH,
        KEYSTORE_DEFAULTS.HASH_ALGORITHM,
        (err, key) => {
          if (err) {
            reject(
              new FdmsError(
                `Key derivation failed: ${err.message}`,
                'CRYPTO33',
                undefined,
                { cause: err }
              )
            );
          } else {
            resolve(key);
          }
        }
      );
    });
  }

  /**
   * Encrypt a private key using AES-256-GCM
   */
  private encryptPrivateKey(privateKey: crypto.KeyObject): {
    ciphertext: string;
    iv: string;
    authTag: string;
  } {
    if (!this.derivedKey) {
      throw new FdmsError('Encryption key not available', 'CRYPTO34');
    }

    // Export private key to PEM format
    const keyPem = privateKey.export({
      type: 'pkcs8',
      format: 'pem',
    }) as string;

    // Generate random IV
    const iv = crypto.randomBytes(KEYSTORE_DEFAULTS.IV_LENGTH);

    // Encrypt using AES-256-GCM
    const cipher = crypto.createCipheriv(
      KEYSTORE_DEFAULTS.ALGORITHM,
      this.derivedKey,
      iv
    ) as crypto.CipherGCM;

    const encrypted = Buffer.concat([
      cipher.update(keyPem, 'utf-8'),
      cipher.final(),
    ]);

    const authTag = cipher.getAuthTag();

    return {
      ciphertext: encrypted.toString('base64'),
      iv: iv.toString('hex'),
      authTag: authTag.toString('hex'),
    };
  }

  /**
   * Decrypt a private key using AES-256-GCM
   */
  private decryptPrivateKey(
    ciphertext: string,
    iv: string,
    authTag: string
  ): crypto.KeyObject {
    if (!this.derivedKey) {
      throw new FdmsError('Decryption key not available', 'CRYPTO35');
    }

    try {
      const decipher = crypto.createDecipheriv(
        KEYSTORE_DEFAULTS.ALGORITHM,
        this.derivedKey,
        Buffer.from(iv, 'hex')
      ) as crypto.DecipherGCM;

      decipher.setAuthTag(Buffer.from(authTag, 'hex'));

      const decrypted = Buffer.concat([
        decipher.update(Buffer.from(ciphertext, 'base64')),
        decipher.final(),
      ]);

      return crypto.createPrivateKey(decrypted.toString('utf-8'));
    } catch (error) {
      throw new FdmsError(
        'Failed to decrypt private key. Invalid password or corrupted data.',
        'CRYPTO36',
        undefined,
        { cause: error instanceof Error ? error : undefined }
      );
    }
  }

  /**
   * Extract basic info from a certificate
   */
  private extractCertificateInfo(
    certificate: crypto.X509Certificate
  ): { commonName?: string; expiryDate?: Date } {
    const subject = certificate.subject;
    const cnMatch = subject.match(/CN=([^,\n]+)/);
    
    return {
      commonName: cnMatch?.[1]?.trim(),
      expiryDate: new Date(certificate.validTo),
    };
  }

  /**
   * Check if a file exists
   */
  private async fileExists(filePath: string): Promise<boolean> {
    try {
      await fs.promises.access(filePath, fs.constants.F_OK);
      return true;
    } catch {
      return false;
    }
  }
}

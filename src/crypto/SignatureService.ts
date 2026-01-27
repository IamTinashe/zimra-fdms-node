/**
 * Digital Signature Service
 * Handles receipt and fiscal day report signing per ZIMRA FDMS specification
 * 
 * This module provides RSA-SHA256 digital signature capabilities for:
 * - Receipt signing (required for all receipt submissions)
 * - Fiscal day report signing (required for day close operations)
 * - Signature verification (for testing and validation)
 * 
 * @module SignatureService
 */

import * as crypto from 'crypto';
import { FdmsError } from '../errors/FdmsError';

/**
 * Receipt data for signature generation
 */
export interface ReceiptSignatureData {
  /** Device ID assigned by ZIMRA */
  deviceId: number;
  /** Receipt type: FiscalInvoice, CreditNote, or DebitNote */
  receiptType: string;
  /** Currency code (ISO 4217) */
  receiptCurrency: string;
  /** Sequential counter within fiscal day */
  receiptCounter: number;
  /** Global sequential number */
  receiptGlobalNo: number;
  /** Business invoice number */
  invoiceNo: string;
  /** Receipt date (ISO 8601 format) */
  receiptDate: string;
  /** Receipt line items */
  receiptLineItems: ReceiptLineItemData[];
  /** Tax summaries */
  receiptTaxes: ReceiptTaxData[];
  /** Payment details */
  receiptPayments: ReceiptPaymentData[];
  /** Total receipt amount */
  receiptTotal: number;
}

/**
 * Line item data for signature
 */
export interface ReceiptLineItemData {
  lineNo: number;
  lineDescription: string;
  lineQuantity: number;
  lineUnitPrice: number;
  lineTaxPercent: number;
  lineTotal: number;
  hsCode?: string;
}

/**
 * Tax data for signature
 */
export interface ReceiptTaxData {
  taxCode: string;
  taxPercent: number;
  taxAmount: number;
  salesAmountWithTax: number;
}

/**
 * Payment data for signature
 */
export interface ReceiptPaymentData {
  moneyTypeCode: number;
  paymentAmount: number;
}

/**
 * Fiscal day report data for signature generation
 */
export interface FiscalDayReportData {
  /** Device ID assigned by ZIMRA */
  deviceId: number;
  /** Fiscal day number */
  fiscalDayNo: number;
  /** Date fiscal day was opened (ISO 8601) */
  fiscalDayOpened: string;
  /** Total receipt counter for the day */
  receiptCounter: number;
  /** Receipt counters by type */
  receiptCounterByType: Record<string, number>;
  /** Total sales amount */
  totalAmount: number;
  /** Total tax amount */
  totalTax: number;
  /** Totals by tax rate */
  totalsByTaxRate: TaxRateTotalData[];
}

/**
 * Tax rate total data for fiscal day signature
 */
export interface TaxRateTotalData {
  taxPercent: number;
  taxAmount: number;
  salesAmount?: number;
}

/**
 * Signature result containing the signature and metadata
 */
export interface SignatureResult {
  /** Base64-encoded signature */
  signature: string;
  /** The data string that was signed */
  dataString: string;
  /** SHA-256 hash of the data string (hex) */
  hash: string;
  /** Timestamp when signature was generated */
  timestamp: Date;
  /** Algorithm used for signing */
  algorithm: string;
}

/**
 * Signature verification result
 */
export interface VerificationResult {
  /** Whether the signature is valid */
  valid: boolean;
  /** Error message if verification failed */
  error?: string;
  /** The data string that was verified */
  dataString?: string;
}

/**
 * Signature service configuration options
 */
export interface SignatureServiceOptions {
  /** Private key in PEM format or as Buffer */
  privateKey: string | Buffer;
  /** Password for encrypted private key */
  privateKeyPassword?: string;
  /** Public key or certificate for verification (optional) */
  publicKey?: string | Buffer;
  /** Enable signature caching to avoid re-signing identical data */
  enableCache?: boolean;
  /** Maximum cache size (default: 1000) */
  maxCacheSize?: number;
}

/**
 * Digital Signature Service for ZIMRA FDMS
 * 
 * Provides RSA-SHA256 digital signature generation and verification
 * for receipts and fiscal day reports according to ZIMRA FDMS specification.
 * 
 * @example
 * ```typescript
 * const signatureService = new SignatureService({
 *   privateKey: fs.readFileSync('./device-key.pem'),
 *   privateKeyPassword: 'key-password'
 * });
 * 
 * // Sign a receipt
 * const result = signatureService.signReceipt({
 *   deviceId: 12345,
 *   receiptType: 'FiscalInvoice',
 *   receiptCurrency: 'USD',
 *   receiptCounter: 1,
 *   receiptGlobalNo: 100,
 *   invoiceNo: 'INV-001',
 *   receiptDate: '2025-01-26T10:00:00Z',
 *   receiptLineItems: [...],
 *   receiptTaxes: [...],
 *   receiptPayments: [...],
 *   receiptTotal: 1150.00
 * });
 * 
 * console.log('Signature:', result.signature);
 * ```
 */
export class SignatureService {
  private privateKey: crypto.KeyObject | null = null;
  private publicKey: crypto.KeyObject | null = null;
  private cache: Map<string, SignatureResult> = new Map();
  private enableCache: boolean;
  private maxCacheSize: number;

  /**
   * Create a new SignatureService instance
   * 
   * @param options - Configuration options
   * @throws FdmsError if private key cannot be loaded
   */
  constructor(options: SignatureServiceOptions) {
    this.enableCache = options.enableCache ?? false;
    this.maxCacheSize = options.maxCacheSize ?? 1000;

    // Load private key
    if (options.privateKey) {
      this.loadPrivateKey(options.privateKey, options.privateKeyPassword);
    }

    // Load public key if provided
    if (options.publicKey) {
      this.loadPublicKey(options.publicKey);
    }
  }

  /**
   * Load a private key for signing
   * 
   * @param key - Private key in PEM format or as Buffer
   * @param password - Password for encrypted keys
   * @throws FdmsError if key cannot be loaded
   */
  loadPrivateKey(key: string | Buffer, password?: string): void {
    try {
      const keyData = typeof key === 'string' ? key : key.toString('utf-8');
      
      this.privateKey = crypto.createPrivateKey({
        key: keyData,
        passphrase: password,
        format: 'pem'
      });

      // Extract public key from private key for verification
      this.publicKey = crypto.createPublicKey(this.privateKey);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error';
      throw new FdmsError(
        `Failed to load private key: ${message}`,
        'CRYPTO30'
      );
    }
  }

  /**
   * Load a public key or certificate for verification
   * 
   * @param key - Public key or certificate in PEM format
   * @throws FdmsError if key cannot be loaded
   */
  loadPublicKey(key: string | Buffer): void {
    try {
      const keyData = typeof key === 'string' ? key : key.toString('utf-8');
      
      // Check if it's a certificate or public key
      if (keyData.includes('CERTIFICATE')) {
        this.publicKey = crypto.createPublicKey({
          key: keyData,
          format: 'pem'
        });
      } else {
        this.publicKey = crypto.createPublicKey({
          key: keyData,
          format: 'pem'
        });
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error';
      throw new FdmsError(
        `Failed to load public key: ${message}`,
        'CRYPTO31'
      );
    }
  }

  /**
   * Sign receipt data according to ZIMRA FDMS specification
   * 
   * The signature is generated by:
   * 1. Preparing a data string with all receipt fields in specific order
   * 2. Computing SHA-256 hash of the data string
   * 3. Signing the hash with RSA private key
   * 4. Encoding the signature as Base64
   * 
   * @param data - Receipt data to sign
   * @returns Signature result with Base64-encoded signature
   * @throws FdmsError if signing fails
   */
  signReceipt(data: ReceiptSignatureData): SignatureResult {
    if (!this.privateKey) {
      throw new FdmsError('Private key not loaded', 'CRYPTO32');
    }

    // Prepare data string
    const dataString = this.prepareReceiptDataString(data);

    // Check cache
    if (this.enableCache) {
      const cached = this.cache.get(dataString);
      if (cached) {
        return cached;
      }
    }

    // Sign the data
    const result = this.sign(dataString);

    // Cache result
    if (this.enableCache) {
      this.addToCache(dataString, result);
    }

    return result;
  }

  /**
   * Sign fiscal day report data according to ZIMRA FDMS specification
   * 
   * @param data - Fiscal day report data to sign
   * @returns Signature result with Base64-encoded signature
   * @throws FdmsError if signing fails
   */
  signFiscalDayReport(data: FiscalDayReportData): SignatureResult {
    if (!this.privateKey) {
      throw new FdmsError('Private key not loaded', 'CRYPTO32');
    }

    // Prepare data string
    const dataString = this.prepareFiscalDayDataString(data);

    // Check cache
    if (this.enableCache) {
      const cached = this.cache.get(dataString);
      if (cached) {
        return cached;
      }
    }

    // Sign the data
    const result = this.sign(dataString);

    // Cache result
    if (this.enableCache) {
      this.addToCache(dataString, result);
    }

    return result;
  }

  /**
   * Sign arbitrary data string
   * 
   * @param dataString - Data string to sign
   * @returns Signature result
   * @throws FdmsError if signing fails
   */
  signData(dataString: string): SignatureResult {
    if (!this.privateKey) {
      throw new FdmsError('Private key not loaded', 'CRYPTO32');
    }

    return this.sign(dataString);
  }

  /**
   * Verify a receipt signature
   * 
   * @param data - Receipt data that was signed
   * @param signature - Base64-encoded signature to verify
   * @returns Verification result
   */
  verifyReceiptSignature(
    data: ReceiptSignatureData,
    signature: string
  ): VerificationResult {
    const dataString = this.prepareReceiptDataString(data);
    return this.verify(dataString, signature);
  }

  /**
   * Verify a fiscal day report signature
   * 
   * @param data - Fiscal day report data that was signed
   * @param signature - Base64-encoded signature to verify
   * @returns Verification result
   */
  verifyFiscalDaySignature(
    data: FiscalDayReportData,
    signature: string
  ): VerificationResult {
    const dataString = this.prepareFiscalDayDataString(data);
    return this.verify(dataString, signature);
  }

  /**
   * Verify a signature against arbitrary data
   * 
   * @param dataString - Data string that was signed
   * @param signature - Base64-encoded signature to verify
   * @returns Verification result
   */
  verifySignature(dataString: string, signature: string): VerificationResult {
    return this.verify(dataString, signature);
  }

  /**
   * Prepare the data string for receipt signing
   * 
   * The data string is constructed by concatenating receipt fields
   * in a specific order with newline separators, as specified by ZIMRA.
   * 
   * @param data - Receipt data
   * @returns Prepared data string
   */
  prepareReceiptDataString(data: ReceiptSignatureData): string {
    const parts: string[] = [];

    // Device identification
    parts.push(String(data.deviceId));
    parts.push(data.receiptType);
    parts.push(data.receiptCurrency);
    parts.push(String(data.receiptCounter));
    parts.push(String(data.receiptGlobalNo));
    parts.push(data.invoiceNo);
    parts.push(data.receiptDate);

    // Line items (sorted by line number)
    const sortedItems = [...data.receiptLineItems].sort((a, b) => a.lineNo - b.lineNo);
    for (const item of sortedItems) {
      parts.push(this.formatLineItem(item));
    }

    // Tax summaries (sorted by tax code)
    const sortedTaxes = [...data.receiptTaxes].sort((a, b) => 
      a.taxCode.localeCompare(b.taxCode)
    );
    for (const tax of sortedTaxes) {
      parts.push(this.formatTax(tax));
    }

    // Payments (sorted by money type code)
    const sortedPayments = [...data.receiptPayments].sort((a, b) => 
      a.moneyTypeCode - b.moneyTypeCode
    );
    for (const payment of sortedPayments) {
      parts.push(this.formatPayment(payment));
    }

    // Total
    parts.push(this.formatAmount(data.receiptTotal));

    return parts.join('\n');
  }

  /**
   * Prepare the data string for fiscal day report signing
   * 
   * @param data - Fiscal day report data
   * @returns Prepared data string
   */
  prepareFiscalDayDataString(data: FiscalDayReportData): string {
    const parts: string[] = [];

    // Device and day identification
    parts.push(String(data.deviceId));
    parts.push(String(data.fiscalDayNo));
    parts.push(data.fiscalDayOpened);

    // Counters
    parts.push(String(data.receiptCounter));
    
    // Receipt counters by type (sorted by type name)
    const sortedTypes = Object.entries(data.receiptCounterByType)
      .sort(([a], [b]) => a.localeCompare(b));
    for (const [type, count] of sortedTypes) {
      parts.push(`${type}:${count}`);
    }

    // Totals
    parts.push(this.formatAmount(data.totalAmount));
    parts.push(this.formatAmount(data.totalTax));

    // Tax rate totals (sorted by tax percent)
    const sortedRates = [...data.totalsByTaxRate].sort((a, b) => 
      a.taxPercent - b.taxPercent
    );
    for (const rate of sortedRates) {
      parts.push(`${this.formatAmount(rate.taxPercent)}:${this.formatAmount(rate.taxAmount)}`);
    }

    return parts.join('\n');
  }

  /**
   * Get the hash of a data string (for debugging/verification)
   * 
   * @param dataString - Data string to hash
   * @returns SHA-256 hash in hexadecimal format
   */
  getDataHash(dataString: string): string {
    return crypto.createHash('sha256').update(dataString, 'utf8').digest('hex');
  }

  /**
   * Clear the signature cache
   */
  clearCache(): void {
    this.cache.clear();
  }

  /**
   * Get current cache size
   */
  getCacheSize(): number {
    return this.cache.size;
  }

  /**
   * Check if the service has a private key loaded
   */
  hasPrivateKey(): boolean {
    return this.privateKey !== null;
  }

  /**
   * Check if the service has a public key loaded
   */
  hasPublicKey(): boolean {
    return this.publicKey !== null;
  }

  // Private methods

  /**
   * Perform the actual signing operation
   */
  private sign(dataString: string): SignatureResult {
    try {
      // Create signer with SHA-256
      const signer = crypto.createSign('RSA-SHA256');
      signer.update(dataString, 'utf8');
      signer.end();

      // Sign with private key
      const signature = signer.sign(this.privateKey!, 'base64');

      // Compute hash for reference
      const hash = this.getDataHash(dataString);

      return {
        signature,
        dataString,
        hash,
        timestamp: new Date(),
        algorithm: 'RSA-SHA256'
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error';
      throw new FdmsError(
        `Failed to sign data: ${message}`,
        'CRYPTO33'
      );
    }
  }

  /**
   * Perform signature verification
   */
  private verify(dataString: string, signature: string): VerificationResult {
    if (!this.publicKey) {
      return {
        valid: false,
        error: 'Public key not loaded for verification'
      };
    }

    try {
      // Create verifier with SHA-256
      const verifier = crypto.createVerify('RSA-SHA256');
      verifier.update(dataString, 'utf8');
      verifier.end();

      // Verify signature
      const valid = verifier.verify(this.publicKey, signature, 'base64');

      return {
        valid,
        dataString,
        error: valid ? undefined : 'Signature does not match'
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error';
      return {
        valid: false,
        error: `Verification failed: ${message}`,
        dataString
      };
    }
  }

  /**
   * Add result to cache with LRU eviction
   */
  private addToCache(key: string, result: SignatureResult): void {
    // Evict oldest entries if cache is full
    if (this.cache.size >= this.maxCacheSize) {
      const firstKey = this.cache.keys().next().value;
      if (firstKey) {
        this.cache.delete(firstKey);
      }
    }
    this.cache.set(key, result);
  }

  /**
   * Format a line item for the data string
   */
  private formatLineItem(item: ReceiptLineItemData): string {
    const parts = [
      String(item.lineNo),
      item.lineDescription,
      this.formatQuantity(item.lineQuantity),
      this.formatAmount(item.lineUnitPrice),
      this.formatAmount(item.lineTaxPercent),
      this.formatAmount(item.lineTotal)
    ];
    
    if (item.hsCode) {
      parts.push(item.hsCode);
    }
    
    return parts.join('|');
  }

  /**
   * Format a tax entry for the data string
   */
  private formatTax(tax: ReceiptTaxData): string {
    return [
      tax.taxCode,
      this.formatAmount(tax.taxPercent),
      this.formatAmount(tax.taxAmount),
      this.formatAmount(tax.salesAmountWithTax)
    ].join('|');
  }

  /**
   * Format a payment entry for the data string
   */
  private formatPayment(payment: ReceiptPaymentData): string {
    return [
      String(payment.moneyTypeCode),
      this.formatAmount(payment.paymentAmount)
    ].join('|');
  }

  /**
   * Format amount with consistent decimal places
   */
  private formatAmount(amount: number): string {
    return amount.toFixed(2);
  }

  /**
   * Format quantity with appropriate decimal places
   */
  private formatQuantity(quantity: number): string {
    // Use up to 4 decimal places for quantity, removing trailing zeros
    return parseFloat(quantity.toFixed(4)).toString();
  }
}

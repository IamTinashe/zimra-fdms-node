/**
 * Base FDMS error class for all SDK errors
 */

/**
 * FDMS Error category codes
 */
export enum FdmsErrorCategory {
  DEVICE = 'DEV',
  VALIDATION = 'VAL',
  AUTH = 'AUTH',
  NETWORK = 'NET',
  CRYPTO = 'CRYPTO',
  CONFIG = 'CONFIG',
  UNKNOWN = 'UNKNOWN',
}

/**
 * Base FDMS Error class
 * 
 * All errors in the SDK extend from this class.
 * Provides consistent error handling and categorization.
 */
export class FdmsError extends Error {
  /** Error code (e.g., DEV01, VAL01) */
  public readonly code?: string;
  
  /** HTTP status code if applicable */
  public readonly statusCode?: number;
  
  /** Error category for classification */
  public readonly category: FdmsErrorCategory;
  
  /** Original error that caused this error */
  public readonly cause?: Error;
  
  /** Additional details about the error */
  public readonly details?: Record<string, unknown>;
  
  /** Timestamp when error occurred */
  public readonly timestamp: Date;

  constructor(
    message: string,
    code?: string,
    statusCode?: number,
    options?: {
      cause?: Error;
      details?: Record<string, unknown>;
    }
  ) {
    super(message);
    this.name = 'FdmsError';
    this.code = code;
    this.statusCode = statusCode;
    this.cause = options?.cause;
    this.details = options?.details;
    this.timestamp = new Date();
    this.category = this.determineCategory(code);
    
    // Maintain proper stack trace
    Object.setPrototypeOf(this, FdmsError.prototype);
    
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, FdmsError);
    }
  }

  /**
   * Determine error category from code
   */
  private determineCategory(code?: string): FdmsErrorCategory {
    if (!code) {
      return FdmsErrorCategory.UNKNOWN;
    }
    
    if (code.startsWith('DEV')) return FdmsErrorCategory.DEVICE;
    if (code.startsWith('VAL')) return FdmsErrorCategory.VALIDATION;
    if (code.startsWith('AUTH')) return FdmsErrorCategory.AUTH;
    if (code.startsWith('NET')) return FdmsErrorCategory.NETWORK;
    if (code.startsWith('CRYPTO')) return FdmsErrorCategory.CRYPTO;
    if (code.startsWith('CONFIG')) return FdmsErrorCategory.CONFIG;
    
    return FdmsErrorCategory.UNKNOWN;
  }

  /**
   * Convert error to JSON-serializable object
   */
  public toJSON(): Record<string, unknown> {
    return {
      name: this.name,
      message: this.message,
      code: this.code,
      statusCode: this.statusCode,
      category: this.category,
      timestamp: this.timestamp.toISOString(),
      details: this.details,
      stack: this.stack,
    };
  }

  /**
   * Check if error has a specific code
   */
  public hasCode(code: string): boolean {
    return this.code === code;
  }

  /**
   * Check if error belongs to a category
   */
  public isCategory(category: FdmsErrorCategory): boolean {
    return this.category === category;
  }

  /**
   * Get human-readable error description
   */
  public getDescription(): string {
    const parts: string[] = [this.message];
    
    if (this.code) {
      parts.unshift(`[${this.code}]`);
    }
    
    if (this.statusCode) {
      parts.push(`(HTTP ${this.statusCode})`);
    }
    
    return parts.join(' ');
  }
}

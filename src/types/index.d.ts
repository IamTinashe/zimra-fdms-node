/**
 * TypeScript type definitions
 */

export interface FdmsConfig {
  // Required
  deviceId: string;
  deviceSerialNo: string;
  activationKey: string;
  deviceModelName: string;
  deviceModelVersion: string;

  // Certificate paths or content
  certificate: string | Buffer;
  privateKey: string | Buffer;
  privateKeyPassword?: string;

  // Optional with defaults
  environment?: 'test' | 'production';
  baseUrl?: string;
  timeout?: number;
  retryAttempts?: number;
  retryDelay?: number;

  // Audit logging
  enableAuditLog?: boolean;
  auditLogPath?: string;

  // State persistence
  stateStorePath?: string;
}

export interface FiscalState {
  deviceId: string;
  currentFiscalDayNo: number;
  fiscalDayStatus: 'Closed' | 'Opened' | 'CloseInitiated' | 'CloseFailed';
  fiscalDayOpenedAt: string | null;
  receiptCounter: number;
  globalReceiptNo: number;
  dayTotals: {
    totalAmount: number;
    totalTax: number;
    byTaxRate: Map<number, { amount: number; tax: number }>;
    byReceiptType: Map<string, number>;
  };
  lastSyncedAt: string;
}

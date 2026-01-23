/**
 * Fiscal day models
 */

export interface FiscalDay {
  fiscalDayNo: number;
  fiscalDayOpened: string;
  fiscalDayStatus: 'Closed' | 'Opened' | 'CloseInitiated' | 'CloseFailed';
}

export interface FiscalDayCounters {
  receiptCounter: number;
  receiptCounterByType: Record<string, number>;
}

export interface FiscalDayTotals {
  totalAmount: number;
  totalTax: number;
  totalsByTaxRate: Array<{
    taxPercent: number;
    taxAmount: number;
  }>;
}

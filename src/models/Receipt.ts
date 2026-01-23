/**
 * Receipt models
 */

export interface Receipt {
  receiptType: 'FiscalInvoice' | 'CreditNote' | 'DebitNote';
  receiptCurrency: string;
  receiptCounter: number;
  receiptGlobalNo: number;
  invoiceNo: string;
  receiptDate: string;
  buyerData?: BuyerData;
  receiptLineItems: ReceiptLineItem[];
  receiptTaxes: ReceiptTax[];
  receiptPayments: ReceiptPayment[];
  receiptTotal: number;
  receiptTaxTotal: number;
  receiptSignature: string;
  refReceiptId?: number;
  refReceiptGlobalNo?: number;
}

export interface BuyerData {
  buyerRegisterName: string;
  buyerTradeName?: string;
  buyerTIN?: string;
  buyerVATNumber?: string;
}

export interface ReceiptLineItem {
  lineNo: number;
  lineDescription: string;
  lineQuantity: number;
  lineUnitPrice: number;
  lineTaxPercent: number;
  lineTotal: number;
  hsCode?: string;
}

export interface ReceiptTax {
  taxCode: string;
  taxPercent: number;
  taxAmount: number;
  salesAmountWithTax: number;
}

export interface ReceiptPayment {
  moneyTypeCode: number;
  paymentAmount: number;
}

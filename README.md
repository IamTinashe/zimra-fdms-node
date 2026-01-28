# ZIMRA FDMS Integration SDK for Node.js/TypeScript

[![CI](https://github.com/yourusername/zimra-fdms-node/workflows/CI/badge.svg)](https://github.com/yourusername/zimra-fdms-node/actions)
[![npm version](https://badge.fury.io/js/zimra-fdms.svg)](https://www.npmjs.com/package/zimra-fdms)
[![codecov](https://codecov.io/gh/yourusername/zimra-fdms-node/branch/main/graph/badge.svg)](https://codecov.io/gh/yourusername/zimra-fdms-node)

Production-grade SDK for integrating with Zimbabwe Revenue Authority's (ZIMRA) Fiscalisation Data Management System (FDMS) API.

## Features

- ✅ Full ZIMRA FDMS API v7.2 compliance
- 🔐 Security-first cryptographic operations
- � X.509 certificate management with CSR generation
- 🔒 Secure encrypted key storage (AES-256-GCM)- ✍️ RSA-SHA256 digital signatures for receipts- �📝 Complete audit logging
- 🔄 Automatic retry and offline queue
- 📊 Real-time fiscal day management
- 🧾 Receipt signing and QR code generation
- 📱 TypeScript support with full type definitions

## Installation

```bash
npm install zimra-fdms
```

## Quick Start

```typescript
import { FdmsClient } from 'zimra-fdms';

const client = new FdmsClient({
  deviceId: 'YOUR_DEVICE_ID',
  deviceSerialNo: 'YOUR_SERIAL_NO',
  activationKey: 'YOUR_ACTIVATION_KEY',
  deviceModelName: 'YOUR_MODEL_NAME',
  deviceModelVersion: 'YOUR_MODEL_VERSION',
  certificate: './path/to/cert.pem',
  privateKey: './path/to/key.pem',
  environment: 'test'
});

// Initialize device
await client.initialize();

// Open fiscal day
await client.openFiscalDay();

// Submit receipt
const receipt = await client.submitReceipt({
  // receipt data
});

// Close fiscal day
await client.closeFiscalDay();
```

## Certificate Management

The SDK provides comprehensive X.509 certificate management:

```typescript
import { CertificateManager, KeyStore } from 'zimra-fdms';

// Certificate Manager
const certManager = new CertificateManager();

// Load existing certificate and key
const cert = certManager.loadCertificate('./device-cert.pem');
const privateKey = certManager.loadPrivateKey('./device-key.pem', 'password');

// Generate new RSA key pair (4096-bit recommended)
const keyPair = certManager.generateKeyPair({ keySize: 4096 });

// Generate CSR for device registration
const csr = certManager.generateCsr(keyPair.privateKey, {
  commonName: 'DEVICE-12345',
  organizationName: 'My Company',
  countryName: 'ZW'
});

// Validate certificate
const validation = certManager.validateCertificate(cert);
if (!validation.valid) {
  console.error('Certificate issues:', validation.errors);
}

// Secure Key Storage
const keyStore = new KeyStore({
  storePath: './keystore.json',
  password: 'secure-password'
});

await keyStore.load();
await keyStore.setKeyPair('device-key', privateKey, cert);
await keyStore.save();

// Retrieve later
const storedKey = await keyStore.getPrivateKey('device-key');
const storedCert = await keyStore.getCertificate('device-key');
```

## Digital Signatures

The SDK provides RSA-SHA256 digital signature services for receipts and fiscal day reports:

```typescript
import { SignatureService } from 'zimra-fdms';

// Create signature service with private key
const signatureService = new SignatureService({
  privateKey: fs.readFileSync('./device-key.pem'),
  privateKeyPassword: 'password',
  enableCache: true  // Cache signatures for identical data
});

// Sign a receipt
const receiptResult = signatureService.signReceipt({
  deviceId: 12345,
  receiptType: 'FiscalInvoice',
  receiptCurrency: 'USD',
  receiptCounter: 1,
  receiptGlobalNo: 100,
  invoiceNo: 'INV-001',
  receiptDate: '2025-01-26T10:00:00Z',
  receiptLineItems: [
    { lineNo: 1, lineDescription: 'Product A', lineQuantity: 2, lineUnitPrice: 500, lineTaxPercent: 15, lineTotal: 1000 }
  ],
  receiptTaxes: [
    { taxCode: 'A', taxPercent: 15, taxAmount: 150, salesAmountWithTax: 1150 }
  ],
  receiptPayments: [
    { moneyTypeCode: 0, paymentAmount: 1150 }
  ],
  receiptTotal: 1150
});

console.log('Receipt Signature:', receiptResult.signature);

// Sign fiscal day report
const dayResult = signatureService.signFiscalDayReport({
  deviceId: 12345,
  fiscalDayNo: 1,
  fiscalDayOpened: '2025-01-26T08:00:00Z',
  receiptCounter: 50,
  receiptCounterByType: { 'FiscalInvoice': 48, 'CreditNote': 2 },
  totalAmount: 125000,
  totalTax: 16304.35,
  totalsByTaxRate: [{ taxPercent: 15, taxAmount: 16304.35 }]
});

console.log('Day Signature:', dayResult.signature);

// Verify a signature
const verification = signatureService.verifyReceiptSignature(receiptData, signature);
if (verification.valid) {
  console.log('Signature is valid');
}
```

## Documentation

- [Installation Guide](./docs/guides/installation.md)
- [Configuration Guide](./docs/guides/configuration.md)
- [API Reference](./docs/api/README.md)
- [Examples](./examples/)

## Requirements

- Node.js >= 18.0.0
- ZIMRA device credentials

## License

MIT

## Support

For issues and questions, please open an issue on [GitHub](https://github.com/yourusername/zimra-fdms-node/issues).

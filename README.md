# ZIMRA FDMS Integration SDK for Node.js/TypeScript

[![CI](https://github.com/yourusername/zimra-fdms-node/workflows/CI/badge.svg)](https://github.com/yourusername/zimra-fdms-node/actions)
[![npm version](https://badge.fury.io/js/zimra-fdms.svg)](https://www.npmjs.com/package/zimra-fdms)
[![codecov](https://codecov.io/gh/yourusername/zimra-fdms-node/branch/main/graph/badge.svg)](https://codecov.io/gh/yourusername/zimra-fdms-node)

Production-grade SDK for integrating with Zimbabwe Revenue Authority's (ZIMRA) Fiscalisation Data Management System (FDMS) API.

## Features

- ✅ Full ZIMRA FDMS API v7.2 compliance
- 🔐 Security-first cryptographic operations
- 📝 Complete audit logging
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

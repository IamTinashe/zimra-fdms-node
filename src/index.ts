/**
 * ZIMRA FDMS Integration SDK for Node.js/TypeScript
 * 
 * Main entry point for the SDK
 */

export { FdmsClient } from './client/FdmsClient';

// HTTP Client
export {
  HttpClient,
  HttpMethod,
  HttpRequestOptions,
  HttpResponse,
  HttpAuditEntry,
  CircuitState,
  CircuitBreakerConfig,
  FdmsApiError,
  RequestInterceptor,
  ResponseInterceptor,
} from './client/HttpClient';

// Configuration
export * from './config';

// Services
export { DeviceService } from './services/DeviceService';
export { FiscalDayService } from './services/FiscalDayService';
export { ReceiptService } from './services/ReceiptService';
export { CertificateService } from './services/CertificateService';
export { VerificationService } from './services/VerificationService';

// Models
export * from './models';

// Types - Export specific types to avoid conflicts with config
export { FiscalState } from './types';

// Errors
export {
  FdmsError,
  FdmsErrorCategory,
} from './errors/FdmsError';
export * from './errors/ValidationError';
export {
  NetworkError,
  NetworkErrorCode,
} from './errors/NetworkError';

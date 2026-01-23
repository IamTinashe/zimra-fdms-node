/**
 * Network error class for HTTP communication failures
 */

import { FdmsError } from './FdmsError';

/**
 * Network error codes
 */
export enum NetworkErrorCode {
  TIMEOUT = 'NET01',
  CONNECTION_REFUSED = 'NET02',
  DNS_LOOKUP_FAILED = 'NET03',
  SSL_ERROR = 'NET04',
  CIRCUIT_BREAKER_OPEN = 'NET05',
  NO_RESPONSE = 'NET06',
  REQUEST_ABORTED = 'NET07',
  UNKNOWN = 'NET10',
}

/**
 * Network error for HTTP transport layer failures
 */
export class NetworkError extends FdmsError {
  /** Whether this error is retryable */
  public readonly retryable: boolean;
  
  /** Network error code */
  public readonly networkCode: NetworkErrorCode;

  constructor(
    message: string,
    statusCode?: number,
    networkCode: NetworkErrorCode = NetworkErrorCode.UNKNOWN,
    retryable: boolean = true
  ) {
    super(message, networkCode, statusCode);
    this.name = 'NetworkError';
    this.networkCode = networkCode;
    this.retryable = retryable;
    Object.setPrototypeOf(this, NetworkError.prototype);
  }

  /**
   * Create a timeout error
   */
  static timeout(message: string = 'Request timed out'): NetworkError {
    return new NetworkError(message, 408, NetworkErrorCode.TIMEOUT, true);
  }

  /**
   * Create a connection refused error
   */
  static connectionRefused(message: string = 'Connection refused'): NetworkError {
    return new NetworkError(message, undefined, NetworkErrorCode.CONNECTION_REFUSED, true);
  }

  /**
   * Create a circuit breaker open error
   */
  static circuitBreakerOpen(retryAfterSeconds: number): NetworkError {
    return new NetworkError(
      `Circuit breaker is open. Retry after ${retryAfterSeconds} seconds`,
      503,
      NetworkErrorCode.CIRCUIT_BREAKER_OPEN,
      false
    );
  }

  /**
   * Create an SSL error
   */
  static sslError(message: string = 'SSL/TLS error'): NetworkError {
    return new NetworkError(message, undefined, NetworkErrorCode.SSL_ERROR, false);
  }
}

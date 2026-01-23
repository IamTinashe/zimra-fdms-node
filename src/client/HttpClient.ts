/**
 * HTTP transport layer for FDMS API
 * Handles all HTTP communication with retry logic, interceptors,
 * circuit breaker pattern, and connection pooling
 */

import axios, {
  AxiosInstance,
  AxiosRequestConfig,
  AxiosResponse,
  InternalAxiosRequestConfig,
  AxiosError,
} from 'axios';
import { ResolvedFdmsConfig } from '../config/FdmsConfig';
import { FdmsError } from '../errors/FdmsError';
import { NetworkError } from '../errors/NetworkError';

/**
 * HTTP method types supported
 */
export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';

/**
 * Request options for HTTP client
 */
export interface HttpRequestOptions {
  /** Request headers */
  headers?: Record<string, string>;
  /** Query parameters */
  params?: Record<string, string | number | boolean>;
  /** Request timeout override (ms) */
  timeout?: number;
  /** Skip retry logic for this request */
  skipRetry?: boolean;
  /** Request-specific metadata */
  metadata?: Record<string, unknown>;
}

/**
 * HTTP response wrapper
 */
export interface HttpResponse<T = unknown> {
  /** Response data */
  data: T;
  /** HTTP status code */
  status: number;
  /** Response headers */
  headers: Record<string, string>;
  /** Request duration in milliseconds */
  duration: number;
  /** Request ID for traceability */
  requestId: string;
}

/**
 * Circuit breaker states
 */
export enum CircuitState {
  CLOSED = 'CLOSED',
  OPEN = 'OPEN',
  HALF_OPEN = 'HALF_OPEN',
}

/**
 * Circuit breaker configuration
 */
export interface CircuitBreakerConfig {
  /** Number of failures before opening circuit */
  failureThreshold: number;
  /** Time in ms before attempting recovery */
  recoveryTimeout: number;
  /** Number of successful requests to close circuit */
  successThreshold: number;
}

/**
 * FDMS API error response structure
 */
export interface FdmsApiError {
  code?: string;
  message?: string;
  errors?: Array<{ code: string; message: string }>;
}

/**
 * Audit log entry for HTTP requests
 */
export interface HttpAuditEntry {
  timestamp: string;
  requestId: string;
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: unknown;
  response?: {
    statusCode: number;
    body?: unknown;
  };
  duration: number;
  success: boolean;
  error?: string;
  retryAttempt?: number;
}

/**
 * Request interceptor callback
 */
export type RequestInterceptor = (
  config: InternalAxiosRequestConfig
) => InternalAxiosRequestConfig | Promise<InternalAxiosRequestConfig>;

/**
 * Response interceptor callback
 */
export type ResponseInterceptor = (
  response: AxiosResponse
) => AxiosResponse | Promise<AxiosResponse>;

/**
 * Default circuit breaker configuration
 */
const DEFAULT_CIRCUIT_BREAKER_CONFIG: CircuitBreakerConfig = {
  failureThreshold: 5,
  recoveryTimeout: 30000,
  successThreshold: 3,
};

/**
 * Sensitive headers/fields that should be redacted in logs
 */
const SENSITIVE_FIELDS = [
  'authorization',
  'x-api-key',
  'privatekey',
  'private_key',
  'password',
  'activationkey',
  'activation_key',
  'certificate',
];

/**
 * HTTP Client for ZIMRA FDMS API
 * 
 * Features:
 * - Automatic retry with exponential backoff
 * - Circuit breaker pattern for resilience
 * - Request/response interceptors
 * - Request ID generation for traceability
 * - Comprehensive audit logging
 * - Connection keep-alive
 */
export class HttpClient {
  private readonly client: AxiosInstance;
  private readonly config: ResolvedFdmsConfig;
  
  // Circuit breaker state
  private circuitState: CircuitState = CircuitState.CLOSED;
  private circuitFailureCount: number = 0;
  private circuitSuccessCount: number = 0;
  private circuitOpenTime: number = 0;
  private readonly circuitConfig: CircuitBreakerConfig;
  
  // Custom interceptors
  private requestInterceptors: RequestInterceptor[] = [];
  private responseInterceptors: ResponseInterceptor[] = [];
  
  // Audit logging
  private auditLogCallback?: (entry: HttpAuditEntry) => void;

  /**
   * Create a new HTTP client instance
   * 
   * @param config - Resolved FDMS configuration
   * @param circuitBreakerConfig - Optional circuit breaker configuration
   */
  constructor(
    config: ResolvedFdmsConfig,
    circuitBreakerConfig?: Partial<CircuitBreakerConfig>
  ) {
    this.config = config;
    this.circuitConfig = {
      ...DEFAULT_CIRCUIT_BREAKER_CONFIG,
      ...circuitBreakerConfig,
    };

    // Create axios instance with base configuration
    this.client = axios.create({
      baseURL: config.baseUrl,
      timeout: config.timeout,
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'DeviceModelName': config.deviceModelName,
        'DeviceModelVersionNo': config.deviceModelVersion,
      },
      // Enable keep-alive for connection pooling
      httpAgent: new (require('http').Agent)({
        keepAlive: true,
        maxSockets: 10,
        maxFreeSockets: 5,
        timeout: config.timeout,
      }),
      httpsAgent: new (require('https').Agent)({
        keepAlive: true,
        maxSockets: 10,
        maxFreeSockets: 5,
        timeout: config.timeout,
      }),
    });

    // Set up default interceptors
    this.setupDefaultInterceptors();
  }

  /**
   * Set up default request and response interceptors
   */
  private setupDefaultInterceptors(): void {
    // Request interceptor: Add request ID and timestamp
    this.client.interceptors.request.use(
      (config: InternalAxiosRequestConfig) => {
        const requestId = this.generateRequestId();
        config.headers = config.headers || {};
        config.headers['X-Request-ID'] = requestId;
        
        // Store metadata for response interceptor
        (config as any).metadata = {
          requestId,
          startTime: Date.now(),
          ...(config as any).metadata,
        };

        // Apply custom request interceptors
        return this.applyRequestInterceptors(config);
      },
      (error) => Promise.reject(error)
    );

    // Response interceptor: Log and normalize errors
    this.client.interceptors.response.use(
      async (response: AxiosResponse) => {
        // Apply custom response interceptors
        const processedResponse = await this.applyResponseInterceptors(response);
        return processedResponse;
      },
      (error: AxiosError<FdmsApiError>) => {
        return Promise.reject(this.normalizeError(error));
      }
    );
  }

  /**
   * Apply custom request interceptors
   */
  private async applyRequestInterceptors(
    config: InternalAxiosRequestConfig
  ): Promise<InternalAxiosRequestConfig> {
    let processedConfig = config;
    for (const interceptor of this.requestInterceptors) {
      processedConfig = await interceptor(processedConfig);
    }
    return processedConfig;
  }

  /**
   * Apply custom response interceptors
   */
  private async applyResponseInterceptors(
    response: AxiosResponse
  ): Promise<AxiosResponse> {
    let processedResponse = response;
    for (const interceptor of this.responseInterceptors) {
      processedResponse = await interceptor(processedResponse);
    }
    return processedResponse;
  }

  /**
   * Add a custom request interceptor
   */
  public addRequestInterceptor(interceptor: RequestInterceptor): void {
    this.requestInterceptors.push(interceptor);
  }

  /**
   * Add a custom response interceptor
   */
  public addResponseInterceptor(interceptor: ResponseInterceptor): void {
    this.responseInterceptors.push(interceptor);
  }

  /**
   * Set audit log callback
   */
  public setAuditLogCallback(callback: (entry: HttpAuditEntry) => void): void {
    this.auditLogCallback = callback;
  }

  /**
   * Generate unique request ID for traceability
   */
  private generateRequestId(): string {
    const timestamp = Date.now().toString(36);
    const random = Math.random().toString(36).substring(2, 10);
    return `fdms-${timestamp}-${random}`;
  }

  /**
   * Normalize error from various sources into FdmsError
   */
  private normalizeError(error: AxiosError<FdmsApiError>): FdmsError | NetworkError {
    if (error.response) {
      // Server responded with error status
      const data = error.response.data;
      const errorCode = data?.code || data?.errors?.[0]?.code;
      const errorMessage = data?.message || data?.errors?.[0]?.message || error.message;
      
      return new FdmsError(errorMessage, errorCode, error.response.status);
    } else if (error.request) {
      // Request made but no response received
      return new NetworkError(
        `Network error: ${error.message || 'No response received'}`,
        undefined
      );
    } else {
      // Error setting up request
      return new FdmsError(`Request error: ${error.message}`);
    }
  }

  /**
   * Check circuit breaker state
   */
  private checkCircuitBreaker(): void {
    if (this.circuitState === CircuitState.OPEN) {
      const timeSinceOpen = Date.now() - this.circuitOpenTime;
      
      if (timeSinceOpen >= this.circuitConfig.recoveryTimeout) {
        // Transition to half-open state
        this.circuitState = CircuitState.HALF_OPEN;
        this.circuitSuccessCount = 0;
      } else {
        throw new NetworkError(
          `Circuit breaker is open. Retry after ${Math.ceil(
            (this.circuitConfig.recoveryTimeout - timeSinceOpen) / 1000
          )} seconds`,
          503
        );
      }
    }
  }

  /**
   * Record circuit breaker success
   */
  private recordCircuitSuccess(): void {
    if (this.circuitState === CircuitState.HALF_OPEN) {
      this.circuitSuccessCount++;
      
      if (this.circuitSuccessCount >= this.circuitConfig.successThreshold) {
        // Close the circuit
        this.circuitState = CircuitState.CLOSED;
        this.circuitFailureCount = 0;
        this.circuitSuccessCount = 0;
      }
    } else if (this.circuitState === CircuitState.CLOSED) {
      // Reset failure count on success
      this.circuitFailureCount = 0;
    }
  }

  /**
   * Record circuit breaker failure
   */
  private recordCircuitFailure(): void {
    if (this.circuitState === CircuitState.HALF_OPEN) {
      // Failed while half-open, reopen circuit
      this.circuitState = CircuitState.OPEN;
      this.circuitOpenTime = Date.now();
    } else if (this.circuitState === CircuitState.CLOSED) {
      this.circuitFailureCount++;
      
      if (this.circuitFailureCount >= this.circuitConfig.failureThreshold) {
        // Open the circuit
        this.circuitState = CircuitState.OPEN;
        this.circuitOpenTime = Date.now();
      }
    }
  }

  /**
   * Calculate retry delay with exponential backoff
   * 
   * @param attempt - Current attempt number (0-based)
   * @returns Delay in milliseconds
   */
  private calculateRetryDelay(attempt: number): number {
    // Exponential backoff: baseDelay * 2^attempt
    // Max delay capped at 16 seconds
    const delay = this.config.retryDelay * Math.pow(2, attempt);
    return Math.min(delay, 16000);
  }

  /**
   * Determine if error is retryable
   */
  private isRetryableError(error: unknown): boolean {
    if (error instanceof NetworkError) {
      return true;
    }
    
    if (error instanceof FdmsError && error.statusCode) {
      // Retry on 5xx errors and specific 4xx errors
      const retryableStatuses = [408, 429, 500, 502, 503, 504];
      return retryableStatuses.includes(error.statusCode);
    }
    
    return false;
  }

  /**
   * Sleep for specified milliseconds
   */
  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  /**
   * Redact sensitive data from object for logging
   */
  private redactSensitiveData(obj: unknown): unknown {
    if (obj === null || obj === undefined) {
      return obj;
    }
    
    if (typeof obj === 'string') {
      return obj;
    }
    
    if (Array.isArray(obj)) {
      return obj.map((item) => this.redactSensitiveData(item));
    }
    
    if (typeof obj === 'object') {
      const redacted: Record<string, unknown> = {};
      
      for (const [key, value] of Object.entries(obj)) {
        const lowerKey = key.toLowerCase();
        const isSensitive = SENSITIVE_FIELDS.some((field) =>
          lowerKey.includes(field)
        );
        
        if (isSensitive) {
          redacted[key] = '[REDACTED]';
        } else if (typeof value === 'object') {
          redacted[key] = this.redactSensitiveData(value);
        } else {
          redacted[key] = value;
        }
      }
      
      return redacted;
    }
    
    return obj;
  }

  /**
   * Create audit log entry
   */
  private createAuditEntry(
    config: AxiosRequestConfig,
    response?: AxiosResponse,
    error?: Error,
    retryAttempt?: number
  ): HttpAuditEntry {
    const metadata = (config as any).metadata || {};
    const duration = Date.now() - (metadata.startTime || Date.now());
    
    return {
      timestamp: new Date().toISOString(),
      requestId: metadata.requestId || 'unknown',
      method: (config.method || 'GET').toUpperCase(),
      url: `${config.baseURL || ''}${config.url || ''}`,
      headers: this.redactSensitiveData(config.headers) as Record<string, string>,
      body: this.redactSensitiveData(config.data),
      response: response
        ? {
            statusCode: response.status,
            body: this.redactSensitiveData(response.data),
          }
        : undefined,
      duration,
      success: !error,
      error: error?.message,
      retryAttempt,
    };
  }

  /**
   * Log audit entry
   */
  private logAudit(entry: HttpAuditEntry): void {
    if (this.config.enableAuditLog && this.auditLogCallback) {
      this.auditLogCallback(entry);
    }
  }

  /**
   * Execute HTTP request with retry logic
   */
  private async executeWithRetry<T>(
    method: HttpMethod,
    url: string,
    data?: unknown,
    options?: HttpRequestOptions
  ): Promise<HttpResponse<T>> {
    // Check circuit breaker before making request
    this.checkCircuitBreaker();

    const maxAttempts = options?.skipRetry ? 1 : this.config.retryAttempts + 1;
    let lastError: Error | undefined;

    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      const startTime = Date.now();
      
      try {
        const requestConfig: AxiosRequestConfig = {
          method,
          url,
          data,
          headers: options?.headers,
          params: options?.params,
          timeout: options?.timeout || this.config.timeout,
        };

        // Store metadata
        (requestConfig as any).metadata = {
          ...options?.metadata,
          startTime,
          attempt,
        };

        const response = await this.client.request<T>(requestConfig);
        
        // Record success for circuit breaker
        this.recordCircuitSuccess();
        
        // Create audit entry
        const auditEntry = this.createAuditEntry(requestConfig, response, undefined, attempt);
        this.logAudit(auditEntry);

        const requestId = (requestConfig as any).metadata?.requestId || 
                          response.config.headers?.['X-Request-ID'] as string || 
                          'unknown';

        return {
          data: response.data,
          status: response.status,
          headers: response.headers as Record<string, string>,
          duration: Date.now() - startTime,
          requestId,
        };
      } catch (error) {
        lastError = error as Error;
        
        // Record failure for circuit breaker
        this.recordCircuitFailure();
        
        // Log audit entry for failed attempt
        const auditEntry = this.createAuditEntry(
          { method, url, data, headers: options?.headers } as AxiosRequestConfig,
          undefined,
          lastError,
          attempt
        );
        this.logAudit(auditEntry);

        // Check if we should retry
        if (attempt < maxAttempts - 1 && this.isRetryableError(error)) {
          const delay = this.calculateRetryDelay(attempt);
          await this.sleep(delay);
          continue;
        }
        
        throw lastError;
      }
    }

    // Should not reach here, but just in case
    throw lastError || new FdmsError('Unknown error occurred');
  }

  /**
   * Perform GET request
   */
  public async get<T = unknown>(
    url: string,
    options?: HttpRequestOptions
  ): Promise<HttpResponse<T>> {
    return this.executeWithRetry<T>('GET', url, undefined, options);
  }

  /**
   * Perform POST request
   */
  public async post<T = unknown>(
    url: string,
    data?: unknown,
    options?: HttpRequestOptions
  ): Promise<HttpResponse<T>> {
    return this.executeWithRetry<T>('POST', url, data, options);
  }

  /**
   * Perform PUT request
   */
  public async put<T = unknown>(
    url: string,
    data?: unknown,
    options?: HttpRequestOptions
  ): Promise<HttpResponse<T>> {
    return this.executeWithRetry<T>('PUT', url, data, options);
  }

  /**
   * Perform DELETE request
   */
  public async delete<T = unknown>(
    url: string,
    options?: HttpRequestOptions
  ): Promise<HttpResponse<T>> {
    return this.executeWithRetry<T>('DELETE', url, undefined, options);
  }

  /**
   * Perform PATCH request
   */
  public async patch<T = unknown>(
    url: string,
    data?: unknown,
    options?: HttpRequestOptions
  ): Promise<HttpResponse<T>> {
    return this.executeWithRetry<T>('PATCH', url, data, options);
  }

  /**
   * Get current circuit breaker state
   */
  public getCircuitState(): CircuitState {
    return this.circuitState;
  }

  /**
   * Reset circuit breaker to closed state
   */
  public resetCircuitBreaker(): void {
    this.circuitState = CircuitState.CLOSED;
    this.circuitFailureCount = 0;
    this.circuitSuccessCount = 0;
    this.circuitOpenTime = 0;
  }

  /**
   * Get base URL
   */
  public getBaseUrl(): string {
    return this.config.baseUrl;
  }

  /**
   * Get device ID from config
   */
  public getDeviceId(): string {
    return this.config.deviceId;
  }
}

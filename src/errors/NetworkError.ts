/**
 * Network error class
 */

import { FdmsError } from './FdmsError';

export class NetworkError extends FdmsError {
  constructor(message: string, statusCode?: number) {
    super(message, 'NETWORK_ERROR', statusCode);
    this.name = 'NetworkError';
    Object.setPrototypeOf(this, NetworkError.prototype);
  }
}

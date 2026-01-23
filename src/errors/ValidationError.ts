/**
 * Validation error class
 */

import { FdmsError } from './FdmsError';

export class ValidationError extends FdmsError {
  constructor(message: string, public field?: string) {
    super(message, 'VALIDATION_ERROR');
    this.name = 'ValidationError';
    Object.setPrototypeOf(this, ValidationError.prototype);
  }
}

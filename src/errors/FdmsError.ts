/**
 * Base FDMS error class
 */

export class FdmsError extends Error {
  constructor(
    message: string,
    public code?: string,
    public statusCode?: number
  ) {
    super(message);
    this.name = 'FdmsError';
    Object.setPrototypeOf(this, FdmsError.prototype);
  }
}

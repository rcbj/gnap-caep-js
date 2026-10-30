/**
 * Base class for every error raised by this library.
 */
export class GNAPClientError extends Error {
  /**
   * @param {string} message
   * @param {{ code?: string, status?: number, cause?: unknown, response?: unknown }} [opts]
   */
  constructor(message, { code, status, cause, response } = {}) {
    super(message, cause ? { cause } : undefined);
    this.name = this.constructor.name;
    this.code = code;
    this.status = status;
    this.response = response;
  }
}

/**
 * The authorization server answered with a GNAP error response (RFC 9635 section 3.6):
 * `{ "error": { "code", "description" } }`, or the bare-string form `{ "error": "code" }`.
 * `error` is the GNAP error code (`user_denied`, `invalid_client`, `too_fast`, ...).
 */
export class GNAPError extends GNAPClientError {
  /**
   * @param {{ error: string, error_description?: string, status?: number, response?: unknown, continue?: Record<string, any> }} opts
   */
  constructor({ error, error_description, status, response, continue: cont }) {
    super(error_description ? `${error}: ${error_description}` : error, { code: error, status, response });
    /** The GNAP error code. @type {string} */
    this.error = error;
    /** @type {string|undefined} */
    this.error_description = error_description;
    /** The `continue` object an error response may carry (section 3.6), when the grant can go on. */
    this.continue = cont;
  }
}

/** A response from the AS failed validation (bad interaction hash, bad subject, insecure endpoint...). */
export class ValidationError extends GNAPClientError {}

/** A Security Event Token could not be accepted. `code` is an RFC 8935 §2.3 error code. */
export class SETValidationError extends GNAPClientError {
  /**
   * @param {string} message
   * @param {string} [code]  The RFC 8935/8936 error code reported to the transmitter.
   * @param {unknown} [cause]
   */
  constructor(message, code = 'invalid_request', cause) {
    super(message, { code, cause });
  }
}

/** A Shared Signals Framework management API call failed. */
export class SSFError extends GNAPClientError {}

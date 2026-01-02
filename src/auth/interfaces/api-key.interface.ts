/**
 * Interfaz que define la estructura de un API key firmado
 */
export interface ApiKeyPayload {
  /**
   * Identificador único del cliente o aplicación
   */
  clientId: string;

  /**
   * Nombre descriptivo del cliente o aplicación
   */
  clientName: string;

  /**
   * Timestamp de cuando fue emitido el API key (issued at)
   */
  iat: number;

  /**
   * Timestamp de expiración del API key (opcional)
   */
  exp?: number;

  /**
   * Permisos o scopes que tiene este API key
   */
  scopes?: string[];

  /**
   * Información adicional del cliente
   */
  metadata?: Record<string, any>;
}

/**
 * Interfaz para el API key completo con su firma
 */
export interface SignedApiKey {
  /**
   * El payload del API key
   */
  payload: ApiKeyPayload;

  /**
   * La firma digital del API key
   */
  signature: string;

  /**
   * El API key completo en formato string (payload.signature)
   */
  apiKey: string;
}

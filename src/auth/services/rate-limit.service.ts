import { Injectable, Logger } from '@nestjs/common';
import { RedisService } from '../../redis/redis.service';

/**
 * Configuración para el rate limiting
 */
export interface RateLimitConfig {
  /** Número máximo de intentos permitidos */
  maxAttempts: number;
  /** Ventana de tiempo en segundos */
  windowSeconds: number;
  /** Tiempo de bloqueo en segundos después de exceder el límite */
  blockDurationSeconds?: number;
}

/**
 * Resultado de la verificación de rate limiting
 */
export interface RateLimitResult {
  /** Indica si la solicitud está permitida */
  allowed: boolean;
  /** Número de intentos restantes */
  remaining: number;
  /** Tiempo hasta el reset en segundos */
  resetTime: number;
  /** Tiempo total de la ventana en segundos */
  windowSeconds: number;
  /** Indica si el cliente está bloqueado */
  blocked?: boolean;
  /** Tiempo restante de bloqueo en segundos */
  blockTimeRemaining?: number;
}

/**
 * Servicio para implementar rate limiting usando Redis como backend de almacenamiento.
 * Utiliza un algoritmo de conteo simple con ventana de tiempo fija para controlar la tasa de solicitudes.
 *
 * @example
 * ```typescript
 * // Verificar rate limit para login
 * const result = await rateLimitService.checkRateLimit(
 *   'login',
 *   clientIp,
 *   { maxAttempts: 5, windowSeconds: 300 }
 * );
 *
 * if (!result.allowed) {
 *   throw new TooManyRequestsException('Demasiados intentos de login');
 * }
 * ```
 */
@Injectable()
export class RateLimitService {
  private readonly logger = new Logger(RateLimitService.name);

  constructor(private readonly redisService: RedisService) {}

  /**
   * Verifica si una solicitud está dentro de los límites de rate limiting.
   * Utiliza un algoritmo de conteo simple con ventana de tiempo fija.
   *
   * @param action - Acción que se está limitando (ej: 'login', 'api-call')
   * @param identifier - Identificador único del cliente (IP, user ID, etc.)
   * @param config - Configuración del rate limiting
   * @returns Resultado de la verificación con información detallada
   *
   * @example
   * ```typescript
   * const result = await this.checkRateLimit('login', '192.168.1.1', {
   *   maxAttempts: 5,
   *   windowSeconds: 300,
   *   blockDurationSeconds: 900
   * });
   * ```
   */
  async checkRateLimit(
    action: string,
    identifier: string,
    config: RateLimitConfig,
  ): Promise<RateLimitResult> {
    const key = this.generateKey(action, identifier);
    const blockKey = this.generateBlockKey(action, identifier);

    try {
      // Verificar si el cliente está bloqueado
      if (config.blockDurationSeconds) {
        const blockInfo = await this.checkBlockStatus(blockKey);
        if (blockInfo.blocked) {
          return {
            allowed: false,
            remaining: 0,
            resetTime: Math.ceil(blockInfo.blockTimeRemaining! / 1000),
            windowSeconds: config.windowSeconds,
            blocked: true,
            blockTimeRemaining: blockInfo.blockTimeRemaining,
          };
        }
      }

      // Obtener el contador actual
      const currentCountStr = await this.redisService.get(key);
      const currentCount = currentCountStr ? parseInt(currentCountStr, 10) : 0;

      // Verificar si se excede el límite
      if (currentCount >= config.maxAttempts) {
        // Si hay configuración de bloqueo, bloquear al cliente
        if (config.blockDurationSeconds) {
          await this.blockClient(blockKey, config.blockDurationSeconds);
        }

        return {
          allowed: false,
          remaining: 0,
          resetTime: config.windowSeconds,
          windowSeconds: config.windowSeconds,
          blocked: !!config.blockDurationSeconds,
          blockTimeRemaining: config.blockDurationSeconds
            ? config.blockDurationSeconds * 1000
            : undefined,
        };
      }

      // Incrementar el contador
      await this.incrementCounter(action, identifier, config.windowSeconds);

      const remaining = Math.max(0, config.maxAttempts - currentCount - 1);

      return {
        allowed: true,
        remaining,
        resetTime: config.windowSeconds,
        windowSeconds: config.windowSeconds,
        blocked: false,
      };
    } catch (error) {
      this.logger.error(`Error en rate limiting para ${key}:`, error);
      // En caso de error, permitir la solicitud para evitar bloqueos del servicio
      return {
        allowed: true,
        remaining: config.maxAttempts - 1,
        resetTime: config.windowSeconds,
        windowSeconds: config.windowSeconds,
        blocked: false,
      };
    }
  }

  /**
   * Incrementa el contador de rate limiting sin verificar límites.
   * Útil para registrar intentos fallidos después de la validación.
   *
   * @param action - Acción que se está limitando
   * @param identifier - Identificador único del cliente
   * @param windowSeconds - Ventana de tiempo en segundos
   *
   * @example
   * ```typescript
   * // Registrar intento fallido de login
   * await this.incrementCounter('login-failed', userIp, 300);
   * ```
   */
  async incrementCounter(
    action: string,
    identifier: string,
    windowSeconds: number,
  ): Promise<void> {
    const key = this.generateKey(action, identifier);

    try {
      const currentCountStr = await this.redisService.get(key);
      const currentCount = currentCountStr ? parseInt(currentCountStr, 10) : 0;
      const newCount = currentCount + 1;

      await this.redisService.set(key, newCount.toString(), windowSeconds);
    } catch (error) {
      this.logger.error(`Error incrementando contador para ${key}:`, error);
    }
  }

  /**
   * Obtiene el estado actual del rate limiting sin incrementar contadores.
   *
   * @param action - Acción que se está consultando
   * @param identifier - Identificador único del cliente
   * @param config - Configuración del rate limiting
   * @returns Estado actual del rate limiting
   *
   * @example
   * ```typescript
   * const status = await this.getRateLimitStatus('login', '192.168.1.1', {
   *   maxAttempts: 5,
   *   windowSeconds: 300
   * });
   * ```
   */
  async getRateLimitStatus(
    action: string,
    identifier: string,
    config: RateLimitConfig,
  ): Promise<RateLimitResult> {
    const key = this.generateKey(action, identifier);
    const blockKey = this.generateBlockKey(action, identifier);

    try {
      // Verificar estado de bloqueo
      if (config.blockDurationSeconds) {
        const blockInfo = await this.checkBlockStatus(blockKey);
        if (blockInfo.blocked) {
          return {
            allowed: false,
            remaining: 0,
            resetTime: Math.ceil(blockInfo.blockTimeRemaining! / 1000),
            windowSeconds: config.windowSeconds,
            blocked: true,
            blockTimeRemaining: blockInfo.blockTimeRemaining,
          };
        }
      }

      // Obtener contador actual
      const currentCountStr = await this.redisService.get(key);
      const currentCount = currentCountStr ? parseInt(currentCountStr, 10) : 0;

      const remaining = Math.max(0, config.maxAttempts - currentCount);
      const allowed = currentCount < config.maxAttempts;

      return {
        allowed,
        remaining,
        resetTime: config.windowSeconds,
        windowSeconds: config.windowSeconds,
        blocked: false,
      };
    } catch (error) {
      this.logger.error(
        `Error obteniendo estado de rate limiting para ${key}:`,
        error,
      );
      return {
        allowed: true,
        remaining: config.maxAttempts,
        resetTime: config.windowSeconds,
        windowSeconds: config.windowSeconds,
        blocked: false,
      };
    }
  }

  /**
   * Resetea el contador de rate limiting para un cliente específico.
   *
   * @param action - Acción a resetear
   * @param identifier - Identificador único del cliente
   *
   * @example
   * ```typescript
   * // Resetear límites después de login exitoso
   * await this.resetRateLimit('login', userIp);
   * ```
   */
  async resetRateLimit(action: string, identifier: string): Promise<void> {
    const key = this.generateKey(action, identifier);
    const blockKey = this.generateBlockKey(action, identifier);

    try {
      await this.redisService.delete([key, blockKey]);
    } catch (error) {
      this.logger.error(`Error reseteando rate limiting para ${key}:`, error);
    }
  }

  /**
   * Verifica el estado de bloqueo de un cliente.
   *
   * @private
   * @param blockKey - Clave de bloqueo en Redis
   * @returns Estado del bloqueo
   */
  private async checkBlockStatus(blockKey: string): Promise<{
    blocked: boolean;
    blockTimeRemaining?: number;
  }> {
    try {
      const blockExpiry = await this.redisService.get(blockKey);
      if (!blockExpiry) {
        return { blocked: false };
      }

      const expiryTime = parseInt(blockExpiry, 10);
      const now = Date.now();

      if (now >= expiryTime) {
        await this.redisService.delete(blockKey);
        return { blocked: false };
      }

      return {
        blocked: true,
        blockTimeRemaining: expiryTime - now,
      };
    } catch (error) {
      this.logger.error(
        `Error verificando estado de bloqueo para ${blockKey}:`,
        error,
      );
      return { blocked: false };
    }
  }

  /**
   * Bloquea un cliente por un período específico.
   *
   * @private
   * @param blockKey - Clave de bloqueo en Redis
   * @param durationSeconds - Duración del bloqueo en segundos
   */
  private async blockClient(
    blockKey: string,
    durationSeconds: number,
  ): Promise<void> {
    try {
      const expiryTime = Date.now() + durationSeconds * 1000;
      await this.redisService.set(
        blockKey,
        expiryTime.toString(),
        durationSeconds,
      );
    } catch (error) {
      this.logger.error(
        `Error bloqueando cliente con clave ${blockKey}:`,
        error,
      );
    }
  }

  /**
   * Genera la clave de Redis para el rate limiting.
   *
   * @private
   * @param action - Acción que se está limitando
   * @param identifier - Identificador único del cliente
   * @returns Clave de Redis formateada
   */
  private generateKey(action: string, identifier: string): string {
    return `rate_limit:${action}:${identifier}`;
  }

  /**
   * Genera la clave de Redis para el bloqueo.
   *
   * @private
   * @param action - Acción que se está limitando
   * @param identifier - Identificador único del cliente
   * @returns Clave de bloqueo de Redis formateada
   */
  private generateBlockKey(action: string, identifier: string): string {
    return `rate_limit_block:${action}:${identifier}`;
  }
}

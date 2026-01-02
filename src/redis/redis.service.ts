import {
  Injectable,
  OnModuleInit,
  OnModuleDestroy,
  Logger,
} from '@nestjs/common';
import * as Redis from 'ioredis';
import { env } from 'process';

// Configuración para el scan inteligente
interface ScanConfig {
  batchSize: number;
  maxIterations: number;
  timeoutMs: number;
}

interface ScanResult {
  keys: string[];
  cursor: string;
  hasMore: boolean;
  totalScanned: number;
  executionTimeMs: number;
}

interface SessionScanOptions {
  limit?: number;
  offset?: number;
  pattern?: string;
  includeExpired?: boolean;
}

// Interface para los datos de sesión almacenados en Redis
interface SessionData {
  user_id: string;
  [key: string]: any; // Permitir propiedades adicionales
}

// Type guard para verificar si un objeto es SessionData válido
function isSessionData(obj: unknown): obj is SessionData {
  return (
    obj !== null &&
    typeof obj === 'object' &&
    obj !== undefined &&
    'user_id' in obj &&
    typeof (obj as Record<string, unknown>).user_id === 'string'
  );
}

@Injectable()
export class RedisService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(RedisService.name);
  private client: Redis.Redis;

  // Configuración por defecto para el scan inteligente
  private readonly defaultScanConfig: ScanConfig = {
    batchSize: 100, // Número de claves por iteración
    maxIterations: 50, // Máximo 5000 claves por operación
    timeoutMs: 5000, // Timeout de 5 segundos
  };

  onModuleInit() {
    this.client = new Redis.Redis({
      host: env.REDIS_HOST || 'localhost', // Redis server host
      port: 6379, // Redis server port
    });
  }

  onModuleDestroy() {
    void this.client.quit(); //
  }

  async set(key: string, value: string, ttlInSeconds: number): Promise<void> {
    try {
      await this.client.set(key, value, 'EX', ttlInSeconds); // 'EX' sets an expiration time
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : 'Unknown error';
      const errorStack = error instanceof Error ? error.stack : undefined;
      this.logger.error(
        `Error setting key ${key} in Redis: ${errorMessage}`,
        errorStack,
      );
      throw new Error(`Failed to set key in Redis: ${errorMessage}`);
    }
  }

  // Example of getting value from Redis
  async get(key: string): Promise<string | null> {
    try {
      return await this.client.get(key);
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : 'Unknown error';
      const errorStack = error instanceof Error ? error.stack : undefined;
      this.logger.error(
        `Error getting key ${key} from Redis: ${errorMessage}`,
        errorStack,
      );
      throw new Error(`Failed to get key from Redis: ${errorMessage}`);
    }
  }

  /**
   * Elimina una o varias clasves de Redis.
   * Acepta un string (una clave) o un array de strings (multiples claves)-
   * */
  async delete(keys: string | string[]): Promise<number> {
    try {
      // El metodo 'del' de ioredis acepta argumentos rest o un array de strings
      if (Array.isArray(keys) && keys.length === 0) {
        return 0;
      }

      // El operador ... propaga el array si es necesario, y del devuelve el número de claves eliminadas.
      if (Array.isArray(keys)) {
        return await this.client.del(...keys);
      } else {
        return await this.client.del(keys);
      }
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : 'Unknown error';
      const errorStack = error instanceof Error ? error.stack : undefined;
      const keysStr = Array.isArray(keys) ? keys.join(', ') : keys;
      this.logger.error(
        `Error deleting keys ${keysStr} from Redis: ${errorMessage}`,
        errorStack,
      );
      throw new Error(`Failed to delete keys from Redis: ${errorMessage}`);
    }
  }

  /**
   * Ejecuta el comando SCAN de Redis para buscar claves por patrón.
   * Versión básica del scan - para operaciones más complejas usar getAllKeys().
   * Retorna [cursor, keys_array].
   */
  async scan(
    cursor: string,
    pattern: string,
    count: number = 100,
  ): Promise<[string, string[]]> {
    try {
      // Validar parámetros de entrada
      if (count > this.defaultScanConfig.batchSize * 2) {
        this.logger.warn(
          `Scan count ${count} is larger than recommended batch size. Consider using getAllKeys() for large operations.`,
        );
      }

      // 'scan' en ioredis devuelve directamente el array [next_cursor: string, keys: string[]]
      // Usamos 'as' para asegurar la tipificación de la tupla.
      const result = (await this.client.scan(
        cursor,
        'MATCH',
        pattern,
        'COUNT',
        Math.min(count, this.defaultScanConfig.batchSize * 2), // Limitar count máximo
      )) as [string, string[]];

      this.logger.debug(
        `Scan executed for pattern ${pattern}: found ${result[1].length} keys, next cursor: ${result[0]}`,
      );

      return result;
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : 'Unknown error';
      const errorStack = error instanceof Error ? error.stack : undefined;
      this.logger.error(
        `Error scanning Redis with pattern ${pattern}: ${errorMessage}`,
        errorStack,
      );
      throw new Error(`Failed to scan Redis: ${errorMessage}`);
    }
  }

  /**
   * Verifica el estado de la conexión con Redis.
   * Retorna información sobre el estado de la conexión y estadísticas básicas.
   */
  async healthCheck(): Promise<{
    status: 'connected' | 'disconnected' | 'error';
    message: string;
    timestamp: string;
    info?: any;
  }> {
    try {
      // Intentar hacer ping a Redis
      const pingResult = await this.client.ping();

      if (pingResult === 'PONG') {
        // Obtener información adicional del servidor Redis
        const info = await this.client.info('server');

        return {
          status: 'connected',
          message: 'Redis connection is healthy',
          timestamp: new Date().toISOString(),
          info: {
            ping: pingResult,
            serverInfo: info,
          },
        };
      } else {
        return {
          status: 'error',
          message: 'Redis ping returned unexpected response',
          timestamp: new Date().toISOString(),
          info: { ping: pingResult },
        };
      }
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : 'Unknown error';
      const errorStack = error instanceof Error ? error.stack : undefined;

      this.logger.error(
        `Redis health check failed: ${errorMessage}`,
        errorStack,
      );

      return {
        status: 'disconnected',
        message: `Redis connection failed: ${errorMessage}`,
        timestamp: new Date().toISOString(),
      };
    }
  }

  /**
   * Busca todas las claves que coincidan con un patrón de forma inteligente.
   * Implementa paginación y límites para evitar saturar Redis.
   */
  async getAllKeys(
    pattern: string,
    config: Partial<ScanConfig> = {},
  ): Promise<ScanResult> {
    const scanConfig = { ...this.defaultScanConfig, ...config };
    const startTime = Date.now();
    let cursor = '0';
    let allKeys: string[] = [];
    let iterations = 0;
    let totalScanned = 0;

    try {
      do {
        // Verificar timeout
        if (Date.now() - startTime > scanConfig.timeoutMs) {
          this.logger.warn(
            `Scan timeout reached for pattern ${pattern} after ${iterations} iterations`,
          );
          break;
        }

        // Verificar límite de iteraciones
        if (iterations >= scanConfig.maxIterations) {
          this.logger.warn(
            `Max iterations reached for pattern ${pattern}: ${iterations}`,
          );
          break;
        }

        const [nextCursor, keys] = await this.client.scan(
          cursor,
          'MATCH',
          pattern,
          'COUNT',
          scanConfig.batchSize,
        );

        allKeys = allKeys.concat(keys);
        totalScanned += keys.length;
        cursor = nextCursor;
        iterations++;

        // Log progreso cada 10 iteraciones
        if (iterations % 10 === 0) {
          this.logger.debug(
            `Scan progress for pattern ${pattern}: ${totalScanned} keys found in ${iterations} iterations`,
          );
        }
      } while (cursor !== '0');

      const executionTime = Date.now() - startTime;

      this.logger.log(
        `Scan completed for pattern ${pattern}: ${allKeys.length} keys found in ${executionTime}ms`,
      );

      return {
        keys: allKeys,
        cursor,
        hasMore: cursor !== '0',
        totalScanned,
        executionTimeMs: executionTime,
      };
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : 'Unknown error';
      const errorStack = error instanceof Error ? error.stack : undefined;
      this.logger.error(
        `Error in getAllKeys with pattern ${pattern}: ${errorMessage}`,
        errorStack,
      );
      throw new Error(`Failed to get all keys: ${errorMessage}`);
    }
  }

  /**
   * Busca sesiones activas de un usuario específico por su UUID.
   * Optimizado para evitar saturar Redis con búsquedas masivas.
   */
  async getUserActiveSessions(
    userUuid: string,
    options: SessionScanOptions = {},
  ): Promise<{
    sessions: string[];
    totalFound: number;
    executionTimeMs: number;
    hasMore: boolean;
  }> {
    const pattern = options.pattern || `session:${userUuid}:*`;
    const limit = options.limit || 100;
    const offset = options.offset || 0;

    try {
      const scanResult = await this.getAllKeys(pattern, {
        batchSize: Math.min(limit * 2, 200), // Optimizar batch size
        maxIterations: 25, // Reducir iteraciones para sesiones
        timeoutMs: 3000, // Timeout más corto para sesiones
      });

      // Aplicar paginación
      const paginatedSessions = scanResult.keys.slice(offset, offset + limit);

      // Si se requiere, filtrar sesiones expiradas
      let validSessions = paginatedSessions;
      if (!options.includeExpired) {
        validSessions = await this.filterValidSessions(paginatedSessions);
      }

      return {
        sessions: validSessions,
        totalFound: scanResult.keys.length,
        executionTimeMs: scanResult.executionTimeMs,
        hasMore: offset + limit < scanResult.keys.length,
      };
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : 'Unknown error';
      const errorStack = error instanceof Error ? error.stack : undefined;
      this.logger.error(
        `Error getting active sessions for user ${userUuid}: ${errorMessage}`,
        errorStack,
      );
      throw new Error(`Failed to get user sessions: ${errorMessage}`);
    }
  }

  /**
   * Filtra sesiones válidas (no expiradas) de una lista de claves.
   */
  private async filterValidSessions(sessionKeys: string[]): Promise<string[]> {
    if (sessionKeys.length === 0) return [];

    try {
      // Usar pipeline para verificar múltiples claves de forma eficiente
      const pipeline = this.client.pipeline();
      sessionKeys.forEach((key) => {
        pipeline.exists(key);
      });

      const results = await pipeline.exec();
      const validSessions: string[] = [];

      results?.forEach((result, index) => {
        if (result && result[1] === 1) {
          // La clave existe (no ha expirado)
          validSessions.push(sessionKeys[index]);
        }
      });

      return validSessions;
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : 'Unknown error';
      this.logger.error(
        `Error filtering valid sessions: ${errorMessage}`,
        error instanceof Error ? error.stack : undefined,
      );
      // En caso de error, devolver todas las sesiones
      return sessionKeys;
    }
  }

  /**
   * Busca y elimina sesiones filtrando por contenido del JSON almacenado.
   * Útil cuando las claves no incluyen el user_id pero el contenido sí.
   */
  async deleteSessionsByUserId(
    userId: string,
    sessionPattern: string = 'session:*',
    batchSize: number = 50,
  ): Promise<{
    deletedCount: number;
    totalScanned: number;
    executionTimeMs: number;
  }> {
    const startTime = Date.now();
    let totalScanned = 0;
    let deletedCount = 0;

    try {
      // Usar getAllKeys para obtener todas las claves de sesión de forma eficiente
      const scanResult = await this.getAllKeys(sessionPattern, {
        batchSize: 100,
        maxIterations: 50,
        timeoutMs: 10000, // Timeout más largo para esta operación
      });

      totalScanned = scanResult.keys.length;

      if (scanResult.keys.length === 0) {
        return {
          deletedCount: 0,
          totalScanned: 0,
          executionTimeMs: Date.now() - startTime,
        };
      }

      // Procesar en lotes para evitar saturar Redis
      const sessionKeysToDelete: string[] = [];

      for (let i = 0; i < scanResult.keys.length; i += batchSize) {
        const batch = scanResult.keys.slice(i, i + batchSize);

        // Usar pipeline para obtener múltiples valores de forma eficiente
        const pipeline = this.client.pipeline();
        batch.forEach((key) => {
          pipeline.get(key);
        });

        const results = await pipeline.exec();

        // Filtrar sesiones que pertenecen al usuario
        results?.forEach((result, index) => {
          if (result && result[1]) {
            try {
              const parsedData: unknown = JSON.parse(result[1] as string);
              if (isSessionData(parsedData) && parsedData.user_id === userId) {
                sessionKeysToDelete.push(batch[index]);
              }
            } catch (e) {
              this.logger.warn(
                `Error parsing session data for key ${batch[index]}:`,
                e,
              );
            }
          }
        });

        this.logger.debug(
          `Processed batch ${Math.floor(i / batchSize) + 1}: found ${sessionKeysToDelete.length} sessions for user ${userId}`,
        );
      }

      // Eliminar todas las sesiones encontradas
      if (sessionKeysToDelete.length > 0) {
        deletedCount = await this.delete(sessionKeysToDelete);
      }

      const executionTime = Date.now() - startTime;
      this.logger.log(
        `Deleted ${deletedCount} sessions for user ${userId} (scanned ${totalScanned} keys) in ${executionTime}ms`,
      );

      return {
        deletedCount,
        totalScanned,
        executionTimeMs: executionTime,
      };
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : 'Unknown error';
      const errorStack = error instanceof Error ? error.stack : undefined;
      this.logger.error(
        `Error deleting sessions by user ID ${userId}: ${errorMessage}`,
        errorStack,
      );
      throw new Error(`Failed to delete sessions by user ID: ${errorMessage}`);
    }
  }

  /**
   * Elimina todas las sesiones activas de un usuario de forma eficiente.
   * Asume que las claves siguen el patrón session:${userUuid}:*
   */
  async deleteUserSessions(
    userUuid: string,
    batchSize: number = 50,
  ): Promise<{
    deletedCount: number;
    totalFound: number;
    executionTimeMs: number;
  }> {
    const startTime = Date.now();

    try {
      // Buscar todas las sesiones del usuario
      const sessionsResult = await this.getUserActiveSessions(userUuid, {
        includeExpired: false, // Solo sesiones válidas
      });

      if (sessionsResult.sessions.length === 0) {
        return {
          deletedCount: 0,
          totalFound: 0,
          executionTimeMs: Date.now() - startTime,
        };
      }

      let deletedCount = 0;
      const sessions = sessionsResult.sessions;

      // Eliminar en lotes para evitar saturar Redis
      for (let i = 0; i < sessions.length; i += batchSize) {
        const batch = sessions.slice(i, i + batchSize);
        const batchDeletedCount = await this.delete(batch);
        deletedCount += batchDeletedCount;

        this.logger.debug(
          `Deleted batch ${Math.floor(i / batchSize) + 1}: ${batchDeletedCount} sessions for user ${userUuid}`,
        );
      }

      const executionTime = Date.now() - startTime;
      this.logger.log(
        `Deleted ${deletedCount} sessions for user ${userUuid} in ${executionTime}ms`,
      );

      return {
        deletedCount,
        totalFound: sessionsResult.totalFound,
        executionTimeMs: executionTime,
      };
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : 'Unknown error';
      const errorStack = error instanceof Error ? error.stack : undefined;
      this.logger.error(
        `Error deleting sessions for user ${userUuid}: ${errorMessage}`,
        errorStack,
      );
      throw new Error(`Failed to delete user sessions: ${errorMessage}`);
    }
  }
}

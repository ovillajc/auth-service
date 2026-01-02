import {
  Injectable,
  CanActivate,
  ExecutionContext,
  HttpException,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Request, Response } from 'express';
import { RateLimitService } from '../services/rate-limit.service';
import {
  RATE_LIMIT_KEY,
  RateLimitOptions,
} from '../decorators/rate-limit.decorator';

/**
 * Interfaz para el objeto request extendido con propiedades de usuario
 */
interface ExtendedRequest extends Request {
  user?: {
    id?: string;
    sessionId?: string;
  };
}

/**
 * Guard que implementa rate limiting para proteger endpoints contra ataques de fuerza bruta
 * y abuso de API. Utiliza Redis como backend de almacenamiento para mantener contadores
 * distribuidos entre múltiples instancias de la aplicación.
 *
 * El guard verifica los metadatos del decorador @RateLimit() aplicado a los endpoints
 * y aplica las restricciones correspondientes basadas en la IP del cliente o un
 * identificador personalizado.
 *
 * @example
 * ```typescript
 * // Aplicar globalmente en main.ts
 * app.useGlobalGuards(new RateLimitGuard(rateLimitService, reflector));
 * ```
 *
 * @example
 * ```typescript
 * // Aplicar a un controlador específico
 * @Controller('auth')
 * @UseGuards(RateLimitGuard)
 * export class AuthController {
 *   @RateLimit({ maxAttempts: 5, windowSeconds: 300 })
 *   @Post('login')
 *   async login(@Body() loginDto: LoginDto) {
 *     return this.authService.login(loginDto);
 *   }
 * }
 * ```
 */
@Injectable()
export class RateLimitGuard implements CanActivate {
  private readonly logger = new Logger(RateLimitGuard.name);

  constructor(
    private readonly rateLimitService: RateLimitService,
    private readonly reflector: Reflector,
  ) {}

  /**
   * Determina si la solicitud actual puede proceder basándose en las reglas de rate limiting.
   * Verifica los metadatos del endpoint, extrae la configuración de rate limiting,
   * y consulta el servicio de rate limiting para determinar si la solicitud está permitida.
   *
   * @param context - Contexto de ejecución de NestJS que contiene información sobre la solicitud
   * @returns Promise<boolean> - true si la solicitud está permitida, false en caso contrario
   * @throws HttpException - Cuando se excede el límite de rate limiting
   *
   * @example
   * ```typescript
   * // El guard se ejecuta automáticamente antes del handler del endpoint
   * // Si el rate limit se excede, lanza HttpException con status 429
   * ```
   */
  async canActivate(context: ExecutionContext): Promise<boolean> {
    // Obtener metadatos del decorador @RateLimit()
    const rateLimitOptions = this.reflector.getAllAndOverride<RateLimitOptions>(
      RATE_LIMIT_KEY,
      [context.getHandler(), context.getClass()],
    );

    // Si no hay configuración de rate limiting, permitir la solicitud
    if (!rateLimitOptions) {
      return true;
    }

    // Si está configurado para omitir el rate limiting, permitir la solicitud
    if (rateLimitOptions.skipIf) {
      return true;
    }

    const request = context.switchToHttp().getRequest<ExtendedRequest>();
    const response = context.switchToHttp().getResponse<Response>();

    // Generar identificador para el rate limiting
    const identifier = this.generateIdentifier(request, rateLimitOptions);

    // Generar acción basada en el endpoint
    const action = this.generateAction(context);

    try {
      // Verificar rate limiting
      const result = await this.rateLimitService.checkRateLimit(
        action,
        identifier,
        {
          maxAttempts: rateLimitOptions.maxAttempts,
          windowSeconds: rateLimitOptions.windowSeconds,
          blockDurationSeconds: rateLimitOptions.blockDurationSeconds,
        },
      );

      // Añadir headers informativos sobre el rate limiting
      this.addRateLimitHeaders(response, result, rateLimitOptions);

      // Si la solicitud no está permitida, lanzar excepción
      if (!result.allowed) {
        const message = this.generateErrorMessage(rateLimitOptions, result);
        this.logger.warn(
          `Rate limit excedido para ${identifier} en acción ${action}. ` +
            `Intentos: ${rateLimitOptions.maxAttempts}, ` +
            `Ventana: ${rateLimitOptions.windowSeconds}s, ` +
            `Bloqueado: ${result.blocked}`,
        );
        throw new HttpException(message, HttpStatus.TOO_MANY_REQUESTS);
      }

      this.logger.debug(
        `Rate limit OK para ${identifier} en acción ${action}. ` +
          `Restantes: ${result.remaining}/${rateLimitOptions.maxAttempts}`,
      );

      return true;
    } catch (error: unknown) {
      if (error instanceof HttpException) {
        throw error;
      }

      // En caso de error del servicio, registrar y permitir la solicitud
      this.logger.error(
        `Error en rate limiting para ${identifier} en acción ${action}:`,
        error,
      );
      return true;
    }
  }

  /**
   * Genera un identificador único para el rate limiting basado en la configuración.
   * Por defecto usa la IP del cliente, pero puede usar identificadores personalizados.
   *
   * @private
   * @param request - Objeto de solicitud HTTP
   * @param options - Opciones de configuración del rate limiting
   * @returns Identificador único para el rate limiting
   *
   * @example
   * ```typescript
   * // Con IP (por defecto)
   * const identifier = this.generateIdentifier(request, { maxAttempts: 5, windowSeconds: 300 });
   * // Resultado: "192.168.1.1"
   *
   * // Con identificador personalizado
   * const identifier = this.generateIdentifier(request, {
   *   maxAttempts: 5,
   *   windowSeconds: 300,
   *   keyGenerator: 'user_id'
   * });
   * // Resultado: "user_123" (si request.user.id = 123)
   * ```
   */
  private generateIdentifier(
    request: ExtendedRequest,
    options: RateLimitOptions,
  ): string {
    if (options.keyGenerator) {
      // Intentar obtener el identificador personalizado
      switch (options.keyGenerator) {
        case 'user_id':
          return request.user?.id || this.getClientIp(request);
        case 'session_id':
          return request.user?.sessionId || this.getClientIp(request);
        case 'api_key': {
          const apiKey = request.headers['x-api-key'] as string;
          return apiKey || this.getClientIp(request);
        }
        default: {
          // Si es un path personalizado, intentar extraerlo del request
          const customValue = this.extractValueFromPath(
            request,
            options.keyGenerator,
          );
          return customValue || this.getClientIp(request);
        }
      }
    }

    // Por defecto, usar la IP del cliente
    return this.getClientIp(request);
  }

  /**
   * Extrae la IP del cliente de la solicitud HTTP, considerando proxies y load balancers.
   *
   * @private
   * @param request - Objeto de solicitud HTTP
   * @returns Dirección IP del cliente
   *
   * @example
   * ```typescript
   * const ip = this.getClientIp(request);
   * // Resultado: "192.168.1.1" o "::1" para localhost
   * ```
   */
  private getClientIp(request: Request): string {
    // Verificar headers de proxy comunes
    const forwarded = request.headers['x-forwarded-for'] as string;
    if (forwarded) {
      // X-Forwarded-For puede contener múltiples IPs separadas por comas
      return forwarded.split(',')[0].trim();
    }

    const realIp = request.headers['x-real-ip'] as string;
    if (realIp) {
      return realIp;
    }

    const clientIp = request.headers['x-client-ip'] as string;
    if (clientIp) {
      return clientIp;
    }

    // Fallback a la IP de conexión directa
    return request.ip || request.connection.remoteAddress || 'unknown';
  }

  /**
   * Extrae un valor del objeto request usando un path de propiedades.
   *
   * @private
   * @param request - Objeto de solicitud HTTP
   * @param path - Path de la propiedad a extraer (ej: 'user.id', 'headers.authorization')
   * @returns Valor extraído o null si no se encuentra
   *
   * @example
   * ```typescript
   * const userId = this.extractValueFromPath(request, 'user.id');
   * const authHeader = this.extractValueFromPath(request, 'headers.authorization');
   * ```
   */
  private extractValueFromPath(request: Request, path: string): string | null {
    try {
      const parts = path.split('.');

      let current: any = request;

      for (const part of parts) {
        if (current && typeof current === 'object' && part in current) {
          // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
          current = current[part];
        } else {
          return null;
        }
      }

      return current ? String(current) : null;
    } catch (error) {
      this.logger.warn(`Error extrayendo valor del path ${path}:`, error);
      return null;
    }
  }

  /**
   * Genera un nombre de acción único basado en el contexto del endpoint.
   *
   * @private
   * @param context - Contexto de ejecución de NestJS
   * @returns Nombre de acción para el rate limiting
   *
   * @example
   * ```typescript
   * // Para AuthController.login()
   * const action = this.generateAction(context);
   * // Resultado: "AuthController.login"
   * ```
   */
  private generateAction(context: ExecutionContext): string {
    const className = context.getClass().name;
    const methodName = context.getHandler().name;
    return `${className}.${methodName}`;
  }

  /**
   * Añade headers HTTP informativos sobre el estado del rate limiting.
   * Estos headers ayudan a los clientes a entender los límites y planificar sus solicitudes.
   *
   * @private
   * @param response - Objeto de respuesta HTTP
   * @param result - Resultado de la verificación de rate limiting
   * @param options - Opciones de configuración del rate limiting
   *
   * @example
   * ```typescript
   * // Headers añadidos:
   * // X-RateLimit-Limit: 100
   * // X-RateLimit-Remaining: 95
   * // X-RateLimit-Reset: 1640995200
   * // X-RateLimit-Window: 3600
   * ```
   */
  private addRateLimitHeaders(
    response: Response,

    result: any,
    options: RateLimitOptions,
  ): void {
    response.setHeader('X-RateLimit-Limit', options.maxAttempts);
    // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
    response.setHeader('X-RateLimit-Remaining', result.remaining);
    response.setHeader(
      'X-RateLimit-Reset',
      // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
      Math.floor(Date.now() / 1000) + result.resetTime,
    );
    response.setHeader('X-RateLimit-Window', options.windowSeconds);

    // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
    if (result.blocked) {
      response.setHeader('X-RateLimit-Blocked', 'true');
      // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
      if (result.blockTimeRemaining) {
        response.setHeader(
          'X-RateLimit-Block-Reset',
          Math.floor(Date.now() / 1000) +
            // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
            Math.ceil(result.blockTimeRemaining / 1000),
        );
      }
    }
  }

  /**
   * Genera un mensaje de error personalizado cuando se excede el rate limiting.
   *
   * @private
   * @param options - Opciones de configuración del rate limiting
   * @param result - Resultado de la verificación de rate limiting
   * @returns Mensaje de error personalizado
   *
   * @example
   * ```typescript
   * const message = this.generateErrorMessage(options, result);
   * // Resultado: "Demasiados intentos. Intenta de nuevo en 5 minutos."
   * ```
   */
  private generateErrorMessage(
    options: RateLimitOptions,

    result: any,
  ): string {
    if (options.message) {
      return options.message;
    }

    // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
    if (result.blocked) {
      // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
      const blockMinutes = Math.ceil(result.blockTimeRemaining / 60000);
      return `Acceso bloqueado temporalmente. Intenta de nuevo en ${blockMinutes} minuto(s).`;
    }

    // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
    const resetMinutes = Math.ceil(result.resetTime / 60);
    return `Demasiadas solicitudes. Intenta de nuevo en ${resetMinutes} minuto(s).`;
  }
}

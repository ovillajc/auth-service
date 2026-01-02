import { Controller, Get } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { AppService } from './app.service';
import type { SystemInfo, HealthStatus, ApiStatus } from './app.service';
import { SkipApiKey } from './auth/decorators/skip-api-key.decorator';
import { SkipRateLimit } from './auth/decorators/rate-limit.decorator';
import { Public } from './auth/decorators/public.decorator';

@ApiTags('Sistema')
@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  /**
   * Endpoint raíz que proporciona información básica de la API.
   * @returns Mensaje de bienvenida con información básica de la API.
   */
  @ApiOperation({
    summary: 'Mensaje de bienvenida',
    description: 'Endpoint raíz que proporciona información básica de la API',
  })
  @ApiResponse({
    status: 200,
    description: 'Mensaje de bienvenida exitoso',
    schema: {
      type: 'string',
      example:
        'Bridge RigCore API v1.0.0 - Sistema de autenticación con Redis, API Keys y Rate Limiting',
    },
  })
  @SkipApiKey()
  @SkipRateLimit()
  @Get()
  @Public()
  getHello(): string {
    return this.appService.getHello();
  }

  /**
   * Endpoint de verificación de salud del sistema.
   * Verifica el estado de Redis, base de datos y métricas del sistema.
   * @returns Estado completo de salud del sistema.
   */
  @ApiOperation({
    summary: 'Verificación de salud del sistema',
    description:
      'Verifica el estado de Redis, base de datos y métricas del sistema',
  })
  @ApiResponse({
    status: 200,
    description: 'Estado de salud obtenido exitosamente',
    schema: {
      type: 'object',
      properties: {
        status: { type: 'string', enum: ['healthy', 'degraded', 'unhealthy'] },
        timestamp: { type: 'string', format: 'date-time' },
        uptime: { type: 'number' },
        services: {
          type: 'object',
          properties: {
            redis: { type: 'object' },
            database: { type: 'object' },
          },
        },
        system: {
          type: 'object',
          properties: {
            memory: { type: 'object' },
            cpu: { type: 'object' },
          },
        },
      },
    },
  })
  @Get('health')
  @Public()
  @SkipApiKey()
  @SkipRateLimit()
  async getHealth(): Promise<HealthStatus> {
    return await this.appService.getHealthStatus();
  }

  /**
   * Información del sistema y versión
   * Útil para desarrolladores y debugging
   * Público para facilitar integración
   */
  @Get('info')
  @Public()
  @SkipApiKey()
  @SkipRateLimit()
  getSystemInfo(): SystemInfo {
    return this.appService.getSystemInfo();
  }

  /**
   * Estado general de la API
   * Incluye endpoints disponibles y características
   * Público para descubrimiento de API
   */
  @Get('status')
  @Public()
  @SkipApiKey()
  @SkipRateLimit()
  async getApiStatus(): Promise<ApiStatus> {
    return await this.appService.getApiStatus();
  }

  /**
   * Documentación de la API
   * Información completa sobre endpoints y uso
   * Público para desarrolladores
   */
  @Get('docs')
  @Public()
  @SkipApiKey()
  @SkipRateLimit()
  getApiDocumentation() {
    return this.appService.getApiDocumentation();
  }

  /**
   * Endpoint de ping simple
   * Para verificaciones básicas de conectividad
   * Público y ultra-rápido
   */
  @Get('ping')
  @SkipApiKey()
  @SkipRateLimit()
  ping(): { message: string; timestamp: string } {
    return {
      message: 'pong',
      timestamp: new Date().toISOString(),
    };
  }
}

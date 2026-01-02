import { Injectable } from '@nestjs/common';
import * as os from 'os';
import { RedisService } from './redis/redis.service';
import { SupabaseService } from './supabase/supabase.service';

export interface SystemInfo {
  name: string;
  version?: string;
  nodeVersion: string;
  environment: string;
  uptimeSeconds: number;
  timestamp: string;
}

export interface HealthStatus {
  status: 'healthy' | 'degraded' | 'unhealthy';
  timestamp: string;
  uptime: number;
  services: {
    redis: {
      status: 'connected' | 'disconnected' | 'error';
      message: string;
      timestamp: string;
      info?: any;
    };
    database?: Record<string, any>;
  };
  system: {
    memory: {
      total: number;
      free: number;
      rss: number;
      heapTotal: number;
      heapUsed: number;
      external: number;
    };
    cpu: {
      loadAvg: number[];
      cpus: number;
    };
  };
}

export interface ApiStatus {
  status: 'ok' | 'degraded' | 'unavailable';
  endpoints: string[];
  features: string[];
  timestamp: string;
}

@Injectable()
export class AppService {
  private readonly startTime = Date.now();

  constructor(
    private readonly redisService: RedisService,
    private readonly supabaseService: SupabaseService,
  ) {}

  getHello(): string {
    return 'Bridge RigCore API - Sistema de autenticación con Redis, API Keys y Rate Limiting';
  }

  async getHealthStatus(): Promise<HealthStatus> {
    const redis = await this.redisService.healthCheck();

    // System metrics
    const memUsage = process.memoryUsage();
    const totalMem = os.totalmem();
    const freeMem = os.freemem();
    const loadAvg = os.loadavg();
    const cpus = os.cpus().length;

    let status: HealthStatus['status'];
    if (redis.status === 'connected') {
      status = 'healthy';
    } else if (redis.status === 'error') {
      status = 'degraded';
    } else {
      status = 'unhealthy';
    }

    return {
      status,
      timestamp: new Date().toISOString(),
      uptime: Math.floor(process.uptime()),
      services: {
        redis,
        // Base de datos: en esta API el cliente de Supabase no tiene ping simple,
        // así que exponemos información mínima del cliente
        database: {
          clientInitialized: Boolean(this.supabaseService.getClient()),
        },
      },
      system: {
        memory: {
          total: totalMem,
          free: freeMem,
          rss: memUsage.rss,
          heapTotal: memUsage.heapTotal,
          heapUsed: memUsage.heapUsed,
          external: memUsage.external ?? 0,
        },
        cpu: {
          loadAvg,
          cpus,
        },
      },
    };
  }

  getSystemInfo(): SystemInfo {
    return {
      name: 'Bridge RigCore API',
      version: undefined, // Opcional: puede leerse de package.json si se requiere
      nodeVersion: process.version,
      environment: process.env.NODE_ENV || 'development',
      uptimeSeconds: Math.floor((Date.now() - this.startTime) / 1000),
      timestamp: new Date().toISOString(),
    };
  }

  async getApiStatus(): Promise<ApiStatus> {
    const endpoints = ['/', '/health', '/info', '/status', '/docs', '/ping'];
    const features = [
      'JWT Auth',
      'API Keys',
      'Rate Limiting',
      'Redis Sessions',
    ];

    const redis = await this.redisService.healthCheck();
    const status: ApiStatus['status'] =
      redis.status === 'connected' ? 'ok' : 'degraded';

    return {
      status,
      endpoints,
      features,
      timestamp: new Date().toISOString(),
    };
  }

  getApiDocumentation() {
    // Stub de documentación. Si Swagger está configurado en main.ts, normalmente
    // se expone en /api o /docs. Aquí devolvemos metadatos básicos.
    return {
      name: 'Bridge RigCore API',
      docsHint:
        'Swagger debe estar configurado en main.ts; revisa la ruta pública configurada.',
      possibleRoutes: ['/api', '/docs'],
      timestamp: new Date().toISOString(),
    };
  }
}

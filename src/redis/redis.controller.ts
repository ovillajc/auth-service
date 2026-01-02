import { Controller, Get } from '@nestjs/common';
import { RedisService } from './redis.service';

@Controller('redis')
export class RedisController {
  constructor(private readonly redisService: RedisService) {}

  /**
   * Endpoint para verificar el estado de la conexión con Redis.
   * Requiere autenticación JWT y API key válida.
   * Retorna información sobre el estado de la conexión y estadísticas básicas.
   */
  @Get('health')
  async getRedisHealth() {
    return await this.redisService.healthCheck();
  }
}

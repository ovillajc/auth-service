import { SetMetadata } from '@nestjs/common';

/**
 * Llave para almacenar metadatos y determinar si un endpoint debe omitir la validación de API key.
 */
export const SKIP_API_KEY = 'skipApiKey';

/**
 * Decorador @SkipApiKey() que marca un endpoint para omitir la validación de API key.
 * Útil para endpoints que no requieren API key como login, health checks, etc.
 *
 * @example
 * @SkipApiKey()
 * @Get('health')
 * async healthCheck() {
 *   return { status: 'ok' };
 * }
 */
export const SkipApiKey = () => SetMetadata(SKIP_API_KEY, true);

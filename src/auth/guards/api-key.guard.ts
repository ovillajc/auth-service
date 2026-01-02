import {
  Injectable,
  CanActivate,
  ExecutionContext,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Request } from 'express';
import { ApiKeyService } from '../services/api-key.service';
import { SKIP_API_KEY } from '../decorators/skip-api-key.decorator';
import { ApiKeyPayload } from '../interfaces/api-key.interface';

// Extendemos la interfaz Request para incluir el payload del API key
interface RequestWithApiKey extends Request {
  apiKeyPayload?: ApiKeyPayload;
}

@Injectable()
export class ApiKeyGuard implements CanActivate {
  constructor(
    private readonly apiKeyService: ApiKeyService,
    private readonly reflector: Reflector,
  ) {}

  canActivate(context: ExecutionContext): boolean {
    // Verificamos si el endpoint tiene el decorador @SkipApiKey()
    const skipApiKey = this.reflector.getAllAndOverride<boolean>(SKIP_API_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (skipApiKey) {
      return true; // Omitimos la validación de API key
    }

    const request = context.switchToHttp().getRequest<RequestWithApiKey>();

    try {
      // Obtenemos el API key del header
      const apiKey = this.extractApiKeyFromRequest(request);

      // Si no hay API key, lanzamos error
      if (!apiKey) {
        throw new UnauthorizedException(
          'API key requerido. Incluye el header X-API-Key.',
        );
      }

      // Verificamos el API key
      const payload = this.apiKeyService.verifyApiKey(apiKey);

      // Guardamos el payload en el request para uso posterior
      request.apiKeyPayload = payload;

      return true;
    } catch (error) {
      if (error instanceof UnauthorizedException) {
        throw error;
      }
      throw new UnauthorizedException('API key inválido');
    }
  }

  /**
   * Extrae el API key de la request
   * Busca en el header X-API-Key, Authorization, o query parameter api_key
   */
  private extractApiKeyFromRequest(req: Request): string | null {
    // Primero buscamos en el header X-API-Key
    const headerApiKey = req.headers['x-api-key'] as string;
    if (headerApiKey) {
      return headerApiKey;
    }

    // También permitimos en el header Authorization con formato "ApiKey <key>"
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('ApiKey ')) {
      return authHeader.substring(7); // Removemos "ApiKey "
    }

    // Como última opción, buscamos en query parameters
    const queryApiKey = req.query.api_key as string;
    if (queryApiKey) {
      return queryApiKey;
    }

    return null;
  }
}

import {
  Injectable,
  NestMiddleware,
  UnauthorizedException,
} from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import { Reflector } from '@nestjs/core';
import { ApiKeyService } from '../services/api-key.service';
import { ApiKeyPayload } from '../interfaces/api-key.interface';

// Extendemos la interfaz Request para incluir el payload del API key
interface RequestWithApiKey extends Request {
  apiKeyPayload?: ApiKeyPayload;
}

@Injectable()
export class ApiKeyMiddleware implements NestMiddleware {
  constructor(
    private readonly apiKeyService: ApiKeyService,
    private readonly reflector: Reflector,
  ) {}

  use(req: RequestWithApiKey, res: Response, next: NextFunction): void {
    try {
      // Obtenemos el API key del header
      const apiKey = this.extractApiKeyFromRequest(req);

      // Si no hay API key, lanzamos error
      if (!apiKey) {
        throw new UnauthorizedException(
          'API key requerido. Incluye el header X-API-Key.',
        );
      }

      // Verificamos el API key
      const payload = this.apiKeyService.verifyApiKey(apiKey);

      // Guardamos el payload en el request para uso posterior
      req.apiKeyPayload = payload;

      // Continuamos con el siguiente middleware/handler
      next();
    } catch (error) {
      // Si hay cualquier error, devolvemos 401
      if (error instanceof UnauthorizedException) {
        res.status(401).json({
          statusCode: 401,
          message: error.message,
          error: 'Unauthorized',
        });
      } else {
        res.status(401).json({
          statusCode: 401,
          message: 'API key inválido',
          error: 'Unauthorized',
        });
      }
    }
  }

  /**
   * Extrae el API key de la request
   * Busca en el header X-API-Key o en el query parameter api_key
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

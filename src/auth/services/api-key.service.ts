import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as crypto from 'crypto';
import { ApiKeyPayload, SignedApiKey } from '../interfaces/api-key.interface';
import { GenerateApiKeyDto } from '../dto/generate-api-key.dto';

@Injectable()
export class ApiKeyService {
  private readonly secretKey: string;
  private readonly algorithm = 'sha256';

  constructor(private readonly configService: ConfigService) {
    // Obtenemos la clave secreta desde las variables de entorno
    this.secretKey =
      this.configService.get<string>('API_KEY_SECRET') || 'default-secret-key';

    if (this.secretKey === 'default-secret-key') {
      console.warn(
        '⚠️  ADVERTENCIA: Usando clave secreta por defecto. Configura API_KEY_SECRET en producción.',
      );
    }
  }

  /**
   * Genera un nuevo API key firmado
   */
  generateApiKey(generateApiKeyDto: GenerateApiKeyDto): SignedApiKey {
    const now = Math.floor(Date.now() / 1000); // Timestamp en segundos

    // Construimos el payload del API key
    const payload: ApiKeyPayload = {
      clientId: generateApiKeyDto.clientId,
      clientName: generateApiKeyDto.clientName,
      iat: now,
      scopes: generateApiKeyDto.scopes,
      metadata: generateApiKeyDto.metadata,
    };

    // Si se especifica expiración, la calculamos
    if (generateApiKeyDto.expirationDays) {
      payload.exp = now + generateApiKeyDto.expirationDays * 24 * 60 * 60;
    }

    // Convertimos el payload a string para firmarlo
    const payloadString = this.encodePayload(payload);

    // Generamos la firma HMAC
    const signature = this.generateSignature(payloadString);

    // Construimos el API key completo
    const apiKey = `${payloadString}.${signature}`;

    return {
      payload,
      signature,
      apiKey,
    };
  }

  /**
   * Verifica si un API key es válido
   */
  verifyApiKey(apiKey: string): ApiKeyPayload {
    try {
      // Separamos el payload de la firma
      const parts = apiKey.split('.');
      if (parts.length !== 2) {
        throw new UnauthorizedException('Formato de API key inválido');
      }

      const [payloadString, providedSignature] = parts;

      // Verificamos la firma
      const expectedSignature = this.generateSignature(payloadString);
      if (!this.compareSignatures(providedSignature, expectedSignature)) {
        throw new UnauthorizedException('Firma de API key inválida');
      }

      // Decodificamos el payload
      const payload = this.decodePayload(payloadString);

      // Verificamos si el API key ha expirado
      if (payload.exp && Math.floor(Date.now() / 1000) > payload.exp) {
        throw new UnauthorizedException('API key expirado');
      }

      return payload;
    } catch (error) {
      if (error instanceof UnauthorizedException) {
        throw error;
      }
      throw new UnauthorizedException('API key inválido');
    }
  }

  /**
   * Verifica si un API key tiene un scope específico
   */
  hasScope(payload: ApiKeyPayload, requiredScope: string): boolean {
    if (!payload.scopes || payload.scopes.length === 0) {
      return true; // Si no hay scopes definidos, permitimos todo
    }
    return (
      payload.scopes.includes(requiredScope) || payload.scopes.includes('*')
    );
  }

  /**
   * Codifica el payload en base64url
   */
  private encodePayload(payload: ApiKeyPayload): string {
    const jsonString = JSON.stringify(payload);
    return Buffer.from(jsonString)
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }

  /**
   * Decodifica el payload desde base64url
   */
  private decodePayload(encodedPayload: string): ApiKeyPayload {
    // Restauramos el padding de base64 si es necesario
    let base64 = encodedPayload.replace(/-/g, '+').replace(/_/g, '/');
    while (base64.length % 4) {
      base64 += '=';
    }

    const jsonString = Buffer.from(base64, 'base64').toString('utf-8');
    return JSON.parse(jsonString) as ApiKeyPayload;
  }

  /**
   * Genera una firma HMAC para el payload
   */
  private generateSignature(payload: string): string {
    return crypto
      .createHmac(this.algorithm, this.secretKey)
      .update(payload)
      .digest('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }

  /**
   * Compara dos firmas de forma segura para evitar timing attacks
   */
  private compareSignatures(signature1: string, signature2: string): boolean {
    if (signature1.length !== signature2.length) {
      return false;
    }

    let result = 0;
    for (let i = 0; i < signature1.length; i++) {
      result |= signature1.charCodeAt(i) ^ signature2.charCodeAt(i);
    }

    return result === 0;
  }
}

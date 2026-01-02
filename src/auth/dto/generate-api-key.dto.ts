import { IsString, IsOptional, IsArray, IsNumber, Min } from 'class-validator';

/**
 * DTO para generar un nuevo API key
 */
export class GenerateApiKeyDto {
  /**
   * Identificador único del cliente o aplicación
   */
  @IsString()
  clientId: string;

  /**
   * Nombre descriptivo del cliente o aplicación
   */
  @IsString()
  clientName: string;

  /**
   * Duración en días para la expiración del API key (opcional)
   * Si no se proporciona, el API key no expirará
   */
  @IsOptional()
  @IsNumber()
  @Min(1)
  expirationDays?: number;

  /**
   * Permisos o scopes que tendrá este API key (opcional)
   */
  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  scopes?: string[];

  /**
   * Información adicional del cliente (opcional)
   */
  @IsOptional()
  metadata?: Record<string, any>;
}

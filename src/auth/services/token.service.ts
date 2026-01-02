import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as crypto from 'crypto';
import { RedisService } from 'src/redis/redis.service';
import { v4 as uuidv4 } from 'uuid';
import { Profile } from '../interfaces/profile.interface';

export interface SessionPayload {
  user_id: string;
  email: string;
  profile: any;
  access_token: string;
  refresh_token: string;
  expires_in?: number;
  expires_at?: number;
  remember_me: boolean;
  created_at: number;
}

export interface TokenResponse {
  session_id: string;
  access_token: string;
  refresh_token: string;
  backend_token: string;
  expires_in?: number;
  expires_at?: number;
}

@Injectable()
export class TokenService {
  private readonly hmacSecret: string;
  private readonly sessionTtl: number;

  constructor(
    private readonly jwtService: JwtService,
    private readonly redisService: RedisService,
  ) {
    this.hmacSecret =
      process.env.HMAC_SECRET || 'mi_super_secreto_hmac_key_2025';
    this.sessionTtl = parseInt(process.env.SESSION_TTL_SECONDS!) || 86400; // 24 horas
  }

  /**
   * Genera un session_id único y lo firma con HMAC
   */
  private generateSignedSessionId(): string {
    const sessionId = uuidv4();
    const signature = crypto
      .createHmac('sha256', this.hmacSecret)
      .update(sessionId)
      .digest('hex');

    return `${sessionId}.${signature}`;
  }

  /**
   * Verifica la firma HMAC del session_id
   */
  verifySessionIdSignature(signedSessionId: string): {
    valid: boolean;
    sessionId?: string;
  } {
    try {
      const [sessionId, signature] = signedSessionId.split('.');

      if (!sessionId || !signature) {
        return { valid: false };
      }

      const expectedSignature = crypto
        .createHmac('sha256', this.hmacSecret)
        .update(sessionId)
        .digest('hex');

      const isValid = crypto.timingSafeEqual(
        Buffer.from(signature, 'hex'),
        Buffer.from(expectedSignature, 'hex'),
      );

      return { valid: isValid, sessionId: isValid ? sessionId : undefined };
    } catch (error) {
      console.log('Error al verificar la firma HMAC:', error);
      return { valid: false };
    }
  }

  /**
   * Crea una nueva sesión completa con tokens
   */
  async createSession(
    userId: string,
    email: string,
    profile: Profile,
    supabaseAccessToken: string,
    supabaseRefreshToken: string,
    expiresIn: number,
    expiresAt: number,
    rememberMe: boolean = false,
  ): Promise<TokenResponse> {
    // 1. Generar session_id firmado
    const signedSessionId = this.generateSignedSessionId();
    const { sessionId } = this.verifySessionIdSignature(signedSessionId);

    // 2. Crear payload para Redis
    const sessionPayload: SessionPayload = {
      access_token: supabaseAccessToken,
      refresh_token: supabaseRefreshToken,
      user_id: userId,
      email,
      profile,
      expires_in: expiresIn,
      expires_at: expiresAt,
      remember_me: rememberMe,
      created_at: Date.now(),
    };

    // 3. Guardar en Redis con clave única
    const redisKey = `session:${sessionId}`;
    await this.redisService.set(
      redisKey,
      JSON.stringify(sessionPayload),
      this.sessionTtl,
    );

    // 4. Crear JWT para backend (más corto, para validación rápida)
    const backendJwtPayload = {
      sub: userId,
      email,
      session_id: sessionId,
      type: 'backend_access',
    };
    const backendToken = this.jwtService.sign(backendJwtPayload, {
      expiresIn: process.env.BACKEND_JWT_EXP || '1d',
      secret: process.env.JWT_SECRET,
    });

    return {
      session_id: signedSessionId,
      access_token: supabaseAccessToken,
      refresh_token: supabaseRefreshToken,
      backend_token: backendToken,
      expires_in: expiresIn,
      expires_at: expiresAt,
    };
  }

  /**
   * Obtiene los datos de la sesión desde Redis
   */
  async getSession(signedSessionId: string): Promise<SessionPayload | null> {
    const verification = this.verifySessionIdSignature(signedSessionId);

    if (!verification.valid || !verification.sessionId) {
      return null;
    }

    const redisKey = `session:${verification.sessionId}`;
    const sessionData = await this.redisService.get(redisKey);

    if (!sessionData) {
      return null;
    }

    try {
      return JSON.parse(sessionData) as SessionPayload;
    } catch (error) {
      console.log('Error al obtener los datos de Redis:', error);
      return null;
    }
  }

  /**
   * Actualiza una sesión existente (útil para refresh)
   */
  async updateSession(
    signedSessionId: string,
    newSupabaseAccessToken: string,
    newSupabaseRefreshToken: string,
  ): Promise<TokenResponse | null> {
    const verification = this.verifySessionIdSignature(signedSessionId);

    if (!verification.valid || !verification.sessionId) {
      return null;
    }

    const currentSession = await this.getSession(signedSessionId);
    if (!currentSession) {
      return null;
    }

    // Actualizar tokens de Supabase
    currentSession.access_token = newSupabaseAccessToken;
    currentSession.refresh_token = newSupabaseRefreshToken;

    const redisKey = `session:${verification.sessionId}`;
    await this.redisService.set(
      redisKey,
      JSON.stringify(currentSession),
      this.sessionTtl,
    );

    // Generar nuevo backend token
    const backendJwtPayload = {
      sub: currentSession.user_id,
      email: currentSession.email,
      session_id: verification.sessionId,
      type: 'backend_access',
    };
    const backendToken = this.jwtService.sign(backendJwtPayload, {
      expiresIn: process.env.BACKEND_JWT_EXP || '1d',
      secret: process.env.JWT_SECRET,
    });

    return {
      session_id: signedSessionId,
      access_token: newSupabaseAccessToken,
      refresh_token: newSupabaseRefreshToken,
      backend_token: backendToken,
    };
  }

  /**
   * Invalida una sesión específica
   */
  async invalidateSession(signedSessionId: string): Promise<boolean> {
    const verification = this.verifySessionIdSignature(signedSessionId);

    if (!verification.valid || !verification.sessionId) {
      return false;
    }

    const redisKey = `session:${verification.sessionId}`;
    const deletedCount = await this.redisService.delete(redisKey);

    return deletedCount > 0;
  }

  /**
   * Invalida todas las sesiones de un usuario en Redis.
   */
  async invalidateAllUserSessions(userId: string): Promise<number> {
    try {
      // 🚀 Usar el nuevo método optimizado con paginación, timeouts y logging
      const result = await this.redisService.deleteSessionsByUserId(
        userId,
        'session:*',
        50, // Procesar en lotes de 50
      );

      return result.deletedCount;
    } catch (error) {
      // Fallback al método manual en caso de error (compatibilidad)
      console.warn(
        `Error using optimized deleteSessionsByUserId, falling back to manual scan:`,
        error,
      );

      let cursor = '0';
      const sessionKeys: string[] = [];

      // Usar SCAN para encontrar todas las claves que coinciden con el patrón 'session:*'
      do {
        // Usamos el nuevo método scan tipado
        const [nextCursor, keys] = await this.redisService.scan(
          cursor,
          'session:*',
          100,
        );
        cursor = nextCursor;

        for (const key of keys) {
          const sessionData = await this.redisService.get(key);
          if (sessionData) {
            try {
              const session = JSON.parse(sessionData) as SessionPayload;
              // 🚨 Verificamos si la sesión pertenece al usuario
              if (session.user_id === userId) {
                sessionKeys.push(key);
              }
            } catch (e) {
              // Manejo de errores de JSON.parse, importante para datos corruptos.
              console.warn(`Error al parsear sesión en clave ${key}:`, e);
            }
          }
        }
      } while (cursor !== '0');

      // 🚨 Borrar todas las claves encontradas a la vez usando el método corregido.
      if (sessionKeys.length > 0) {
        // delete ahora acepta el array string[]
        return this.redisService.delete(sessionKeys);
      }

      return 0; // No se borró ninguna clave
    }
  }

  /**
   * Obtiene los datos de la sesión desde Redis usando directamente el UUID
   */
  async getSessionByUuid(sessionId: string): Promise<SessionPayload | null> {
    const redisKey = `session:${sessionId}`;
    const sessionData = await this.redisService.get(redisKey);

    if (!sessionData) {
      return null;
    }

    try {
      return JSON.parse(sessionData) as SessionPayload;
    } catch (error) {
      console.log('Error al obtener los datos de Redis:', error);
      return null;
    }
  }

  /**
   * Valida un JWT backend token
   */
  validateBackendToken(token: string): any {
    try {
      return this.jwtService.verify(token, {
        secret: process.env.JWT_SECRET,
      });
    } catch (error) {
      console.log('Error al validar el JWT:', error);
      return null;
    }
  }
}

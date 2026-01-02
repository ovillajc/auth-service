import { Injectable, UnauthorizedException } from '@nestjs/common';

import { LoginUserDto } from './dto/login.dto';
import { Profile } from './interfaces/profile.interface';
import { SupabaseService } from 'src/supabase/supabase.service';
import { TokenService, SessionPayload } from './services/token.service';
import { JwtService } from '@nestjs/jwt';
import { SignOutAllDto } from './dto/sign-out-all.dto';
import { RefreshSessionDto } from './dto/refresh-session.dto';
import { LogoutDto } from './dto/logout.dto';
import { GetProfileDto } from './dto/get-profile.dto';
import { CheckSessionDto } from './dto/check-session.dto';
import { SessionExpirationDto } from './dto/session-expiration.dto';
import { JwtPayload } from './interfaces/jwt-payload.interface';

@Injectable()
export class AuthService {
  constructor(
    private readonly supabaseService: SupabaseService,
    private readonly jwtService: JwtService,
    private readonly tokenService: TokenService,
  ) {}

  // Iniciar sesion y obtener rpc
  async singIn(loginUserDto: LoginUserDto) {
    const { email, password, rememberMe = false } = loginUserDto;

    // 1. Autenticar con Supabase
    const { user, session } = await this.authenticateWithSupabase(
      email,
      password,
    );

    // 2. Obtener perfil del usuario
    const profile = await this.getUserProfileFromRPC(
      session.access_token,
      session.refresh_token,
    );

    // 3. Crear sesión con TokenService y guardar en cache
    const { session_id, backend_token } = await this.tokenService.createSession(
      user.id,
      user.email!,
      profile,
      session.access_token,
      session.refresh_token,
      session.expires_in,
      session.expires_at!,
      rememberMe,
    );

    console.log('Nueva sesión creada correctamente');

    // 4. Retornar credenciales de sesión
    return {
      session_id,
      backend_token,
    };
  }

  // Mantener la sesion activa mediante refresh tokens
  async refreshSession(refreshSessionDto: RefreshSessionDto) {
    const { session_id, refresh_token } = refreshSessionDto;

    // 1. Validar sesión existente
    await this.validateSession(session_id);

    // 2. Refrescar tokens en Supabase
    const { session, user } = await this.refreshSupabaseTokens(
      refresh_token,
      session_id,
    );

    // 3. Actualizar sesión con nuevos tokens
    await this.updateSessionTokens(
      session_id,
      session.access_token,
      session.refresh_token,
    );

    return {
      message: 'Sesion actualizada correctamente',
      updatedTokens: session_id,
      access_token: session.access_token,
      refresh_token: session.refresh_token,
      user: user,
    };
  }

  // Cerrar sesion (logout normal - solo invalida la sesion actual)
  async signOut(logoutDto: LogoutDto) {
    const { signed_session_id } = logoutDto;

    // 1. Obtener datos de la sesion para hacer signOut en Supabase
    const sessionData = await this.tokenService.getSession(signed_session_id);

    // 2. Sign out en Supabase para revocar el token
    await this.signOutFromSupabase(sessionData);

    // 3. Invalidar la sesión en Redis.
    const invalidated =
      await this.tokenService.invalidateSession(signed_session_id);

    if (!invalidated) {
      // Si no se pudo invalidar, significa que la clave ya no existía o la firma era inválida.
      // Lanzamos la excepción si no se pudo hacer NADA (ni Supabase, ni Redis).
      throw new UnauthorizedException('Sesión no encontrada o ya invalidada.');
    }

    return { message: 'Sesión cerrada correctamente' };
  }

  async signOutAll(signOutAllDto: SignOutAllDto) {
    const { access_token, backend_token } = signOutAllDto;

    // Validar parámetros
    if (!access_token || access_token.trim() === '') {
      throw new UnauthorizedException('access_token de Supabase es requerido');
    }

    if (!backend_token || backend_token.trim() === '') {
      throw new UnauthorizedException('backend_token es requerido');
    }

    // 1. Verificar y decodificar el backend token
    const userId = this.validateBackendToken(backend_token);

    // 2. Cerrar sesión global en Supabase
    await this.globalSignOutFromSupabase(access_token);

    // 3. Invalidar todas las sesiones del usuario en Redis
    try {
      const deletedCount =
        await this.tokenService.invalidateAllUserSessions(userId);

      return {
        message: 'Todas las sesiones fueron cerradas correctamente.',
        deleted_sessions_count: deletedCount,
        user_id: userId,
      };
    } catch (redisError) {
      console.error('Error al limpiar sesiones de Redis:', redisError);
      throw new UnauthorizedException(
        'Error al invalidar sesiones del usuario.',
      );
    }
  }

  async getUserProfile(getProfileDto: GetProfileDto) {
    const { access_token, refresh_token } = getProfileDto;

    const supabaseWithSession = this.supabaseService.getClient();
    await supabaseWithSession.auth.setSession({
      access_token: access_token,
      refresh_token: refresh_token,
    });

    const { data: profile, error: rpcError } = await supabaseWithSession
      .rpc('get_user_profile')
      .returns<Profile>()
      .single();

    if (rpcError) {
      throw new UnauthorizedException(rpcError.message);
    }

    if (!profile) {
      throw new UnauthorizedException(
        'No se pudo obtener el perfil de usuario. La función RPC devolvió un valor nulo.',
      );
    }

    return profile;
  }

  // ========== MÉTODOS PRIVADOS ==========

  /**
   * Autentica al usuario con Supabase
   * @private
   */
  private async authenticateWithSupabase(email: string, password: string) {
    const supabase = this.supabaseService.getClient();
    const { data, error } = await supabase.auth.signInWithPassword({
      email,
      password,
    });

    if (error) {
      throw new UnauthorizedException(error.message);
    }

    const session = data.session;
    if (!session) {
      throw new UnauthorizedException('No se pudo crear la sesion.');
    }

    return { user: data.user, session };
  }

  /**
   * Obtiene el perfil del usuario mediante RPC
   * @private
   */
  private async getUserProfileFromRPC(
    accessToken: string,
    refreshToken: string,
  ): Promise<Profile> {
    const supabaseWithSession = this.supabaseService.getClient();
    await supabaseWithSession.auth.setSession({
      access_token: accessToken,
      refresh_token: refreshToken,
    });

    const { data: profile, error: rpcError } = await supabaseWithSession
      .rpc('get_user_profile')
      .returns<Profile>()
      .single();

    if (rpcError) {
      throw new UnauthorizedException(rpcError.message);
    }

    if (!profile) {
      throw new UnauthorizedException(
        'No se pudo obtener el perfil de usuario. La función RPC devolvió un valor nulo.',
      );
    }

    return profile;
  }

  /**
   * Valida que una sesión existe y es válida
   * @private
   */
  private async validateSession(sessionId: string) {
    const currentSession = await this.tokenService.getSession(sessionId);
    if (!currentSession) {
      throw new UnauthorizedException('Sesion invalidada o expirada');
    }
    return currentSession;
  }

  /**
   * Refresca los tokens en Supabase
   * @private
   */
  private async refreshSupabaseTokens(refreshToken: string, sessionId: string) {
    const supabase = this.supabaseService.getClient();
    const { data, error } = await supabase.auth.refreshSession({
      refresh_token: refreshToken,
    });

    if (error) {
      // Si el refresh falla, invalidar la sesion
      await this.tokenService.invalidateSession(sessionId);
      throw new UnauthorizedException(error.message);
    }

    if (!data || !data.session) {
      // Si no hay datos o la sesion no se renovo, invalidar y lanzar error
      await this.tokenService.invalidateSession(sessionId);
      throw new UnauthorizedException('No hay datos del usuario');
    }

    return { session: data.session, user: data.user };
  }

  /**
   * Actualiza la sesión con nuevos tokens
   * @private
   */
  private async updateSessionTokens(
    sessionId: string,
    accessToken: string,
    refreshToken: string,
  ) {
    const updatedTokens = await this.tokenService.updateSession(
      sessionId,
      accessToken,
      refreshToken,
    );

    if (!updatedTokens) {
      throw new UnauthorizedException('No se pudo actualizar la sesion');
    }
  }

  /**
   * Realiza signOut en Supabase
   * @private
   */
  private async signOutFromSupabase(sessionData: SessionPayload | null) {
    if (!sessionData) {
      return;
    }

    const supabase = this.supabaseService.getClient();

    // Supabase solo necesita el access_token para saber qué token revocar.
    await supabase.auth.setSession({
      access_token: sessionData.access_token,
      refresh_token: sessionData.refresh_token,
    });

    const { error } = await supabase.auth.signOut();
    if (error) {
      // Esto es una advertencia. La invalidación de la sesión local puede continuar.
      console.warn('Error al hacer signOut en Supabase:', error.message);
    }
  }

  /**
   * Valida y decodifica el backend token
   * @private
   */
  private validateBackendToken(backendToken: string): string {
    try {
      // Tipar el payload para evitar usos inseguros de 'any'
      const decodedToken = this.jwtService.verify<JwtPayload>(backendToken, {
        ignoreExpiration: true,
        secret: process.env.JWT_SECRET || '',
      });

      if (!decodedToken || typeof decodedToken.sub !== 'string') {
        throw new Error('Token verificado no contiene un "sub" válido.');
      }

      if (decodedToken.type !== 'backend_access') {
        throw new Error('Token no es un backend token válido.');
      }

      return decodedToken.sub;
    } catch (e) {
      console.log('Error al verificar el token:', e);
      throw new UnauthorizedException(
        'Backend Token inválido o sin ID de usuario.',
      );
    }
  }

  /**
   * Realiza signOut global en Supabase
   * @private
   */
  private async globalSignOutFromSupabase(accessToken: string) {
    try {
      const supabase = this.supabaseService.getClient();

      const { error: sessionError } = await supabase.auth.setSession({
        access_token: accessToken,
        refresh_token: '',
      });

      if (!sessionError) {
        const { error: signOutError } = await supabase.auth.signOut({
          scope: 'global',
        });

        if (signOutError) {
          console.warn(
            'Error en Supabase signOut global:',
            signOutError.message,
          );
        }
      }
    } catch (supabaseError) {
      console.warn('Error inesperado en Supabase signOut:', supabaseError);
      // Continuamos con la limpieza de Redis aunque Supabase falle
    }
  }

  /**
   * Verifica si una sesión existe y es válida
   */
  async checkSession(checkSessionDto: CheckSessionDto) {
    const { session_id } = checkSessionDto;

    try {
      // Verificar si la sesión existe en Redis
      const sessionData = await this.tokenService.getSessionByUuid(session_id);

      if (!sessionData) {
        return {
          exists: false,
          message: 'Sesión no encontrada',
        };
      }

      return {
        exists: true,
        user_id: sessionData.user_id,
        email: sessionData.email,
        remember_me: sessionData.remember_me || false,
        message: 'Sesión válida',
      };
    } catch (error) {
      console.error('Error verificando sesión:', error);
      return {
        exists: false,
        message: 'Error verificando sesión',
      };
    }
  }

  /**
   * Obtiene información de expiración de una sesión
   */
  async getSessionExpiration(sessionExpirationDto: SessionExpirationDto) {
    const { session_id } = sessionExpirationDto;

    try {
      // Obtener datos de la sesión
      const sessionData = await this.tokenService.getSessionByUuid(session_id);

      if (!sessionData) {
        return {
          exists: false,
          message: 'Sesión no encontrada',
        };
      }

      // Calcular tiempo restante
      const currentTime = Math.floor(Date.now() / 1000);
      const expiresAt = sessionData.expires_at;
      const expiresIn = expiresAt ? Math.max(0, expiresAt - currentTime) : 0;

      return {
        exists: true,
        expires_in: expiresIn,
        expires_at: expiresAt,
        remember_me: sessionData.remember_me || false,
      };
    } catch (error) {
      console.error('Error obteniendo expiración de sesión:', error);
      return {
        exists: false,
        message: 'Error obteniendo información de sesión',
      };
    }
  }
}

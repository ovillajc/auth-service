import { Body, Controller, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { LoginUserDto } from './dto/login.dto';
import { SignOutAllDto } from './dto/sign-out-all.dto';
import { RefreshSessionDto } from './dto/refresh-session.dto';
import { LogoutDto } from './dto/logout.dto';
import { GetProfileDto } from './dto/get-profile.dto';
import { GenerateApiKeyDto } from './dto/generate-api-key.dto';
import { CheckSessionDto } from './dto/check-session.dto';
import { SessionExpirationDto } from './dto/session-expiration.dto';
import { Public } from './decorators/public.decorator';
import { SkipApiKey } from './decorators/skip-api-key.decorator';
import { StrictRateLimit } from './decorators/rate-limit.decorator';
import { ApiKeyService } from './services/api-key.service';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly apiKeyService: ApiKeyService,
  ) {}

  /**
   * Endpoint público para iniciar sesión.
   * No requiere autenticación JWT ni API key.
   * Implementa rate limiting estricto para prevenir ataques de fuerza bruta.
   * Límite: 5 intentos por IP cada 15 minutos, bloqueo de 30 minutos tras exceder el límite.
   */
  @Public()
  @SkipApiKey()
  @StrictRateLimit()
  @Post('login')
  async login(@Body() loginUserDto: LoginUserDto) {
    return await this.authService.singIn(loginUserDto);
  }

  /**
   * Endpoint protegido para obtener el perfil del usuario.
   * Requiere un token JWT válido.
   */
  @Post('profile')
  async getProfile(@Body() getProfileDto: GetProfileDto) {
    // El guard global se encarga de la autenticación.
    return await this.authService.getUserProfile(getProfileDto);
  }

  /**
   * Endpoint protegido para refrescar la sesión.
   * Requiere un token JWT válido.
   */
  @Post('refresh')
  async refresh(@Body() refreshSessionDto: RefreshSessionDto) {
    return this.authService.refreshSession(refreshSessionDto);
  }

  /**
   * Endpoint protegido para cerrar la sesión actual.
   * Requiere un token JWT válido.
   */
  @Post('logout')
  async logout(@Body() logoutDto: LogoutDto) {
    return await this.authService.signOut(logoutDto);
  }

  /**
   * Endpoint protegido para cerrar todas las sesiones del usuario.
   * Requiere un token JWT válido.
   */
  @Post('logout-all')
  async logoutAll(@Body() signOutAllDto: SignOutAllDto) {
    return await this.authService.signOutAll(signOutAllDto);
  }

  /**
   * Endpoint protegido para generar un nuevo API key.
   * Requiere autenticación JWT pero omite la validación de API key.
   * Solo usuarios autenticados pueden generar API keys.
   */
  @Public()
  @SkipApiKey()
  @Post('generate-api-key')
  generateApiKey(@Body() generateApiKeyDto: GenerateApiKeyDto) {
    return this.apiKeyService.generateApiKey(generateApiKeyDto);
  }

  /**
   * Endpoint protegido para verificar si una sesión existe y es válida.
   * Requiere un token JWT válido.
   */
  @Post('check-session')
  async checkSession(@Body() checkSessionDto: CheckSessionDto) {
    return await this.authService.checkSession(checkSessionDto);
  }

  /**
   * Endpoint protegido para obtener información de expiración de una sesión.
   * Requiere un token JWT válido.
   */
  @Post('session-expiration')
  async getSessionExpiration(
    @Body() sessionExpirationDto: SessionExpirationDto,
  ) {
    return await this.authService.getSessionExpiration(sessionExpirationDto);
  }
}

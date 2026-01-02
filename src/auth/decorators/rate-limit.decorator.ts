import { SetMetadata } from '@nestjs/common';

/**
 * Configuración para el decorador de rate limiting
 */
export interface RateLimitOptions {
  /** Número máximo de intentos permitidos en la ventana de tiempo */
  maxAttempts: number;
  /** Ventana de tiempo en segundos */
  windowSeconds: number;
  /** Tiempo de bloqueo en segundos después de exceder el límite (opcional) */
  blockDurationSeconds?: number;
  /** Identificador personalizado para el rate limiting (opcional, por defecto usa la IP) */
  keyGenerator?: string;
  /** Mensaje personalizado cuando se excede el límite (opcional) */
  message?: string;
  /** Indica si se debe omitir el rate limiting para este endpoint (opcional) */
  skipIf?: boolean;
}

/**
 * Clave de metadatos para el decorador de rate limiting
 */
export const RATE_LIMIT_KEY = 'rate_limit';

/**
 * Decorador para aplicar rate limiting a endpoints específicos.
 * Permite configurar límites de tasa de solicitudes por IP o identificador personalizado.
 *
 * @param options - Configuración del rate limiting
 * @returns Decorador de método para aplicar rate limiting
 *
 * @example
 * ```typescript
 * // Rate limiting básico para login
 * @RateLimit({
 *   maxAttempts: 5,
 *   windowSeconds: 300, // 5 minutos
 *   message: 'Demasiados intentos de login. Intenta de nuevo en 5 minutos.'
 * })
 * @Post('login')
 * async login(@Body() loginDto: LoginDto) {
 *   return this.authService.login(loginDto);
 * }
 * ```
 *
 * @example
 * ```typescript
 * // Rate limiting con bloqueo temporal
 * @RateLimit({
 *   maxAttempts: 3,
 *   windowSeconds: 300,
 *   blockDurationSeconds: 900, // 15 minutos de bloqueo
 *   message: 'Cuenta bloqueada temporalmente por exceso de intentos fallidos.'
 * })
 * @Post('reset-password')
 * async resetPassword(@Body() resetDto: ResetPasswordDto) {
 *   return this.authService.resetPassword(resetDto);
 * }
 * ```
 *
 * @example
 * ```typescript
 * // Rate limiting con identificador personalizado
 * @RateLimit({
 *   maxAttempts: 10,
 *   windowSeconds: 60,
 *   keyGenerator: 'user_id', // Usar user_id en lugar de IP
 *   message: 'Has excedido el límite de solicitudes por minuto.'
 * })
 * @Get('profile')
 * async getProfile(@Req() req: Request) {
 *   return this.userService.getProfile(req.user.id);
 * }
 * ```
 *
 * @example
 * ```typescript
 * // Rate limiting condicional
 * @RateLimit({
 *   maxAttempts: 100,
 *   windowSeconds: 3600,
 *   skipIf: process.env.NODE_ENV === 'development'
 * })
 * @Get('public-data')
 * async getPublicData() {
 *   return this.dataService.getPublicData();
 * }
 * ```
 */
export const RateLimit = (options: RateLimitOptions): MethodDecorator => {
  return SetMetadata(RATE_LIMIT_KEY, options);
};

/**
 * Decorador para omitir el rate limiting en endpoints específicos.
 * Útil cuando se tiene un guard global de rate limiting pero se quiere
 * excluir ciertos endpoints.
 *
 * @returns Decorador de método para omitir rate limiting
 *
 * @example
 * ```typescript
 * // Omitir rate limiting para endpoint de health check
 * @SkipRateLimit()
 * @Get('health')
 * async healthCheck() {
 *   return { status: 'ok', timestamp: new Date().toISOString() };
 * }
 * ```
 *
 * @example
 * ```typescript
 * // Omitir rate limiting para endpoints internos
 * @SkipRateLimit()
 * @Post('internal/webhook')
 * async handleWebhook(@Body() payload: any) {
 *   return this.webhookService.process(payload);
 * }
 * ```
 */
export const SkipRateLimit = (): MethodDecorator => {
  return SetMetadata(RATE_LIMIT_KEY, { skipIf: true });
};

/**
 * Decorador preconfigurado para rate limiting estricto en endpoints de autenticación.
 * Aplica límites conservadores para prevenir ataques de fuerza bruta.
 *
 * @param customOptions - Opciones adicionales para sobrescribir la configuración por defecto
 * @returns Decorador de método con configuración de rate limiting estricta
 *
 * @example
 * ```typescript
 * // Rate limiting estricto para login
 * @StrictRateLimit()
 * @Post('login')
 * async login(@Body() loginDto: LoginDto) {
 *   return this.authService.login(loginDto);
 * }
 * ```
 *
 * @example
 * ```typescript
 * // Rate limiting estricto con mensaje personalizado
 * @StrictRateLimit({
 *   message: 'Demasiados intentos de acceso. Cuenta bloqueada temporalmente.'
 * })
 * @Post('admin/login')
 * async adminLogin(@Body() loginDto: LoginDto) {
 *   return this.authService.adminLogin(loginDto);
 * }
 * ```
 */
export const StrictRateLimit = (
  customOptions: Partial<RateLimitOptions> = {},
): MethodDecorator => {
  const defaultOptions: RateLimitOptions = {
    maxAttempts: 3,
    windowSeconds: 300, // 5 minutos
    blockDurationSeconds: 900, // 15 minutos de bloqueo
    message: 'Demasiados intentos fallidos. Acceso bloqueado temporalmente.',
  };

  const finalOptions = { ...defaultOptions, ...customOptions };
  return SetMetadata(RATE_LIMIT_KEY, finalOptions);
};

/**
 * Decorador preconfigurado para rate limiting moderado en endpoints de API.
 * Aplica límites balanceados para uso general de API.
 *
 * @param customOptions - Opciones adicionales para sobrescribir la configuración por defecto
 * @returns Decorador de método con configuración de rate limiting moderada
 *
 * @example
 * ```typescript
 * // Rate limiting moderado para endpoints de API
 * @ModerateRateLimit()
 * @Get('users')
 * async getUsers(@Query() query: GetUsersDto) {
 *   return this.userService.getUsers(query);
 * }
 * ```
 *
 * @example
 * ```typescript
 * // Rate limiting moderado con límite personalizado
 * @ModerateRateLimit({ maxAttempts: 50 })
 * @Post('upload')
 * async uploadFile(@UploadedFile() file: Express.Multer.File) {
 *   return this.fileService.upload(file);
 * }
 * ```
 */
export const ModerateRateLimit = (
  customOptions: Partial<RateLimitOptions> = {},
): MethodDecorator => {
  const defaultOptions: RateLimitOptions = {
    maxAttempts: 20,
    windowSeconds: 60, // 1 minuto
    message: 'Has excedido el límite de solicitudes por minuto.',
  };

  const finalOptions = { ...defaultOptions, ...customOptions };
  return SetMetadata(RATE_LIMIT_KEY, finalOptions);
};

/**
 * Decorador preconfigurado para rate limiting permisivo en endpoints públicos.
 * Aplica límites altos para endpoints de acceso público.
 *
 * @param customOptions - Opciones adicionales para sobrescribir la configuración por defecto
 * @returns Decorador de método con configuración de rate limiting permisiva
 *
 * @example
 * ```typescript
 * // Rate limiting permisivo para datos públicos
 * @LenientRateLimit()
 * @Get('public/articles')
 * async getPublicArticles(@Query() query: GetArticlesDto) {
 *   return this.articleService.getPublicArticles(query);
 * }
 * ```
 *
 * @example
 * ```typescript
 * // Rate limiting permisivo con ventana personalizada
 * @LenientRateLimit({ windowSeconds: 3600 }) // 1 hora
 * @Get('public/stats')
 * async getPublicStats() {
 *   return this.statsService.getPublicStats();
 * }
 * ```
 */
export const LenientRateLimit = (
  customOptions: Partial<RateLimitOptions> = {},
): MethodDecorator => {
  const defaultOptions: RateLimitOptions = {
    maxAttempts: 100,
    windowSeconds: 300, // 5 minutos
    message:
      'Has excedido el límite de solicitudes. Intenta de nuevo más tarde.',
  };

  const finalOptions = { ...defaultOptions, ...customOptions };
  return SetMetadata(RATE_LIMIT_KEY, finalOptions);
};

import { SetMetadata } from '@nestjs/common';

/**
 * Llave para almacenar metadatos y determinar si un endpoint es público.
 * Se utiliza para que el Guard global (JwtAuthGuard) sepa si debe omitir la autenticación.
 */
export const IS_PUBLIC_KEY = 'isPublic';

/**
 * Decorador @Public() que marca un endpoint como público.
 * Cualquier endpoint con este decorador no requerirá autenticación JWT.
 *
 * @example
 * @Public()
 * @Post('login')
 * async login(@Body() loginUserDto: LoginUserDto) {}
 */
export const Public = () => SetMetadata(IS_PUBLIC_KEY, true);

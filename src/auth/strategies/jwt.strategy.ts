import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { RedisService } from 'src/redis/redis.service';
import { JwtPayload } from '../interfaces/jwt-payload.interface';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private redisService: RedisService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: process.env.JWT_SECRET || '',
    });
  }

  async validate(payload: JwtPayload) {
    // 1. Obtener el ID de sesion del payload del token
    const sessionId = payload.session_id;

    // 2. Construir la clave de Redis
    const redisKey = `session:${sessionId}`;

    // 3. Buscar la sesion en Redis
    const sessionExist = await this.redisService.get(redisKey);

    // 4. Si la sesion no existe, lanzar un error de no autorizado
    if (!sessionExist) {
      throw new UnauthorizedException('Session expired or has been revoked');
    }

    // 5. Si la sesion existe, la validacion es exitosa y retornamos el usuario
    return {
      userId: payload.sub,
      email: payload.email,
      sessionId: payload.session_id,
      type: payload.type,
    };
  }
}

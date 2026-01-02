import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { SupabaseModule } from 'src/supabase/supabase.module';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtStrategy } from './strategies/jwt.strategy';
import { RedisModule } from 'src/redis/redis.module';
import { TokenService } from './services/token.service';
import { ApiKeyService } from './services/api-key.service';
import { RateLimitService } from './services/rate-limit.service';
import { RateLimitGuard } from './guards/rate-limit.guard';

@Module({
  imports: [
    // Retrasa su inicializacion hasta que se complete la carga del modulo
    // JwtModule.registerAsync({
    //   imports: [ConfigModule],
    //   inject: [ConfigService],
    //   useFactory: (configService: ConfigService) => {
    //     console.log('JWT SECRET:', configService.get('JWT_SECRET'));
    //     return {
    //       secret: process.env.JWT_SECRET,
    //       signOptions: {
    //         expiresIn: '1d',
    //       },
    //     };
    //   },
    // }),

    JwtModule.register({
      global: true,
      secret: process.env.JWT_SECRET || '',
      signOptions: { expiresIn: `${process.env.BACKEND_JWT_EXP}` }, // expira en 1 dia
    }),
    SupabaseModule,
    RedisModule,
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    JwtStrategy,
    TokenService,
    ApiKeyService,
    RateLimitService,
    RateLimitGuard,
  ],
  exports: [
    AuthService,
    TokenService,
    ApiKeyService,
    RateLimitService,
    RateLimitGuard,
  ],
})
export class AuthModule {}

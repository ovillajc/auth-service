import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { SupabaseModule } from './supabase/supabase.module';
import { RedisModule } from './redis/redis.module';
import { ConfigModule } from '@nestjs/config';
import { APP_GUARD } from '@nestjs/core';
import { JwtAuthGuard } from './auth/guards/jwt-auth.guard';
import { ApiKeyGuard } from './auth/guards/api-key.guard';

@Module({
  imports: [
    // ConfigModule para acceder a las variables de entorno de manera global
    ConfigModule.forRoot({
      isGlobal: true,
    }),
    AuthModule,
    SupabaseModule,
    RedisModule,
  ],
  controllers: [AppController],
  providers: [
    // AppService para manejar la lógica de la aplicación
    AppService,
    // ApiKeyGuard para proteger los endpoints con API key
    {
      provide: APP_GUARD,
      useClass: ApiKeyGuard,
    },
    // JwtAuthGuard para proteger los endpoints con autenticación JWT
    {
      provide: APP_GUARD,
      useClass: JwtAuthGuard,
    },
  ],
})
export class AppModule {}

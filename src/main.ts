import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe, Logger } from '@nestjs/common';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Habilitar logger
  const logger = new Logger('Bootstrap');

  // Para añadir el prefijo api en la url
  app.setGlobalPrefix('api');

  // Configuraciones global de pipes
  app.useGlobalPipes(
    new ValidationPipe({
      // Remueve todo lo que no esta inncluido en los DTO
      whitelist: true,
      // Re torna bad request si hay propiedades en el objeto no requeridas
      forbidNonWhitelisted: true,
    }),
  );

  await app.listen(process.env.PORT ?? 3005);

  logger.log(`App runing on port ${process.env.PORT}`);
}

void bootstrap();

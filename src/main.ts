import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Habilita CORS para permitir peticiones desde la app en React Native
  app.enableCors();

  // Escucha en '0.0.0.0' para aceptar conexiones locales (Wi-Fi, USB y ADB)
  const port = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;
  await app.listen(port, '0.0.0.0');

  console.log(`🚀 Servidor backend ejecutándose en el puerto ${port}`);
}
void bootstrap();
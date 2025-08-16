/* eslint-disable prettier/prettier */
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
// const port = parseInt(process.env.PORT, 10) || 3001;
  await app.listen(3001); // Verify this port
  console.log(`🚀 Server is running on http://localhost:${3001}`);

}
bootstrap();

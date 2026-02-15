import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import * as bodyParser from 'body-parser';
import * as dotenv from 'dotenv';
import helmet from 'helmet';

dotenv.config();

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Security headers
  app.use(helmet());

  // Body parsing
  app.use(bodyParser.json({ limit: '1mb' }));

  // CORS — allow the browser extension to talk to us
  app.enableCors({
    origin: (origin, callback) => {
      // Extensions send origin as chrome-extension://<id>
      // Also allow localhost for development
      if (
        !origin ||
        origin.startsWith('chrome-extension://') ||
        origin.includes('localhost')
      ) {
        callback(null, true);
      } else if (process.env.NODE_ENV !== 'production') {
        callback(null, true);
      } else {
        callback(new Error('Not allowed by CORS'));
      }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  });

  // Global API prefix
  app.setGlobalPrefix('api');

  const port = process.env.PORT || 3001;
  await app.listen(port, '0.0.0.0');
  console.log(`AI Security Backend running on http://localhost:${port}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
}
bootstrap();

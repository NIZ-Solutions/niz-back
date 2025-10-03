import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { ValidationPipe } from '@nestjs/common';
import { ResponseInterceptor } from './common/interceptors/response.interceptor';
import { AllExceptionsFilter } from './common/filters/all-exceptions.filter';

async function bootstrap() {
  // BigInt → string 직렬화 대응 (전역 설정)
  (BigInt.prototype as any).toJSON = function () {
    return this.toString();
  };

  const app = await NestFactory.create(AppModule);

  // Swagger 설정
  const config = new DocumentBuilder()
    .setTitle('NIZ API Docs')
    .setDescription('NIZ 프로젝트 API')
    .setVersion('1.0')
    .addBearerAuth()
    .build();

  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api', app, document);

  // ValidationPipe (DTO 유효성 검사)
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,              // DTO에 없는 속성 제거
      forbidNonWhitelisted: true,   // 정의되지 않은 속성이 들어오면 에러
      transform: true,              // 타입 자동 변환
    }),
  );

  // 글로벌 인터셉터 (성공 응답 포맷 통일)
  app.useGlobalInterceptors(new ResponseInterceptor());

  // 글로벌 예외 필터 (실패 응답 포맷 통일)
  app.useGlobalFilters(new AllExceptionsFilter());

  await app.listen(3000);
}
bootstrap();
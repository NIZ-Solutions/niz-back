import { Module } from '@nestjs/common';
import { PassportModule } from '@nestjs/passport';
import { JwtModule } from '@nestjs/jwt';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { HttpModule } from '@nestjs/axios';

import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { PrismaService } from '../prisma.service';

import { KakaoStrategy } from './strategies/kakao.strategy';
import { KakaoAuthGuard } from './guards/kakao.guard';
import { JwtStrategy } from './strategies/jwt.strategy';

@Module({
  imports: [
    PassportModule.register({ defaultStrategy: 'jwt' }),
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: async (config: ConfigService) => ({
        secret: config.get<string>('JWT_SECRET'),
        signOptions: { expiresIn: '1h' },
      }),
    }),
    HttpModule, // 추가!
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    PrismaService,
    KakaoStrategy,
    KakaoAuthGuard,
    JwtStrategy,
  ],
  exports: [AuthService],
})
export class AuthModule {}
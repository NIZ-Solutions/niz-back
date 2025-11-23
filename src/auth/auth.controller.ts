import {
  Controller,
  Post,
  Get,
  Body,
  UseGuards,
  Req,
  HttpCode,
  Query,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignupDto } from './dto/signup.dto';
import { LoginDto } from './dto/login.dto';
import { RefreshDto } from './dto/refresh.dto';
import { LogoutDto } from './dto/logout.dto';
import { SignupResponseDto } from './dto/signup-response.dto';
import { LoginResponseDto } from './dto/login-response.dto';
import { RefreshResponseDto } from './dto/refresh-response.dto';
import { LogoutResponseDto } from './dto/logout-response.dto';
import { Public } from '../common/decorators/public.decorator';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import {
  ApiTags,
  ApiOperation,
  ApiCreatedResponse,
  ApiOkResponse,
  ApiBearerAuth,
  ApiBody,
} from '@nestjs/swagger';

@ApiTags('Auth')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  // ======================
  // 일반 회원가입
  // ======================
  @Public()
  @Post('signup')
  @ApiOperation({ summary: '일반 회원가입' })
  @ApiBody({
    schema: {
      example: {
        userId: 'niz123',
        password: 'password123!',
        name: '홍길동',
        phone: '01012345678',
        privacyPolicy: true,
        termsOfService: true,
        paymentPolicy: true,
      },
    },
  })
  @ApiCreatedResponse({ description: '회원가입 성공' })
  async signup(@Body() dto: SignupDto): Promise<SignupResponseDto> {
    return this.authService.signup(dto);
  }

  // ======================
  // 일반 로그인
  // ======================
  @Public()
  @Post('login')
  @HttpCode(200)
  @ApiOperation({ summary: '일반 로그인' })
  @ApiBody({
    schema: {
      example: {
        userId: 'niz123',
        password: 'password123!',
      },
    },
  })
  @ApiOkResponse({ description: '로그인 성공' })
  async login(@Body() dto: LoginDto): Promise<LoginResponseDto> {
    return this.authService.login(dto);
  }

  // ======================
  // 관리자 로그인
  // ======================
  @Public()
  @Post('admin/login')
  @HttpCode(200)
  @ApiOperation({ summary: '관리자 로그인 (role = ADMIN만 허용)' })
  @ApiBody({
    schema: {
      example: {
        userId: 'nizadmin',
        password: 'niz2025!',
      },
    },
  })
  @ApiOkResponse({
    description: '관리자 로그인 성공',
    schema: {
      example: {
        success: true,
        data: {
          id: '1',
          userId: 'nizadmin',
          name: '관리자',
          phone: '',
          createdAt: '2025-11-23T12:00:00.000Z',
          accessToken: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
          refreshToken: 'eyJh...',
        },
      },
    },
  })
  async adminLogin(@Body() dto: LoginDto): Promise<LoginResponseDto> {
    return this.authService.adminLogin(dto);
  }

  // ======================
  // 토큰 재발급
  // ======================
  @Public()
  @Post('refresh')
  @HttpCode(200)
  @ApiOperation({ summary: '토큰 재발급' })
  @ApiBody({
    schema: {
      example: {
        refreshToken: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
      },
    },
  })
  async refresh(@Body() dto: RefreshDto): Promise<RefreshResponseDto> {
    return this.authService.refreshToken(dto.refreshToken);
  }

  // ======================
  // 카카오 로그인
  // ======================
  @Public()
  @Post('kakao')
  @HttpCode(200)
  @ApiOperation({ summary: '카카오 로그인' })
  @ApiBody({
    schema: {
      example: {
        code: '카카오 인가 코드',
      },
    },
  })
  async kakaoLogin(@Body('code') code: string): Promise<LoginResponseDto> {
    return this.authService.kakaoLoginByCode(code);
  }

  // 카카오 리다이렉트
  @Public()
  @Get('kakao/redirect')
  async kakaoRedirect(@Query('code') code: string) {
    return this.authService.kakaoLoginByCode(code);
  }

  // ======================
  // 로그아웃
  // ======================
  @UseGuards(JwtAuthGuard)
  @Post('logout')
  @HttpCode(200)
  @ApiBearerAuth('access-token')
  @ApiOperation({ summary: '로그아웃' })
  @ApiBody({
    schema: {
      example: {
        refreshToken: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
      },
    },
  })
  async logout(@Req() req, @Body() dto: LogoutDto): Promise<LogoutResponseDto> {
    return this.authService.logout(req.user.id, dto.refreshToken);
  }
}
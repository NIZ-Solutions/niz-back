import {
  Controller,
  Post,
  Get,
  Body,
  UseGuards,
  Req,
  HttpCode,
  Query
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
import { KakaoAuthGuard } from './guards/kakao.guard';
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

  // 회원가입
  @Public()
  @Post('signup')
  @ApiOperation({ summary: '회원가입 (모든 약관 동의 필요)' })
  @ApiBody({
    description: '회원가입 요청 DTO',
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
  @ApiCreatedResponse({
    description: '회원가입 성공',
    schema: {
      example: {
        success: true,
        data: {
          id: '1',
          userId: 'niz123',
          name: '홍길동',
          phone: '01012345678',
          createdAt: '2025-09-29T15:30:00.000Z',
          accessToken: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
          refreshToken: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
        },
      },
    },
  })
  async signup(@Body() dto: SignupDto): Promise<SignupResponseDto> {
    return this.authService.signup(dto);
  }

  // 로그인
  @Public()
  @Post('login')
  @HttpCode(200)
  @ApiOperation({ summary: '로그인' })
  @ApiBody({
    description: '로그인 요청 DTO',
    schema: {
      example: {
        userId: 'niz123',
        password: 'password123!',
      },
    },
  })
  @ApiOkResponse({
    description: '로그인 성공',
    schema: {
      example: {
        success: true,
        data: {
          id: '1',
          userId: 'niz123',
          name: '홍길동',
          phone: '01012345678',
          createdAt: '2025-09-29T15:30:00.000Z',
          accessToken: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
          refreshToken: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
        },
      },
    },
  })
  async login(@Body() dto: LoginDto): Promise<LoginResponseDto> {
    return this.authService.login(dto);
  }

  // 토큰 재발급
  @Public()
  @Post('refresh')
  @HttpCode(200)
  @ApiOperation({ summary: '토큰 재발급' })
  @ApiBody({
    description: '리프레시 토큰을 전달하여 새 토큰을 발급받음',
    schema: {
      example: {
        refreshToken: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
      },
    },
  })
  @ApiOkResponse({
    description: '재발급 성공',
    schema: {
      example: {
        success: true,
        data: {
          accessToken: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
          refreshToken: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
        },
      },
    },
  })
  async refresh(@Body() dto: RefreshDto): Promise<RefreshResponseDto> {
    return this.authService.refreshToken(dto.refreshToken);
  }

   // 카카오 로그인
  @Public()
  @Post('kakao')
  @HttpCode(200)
  @ApiOperation({ summary: '카카오 로그인' })
  @ApiBody({
    description: '카카오 인가 코드 전달',
    schema: {
      example: {
        code: '0QzZw89U5s12kFYVvYv2vQftr7YwzKqQW3qrvzI6XbGzFb3m1w',
      },
    },
  })
  @ApiOkResponse({
    description: '카카오 로그인 / 회원가입 성공',
    schema: {
      example: {
        success: true,
        data: {
          id: '15',
          userId: 'kakao_987654321',
          name: '홍길동',
          phone: '',
          createdAt: '2025-10-13T07:00:00.000Z',
          accessToken: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
          refreshToken: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
        },
      },
    },
  })
  async kakaoLogin(@Body('code') code: string): Promise<LoginResponseDto> {
    return this.authService.kakaoLoginByCode(code);
  }
   
  // // 카카오 리다이렉트
  // @Public()
  // @Get('kakao/redirect')
  // async kakaoRedirect(@Query('code') code: string) {
  //   return this.authService.kakaoLoginByCode(code);
  // }

  // 로그아웃
  @UseGuards(JwtAuthGuard)
  @Post('logout')
  @HttpCode(200)
  @ApiBearerAuth('access-token')
  @ApiOperation({ summary: '로그아웃' })
  @ApiBody({
    description: '로그아웃 요청 DTO',
    schema: {
      example: {
        refreshToken: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
      },
    },
  })
  @ApiOkResponse({
    description: '로그아웃 성공',
    schema: {
      example: {
        success: true,
        data: {
          message: '로그아웃 되었습니다.',
        },
      },
    },
  })
  async logout(@Req() req, @Body() dto: LogoutDto): Promise<{ message: string }> {
    await this.authService.logout(req.user.id, dto.refreshToken);
    return { message: '로그아웃 되었습니다.' };
  }
}
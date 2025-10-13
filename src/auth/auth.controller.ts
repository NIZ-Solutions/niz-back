import { 
  Controller, 
  Post, 
  Get, 
  Body, 
  UseGuards, 
  Req, 
  HttpCode 
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
} from '@nestjs/swagger';

@ApiTags('Auth')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  // 회원가입
  @Public()
  @Post('signup')
  @ApiOperation({ summary: '회원가입 (토큰 포함)' })
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

  // 카카오 로그인 콜백
  @Public()
  @UseGuards(KakaoAuthGuard)
  @Get('kakao/redirect')
  @ApiOperation({ summary: '카카오 로그인 콜백' })
  @ApiOkResponse({
    description: '카카오 로그인 성공',
    schema: {
      example: {
        success: true,
        data: {
          id: '15',
          userId: 'kakao_987654321',
          name: '카카오사용자',
          phone: '',
          createdAt: '2025-10-13T07:00:00.000Z',
          accessToken: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
          refreshToken: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
        },
      },
    },
  })
  async kakaoCallback(@Req() req): Promise<LoginResponseDto> {
    const user = await this.authService.validateKakaoUser(req.user);
    return this.authService.kakaoLogin(user);
  }

  // 로그아웃
  @UseGuards(JwtAuthGuard)
  @Post('logout')
  @HttpCode(200)
  @ApiBearerAuth('access-token')
  @ApiOperation({ summary: '로그아웃' })
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
  async logout(@Req() req, @Body() dto: LogoutDto) {
    await this.authService.logout(req.user.id, dto.refreshToken);
    return { message: '로그아웃 되었습니다.' };
  }
}
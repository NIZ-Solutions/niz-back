import { Controller, Post, Get, Body, UseGuards, Req } from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignupDto } from './dto/signup.dto';
import { LoginDto } from './dto/login.dto';
import { RefreshDto } from './dto/refresh.dto';
import { LogoutDto } from './dto/logout.dto';
import { UserResponseDto } from './dto/user-response.dto';
import { LoginResponseDto } from './dto/login-response.dto';
import { RefreshResponseDto } from './dto/refresh-response.dto';
import { LogoutResponseDto } from './dto/logout-response.dto';
import { ErrorResponseDto } from './dto/error-response.dto';
import { Public } from '../common/decorators/public.decorator';
import { JwtAuthGuard } from './guards/jwt-auth.guard'; 
import { KakaoAuthGuard } from './guards/kakao.guard';
import {
  ApiTags,
  ApiOperation,
  ApiCreatedResponse,
  ApiOkResponse,
  ApiBearerAuth,
  ApiConflictResponse,
  ApiUnauthorizedResponse,
  ApiBadRequestResponse,
} from '@nestjs/swagger';

@ApiTags('Auth')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Public()
  @Post('signup')
  @ApiOperation({ summary: '회원가입' })
  @ApiCreatedResponse({ description: '회원가입 성공', type: UserResponseDto })
  async signup(@Body() dto: SignupDto): Promise<UserResponseDto> {
    return this.authService.signup(dto);
  }

  @Public()
  @Post('login')
  @ApiOperation({ summary: '로그인' })
  @ApiOkResponse({ description: '로그인 성공', type: LoginResponseDto })
  async login(@Body() dto: LoginDto): Promise<LoginResponseDto> {
    return this.authService.login(dto);
  }

  @Public()
  @Post('refresh')
  @ApiOperation({ summary: '토큰 재발급' })
  @ApiOkResponse({ description: '재발급 성공', type: RefreshResponseDto })
  async refresh(@Body() dto: RefreshDto): Promise<RefreshResponseDto> {
    return this.authService.refreshToken(dto.refreshToken);
  }

  @Public()
  @UseGuards(KakaoAuthGuard)
  @Get('kakao/redirect')
  async kakaoCallback(@Req() req): Promise<LoginResponseDto> {
    const user = await this.authService.validateKakaoUser(req.user);
    return this.authService.kakaoLogin(user);
  }

  // 로그아웃
  @UseGuards(JwtAuthGuard)
  @Post('logout')
  @ApiBearerAuth('access-token')
  @ApiOperation({ summary: '로그아웃' })
  @ApiOkResponse({ description: '로그아웃 성공', type: LogoutResponseDto })
  async logout(@Req() req, @Body() dto: LogoutDto) {
    console.log('Logout controller user:', req.user);
    await this.authService.logout(req.user.id, dto.refreshToken);
    return { message: '로그아웃 되었습니다.' };
  }
}
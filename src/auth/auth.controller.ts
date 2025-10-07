import { Controller, Post, Body } from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignupDto } from './dto/signup.dto';
import { LoginDto } from './dto/login.dto';
import { RefreshDto } from './dto/refresh.dto';
import { UserResponseDto } from './dto/user-response.dto';
import { LoginResponseDto } from './dto/login-response.dto';
import { RefreshResponseDto } from './dto/refresh-response.dto';
import {
  ApiTags,
  ApiOperation,
  ApiCreatedResponse,
  ApiOkResponse,
  ApiConflictResponse,
  ApiUnauthorizedResponse,
  ApiBadRequestResponse,
} from '@nestjs/swagger';
import { Public } from 'src/common/decorators/public.decorator';
import { ErrorResponseDto } from './dto/error-response.dto';

@ApiTags('Auth')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  // 회원가입
  @Public()
  @Post('signup')
  @ApiOperation({
    summary: '회원가입',
    description: '아이디, 비밀번호, 이름, 전화번호, 약관 동의(필수/선택)로 회원가입합니다.',
  })
  @ApiCreatedResponse({ description: '회원가입 성공', type: UserResponseDto })
  @ApiBadRequestResponse({ description: '필수 약관 동의 누락', type: ErrorResponseDto })
  @ApiConflictResponse({ description: '이미 존재하는 아이디', type: ErrorResponseDto })
  async signup(@Body() dto: SignupDto): Promise<UserResponseDto> {
    return this.authService.signup(dto);
  }

  // 로그인
  @Public()
  @Post('login')
  @ApiOperation({
    summary: '로그인',
    description: '아이디와 비밀번호로 로그인합니다.',
  })
  @ApiOkResponse({ description: '로그인 성공', type: LoginResponseDto })
  @ApiUnauthorizedResponse({ description: '아이디 또는 비밀번호 불일치', type: ErrorResponseDto })
  async login(@Body() dto: LoginDto): Promise<LoginResponseDto> {
    return this.authService.login(dto);
  }

  // 토큰 재발급
  @Public()
  @Post('refresh')
  @ApiOperation({
    summary: '토큰 재발급',
    description: 'Refresh Token으로 Access Token을 갱신합니다.',
  })
  @ApiOkResponse({ description: '재발급 성공', type: RefreshResponseDto })
  @ApiUnauthorizedResponse({ description: 'Refresh Token 검증 실패', type: ErrorResponseDto })
  async refresh(@Body() dto: RefreshDto): Promise<RefreshResponseDto> {
    return this.authService.refreshToken(dto.refreshToken);
  }
}
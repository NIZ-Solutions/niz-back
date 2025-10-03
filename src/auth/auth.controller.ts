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
} from '@nestjs/swagger';
import { Public } from 'src/common/decorators/public.decorator';
import { BaseResponseDto } from './dto/base-response.dto';
import { ErrorResponseDto } from './dto/error-response.dto';

@ApiTags('Auth')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Public()
  @Post('signup')
  @ApiOperation({ summary: '회원가입', description: '이메일, 비밀번호, 이름, 전화번호로 회원가입' })
  @ApiCreatedResponse({ description: '회원가입 성공', type: BaseResponseDto<UserResponseDto> })
  @ApiConflictResponse({ description: '이미 존재하는 이메일', type: ErrorResponseDto })
  async signup(@Body() dto: SignupDto): Promise<BaseResponseDto<UserResponseDto>> {
    const user = await this.authService.signup(dto);
    return { success: true, data: user };
  }

  @Public()
  @Post('login')
  @ApiOperation({ summary: '로그인', description: '이메일과 비밀번호로 로그인' })
  @ApiOkResponse({ description: '로그인 성공', type: BaseResponseDto<LoginResponseDto> })
  @ApiUnauthorizedResponse({ description: '이메일 또는 비밀번호 불일치', type: ErrorResponseDto })
  async login(@Body() dto: LoginDto): Promise<BaseResponseDto<LoginResponseDto>> {
    const tokens = await this.authService.login(dto);
    return { success: true, data: tokens };
  }

  @Public()
  @Post('refresh')
  @ApiOperation({ summary: '토큰 재발급', description: 'Refresh Token으로 Access Token 갱신' })
  @ApiOkResponse({ description: '재발급 성공', type: BaseResponseDto<RefreshResponseDto> })
  @ApiUnauthorizedResponse({ description: 'Refresh Token 검증 실패', type: ErrorResponseDto })
  async refresh(@Body() dto: RefreshDto): Promise<BaseResponseDto<RefreshResponseDto>> {
    const tokens = await this.authService.refreshToken(dto.refreshToken);
    return { success: true, data: tokens };
  }
}
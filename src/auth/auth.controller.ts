import { Controller, Post, Body } from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignupDto } from './dto/signup.dto';
import { LoginDto } from './dto/login.dto';
import { UserResponseDto } from './dto/user-response.dto';
import { LoginResponseDto } from './dto/login-response.dto';
import { ApiTags, ApiOperation, ApiCreatedResponse, ApiOkResponse, ApiConflictResponse, ApiUnauthorizedResponse } from '@nestjs/swagger';

@ApiTags('Auth')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('signup')
  @ApiOperation({ summary: '회원가입', description: '이메일, 비밀번호, 이름, 전화번호로 회원가입' })
  @ApiCreatedResponse({ description: '회원가입 성공', type: UserResponseDto })
  @ApiConflictResponse({
    description: '이미 존재하는 이메일',
    schema: {
      example: {
        success: false,
        error: {
          code: 409,
          message: '이미 가입된 이메일입니다.',
        },
      },
    },
  })
  async signup(@Body() dto: SignupDto): Promise<UserResponseDto> {
    return this.authService.signup(dto);
  }

  @Post('login')
  @ApiOperation({ summary: '로그인', description: '이메일과 비밀번호로 로그인' })
  @ApiOkResponse({ description: '로그인 성공', type: LoginResponseDto })
  @ApiUnauthorizedResponse({
    description: '이메일 또는 비밀번호 불일치',
    schema: {
      example: {
        success: false,
        error: {
          code: 401,
          message: '이메일 또는 비밀번호가 올바르지 않습니다.',
        },
      },
    },
  })
  async login(@Body() dto: LoginDto): Promise<LoginResponseDto> {
    return this.authService.login(dto);
  }
}
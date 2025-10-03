import { Controller, Post, Body } from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignupDto } from './dto/signup.dto';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';

@ApiTags('Auth')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('signup')
  @ApiOperation({ summary: '회원가입', description: '이메일, 비밀번호, 이름, 전화번호로 회원가입' })
  @ApiResponse({
    status: 201,
    description: '회원가입 성공',
    schema: {
      example: {
        success: true,
        data: {
          userId: 1,
          email: 'user@example.com',
          name: '홍길동',
          phone: '01012345678',
          createdAt: '2025-09-26T12:34:56.000Z',
        },
      },
    },
  })
  @ApiResponse({
    status: 409,
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
  signup(@Body() dto: SignupDto) {
    return this.authService.signup(dto.email, dto.password, dto.name, dto.phone);
  }
}
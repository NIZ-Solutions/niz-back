import { ApiProperty } from '@nestjs/swagger';
import { SignupDto } from './signup.dto';
import { IsNotEmpty } from 'class-validator';

export class AdminSignupDto extends SignupDto {
  @ApiProperty({
    example: 'ADMIN_SECRET_1234',
    description: '관리자 회원가입용 시크릿 코드 (환경변수 ADMIN_SIGNUP_SECRET 과 일치해야 함)',
  })
  @IsNotEmpty()
  adminSecret: string;
}

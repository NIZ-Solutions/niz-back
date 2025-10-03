import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty, Matches, MinLength, MaxLength } from 'class-validator';

export class SignupDto {
  @ApiProperty({ example: 'user@example.com' })
  @IsEmail()
  email: string;

  @ApiProperty({ example: 'P@ssw0rd123' })
  @IsNotEmpty()
  @MinLength(8)
  @MaxLength(64)
  @Matches(/^(?=.*[a-zA-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]).+$/, {
    message: '비밀번호는 최소 8자 이상, 영문/숫자/특수문자를 포함해야 합니다.',
  })
  password: string;

  @ApiProperty({ example: 'P@ssw0rd123' })
  @IsNotEmpty()
  passwordConfirm: string;

  @ApiProperty({ example: '홍길동' })
  @IsNotEmpty()
  name: string;

  @ApiProperty({ example: '01012345678' })
  @IsNotEmpty()
  phone: string;
}
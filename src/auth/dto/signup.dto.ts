import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, Matches, MinLength, MaxLength } from 'class-validator';

export class SignupDto {
  @ApiProperty({ example: 'niz123' })
  @IsNotEmpty()
  @MinLength(4)
  @MaxLength(10)
  @Matches(/^[a-zA-Z0-9]+$/, {
    message: '아이디는 영문과 숫자만 사용할 수 있으며 최대 10자까지 가능합니다.',
  })
  userId: string;

  @ApiProperty({ example: 'password123@' })
  @IsNotEmpty()
  @MinLength(8)
  @MaxLength(16)
  @Matches(/^(?=.*[a-zA-Z])(?=.*[0-9])(?=.*[!@#$%^&*?_]).{8,16}$/, {
    message: '비밀번호는 8~16자, 영문/숫자/특수문자를 모두 포함해야 합니다.',
  })
  password: string;

  @ApiProperty({ example: '홍길동' })
  @IsNotEmpty()
  name: string;

  @ApiProperty({ example: '01012345678' })
  @IsNotEmpty()
  phone: string;
}
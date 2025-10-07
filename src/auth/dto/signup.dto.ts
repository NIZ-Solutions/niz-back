import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, Matches, MinLength, MaxLength, IsBoolean } from 'class-validator';

export class SignupDto {
  @ApiProperty({ example: 'niz123', description: '아이디 (영문+숫자 4~10자)' })
  @IsNotEmpty()
  @MinLength(4)
  @MaxLength(10)
  @Matches(/^[a-zA-Z0-9]+$/, {
    message: '아이디는 영문과 숫자만 사용할 수 있으며 최대 10자까지 가능합니다.',
  })
  userId: string;

  @ApiProperty({ example: 'Password123@', description: '비밀번호 (영문+숫자+특수문자 8~16자)' })
  @IsNotEmpty()
  @MinLength(8)
  @MaxLength(16)
  @Matches(/^(?=.*[a-zA-Z])(?=.*[0-9])(?=.*[!@#$%^&*?_]).{8,16}$/, {
    message: '비밀번호는 8~16자, 영문/숫자/특수문자를 모두 포함해야 합니다.',
  })
  password: string;

  @ApiProperty({ example: '홍길동', description: '이름' })
  @IsNotEmpty()
  name: string;

  @ApiProperty({ example: '01012345678', description: '휴대폰 번호' })
  @IsNotEmpty()
  phone: string;

  // 필수 약관 동의
  @ApiProperty({ example: true, description: '이용약관 동의 (필수)' })
  @IsBoolean()
  termsOfService: boolean;

  @ApiProperty({ example: true, description: '개인정보 수집 및 이용 동의 (필수)' })
  @IsBoolean()
  privacyPolicy: boolean;

  @ApiProperty({ example: true, description: '결제 및 환불 약관 동의 (필수)' })
  @IsBoolean()
  paymentPolicy: boolean;

  // 선택 약관 동의
  @ApiProperty({ example: false, description: '마케팅 정보 수신 동의 (선택)' })
  @IsBoolean()
  marketingOptIn: boolean;
}
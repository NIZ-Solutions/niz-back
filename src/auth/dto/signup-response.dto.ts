import { ApiProperty } from '@nestjs/swagger';

export class SignupResponseDto {
  @ApiProperty({ example: '1', description: '사용자 PK' })
  id: string;

  @ApiProperty({ example: 'niz123', description: '로그인용 사용자 아이디' })
  userId: string;

  @ApiProperty({ example: '홍길동', description: '이름' })
  name: string;

  @ApiProperty({ example: '01012345678', description: '휴대폰 번호' })
  phone: string;

  @ApiProperty({ example: '2025-09-29T15:30:00.000Z', description: '가입일' })
  createdAt: Date;

  @ApiProperty({
    example: 'eyJhbGciOiJIUzI1NiIsInR5cCI...',
    description: '액세스 토큰',
  })
  accessToken: string;

  @ApiProperty({
    example: 'eyJhbGciOiJIUzI1NiIsInR5cCI...',
    description: '리프레시 토큰',
  })
  refreshToken: string;
}
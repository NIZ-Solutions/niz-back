import { ApiProperty } from '@nestjs/swagger';

export class UserResponseDto {
  @ApiProperty({ type: String, description: '사용자 PK' })
  id: string;

  @ApiProperty({ example: 'niz123', description: '로그인용 사용자 아이디' })
  userId: string;

  @ApiProperty({ example: '홍길동' })
  name: string;

  @ApiProperty({ example: '01012345678' })
  phone: string;

  @ApiProperty({ example: '2025-09-29T15:30:00.000Z' })
  createdAt: Date;
}
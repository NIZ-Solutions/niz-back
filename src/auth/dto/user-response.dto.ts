import { ApiProperty } from '@nestjs/swagger';

export class UserResponseDto {
  @ApiProperty({ type: String, description: '사용자 ID (BigInt → string)' })
  id: string;

  @ApiProperty({ example: 'user@example.com' })
  email: string;

  @ApiProperty({ example: '홍길동' })
  name: string;

  @ApiProperty({ example: '01012345678' })
  phone: string;

  @ApiProperty({ example: '2025-09-29T15:30:00.000Z' })
  createdAt: Date;
}
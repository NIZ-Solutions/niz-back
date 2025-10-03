import { ApiProperty } from '@nestjs/swagger';

export class RefreshResponseDto {
  @ApiProperty({ description: '새로 발급된 Access Token' })
  accessToken: string;

  @ApiProperty({ description: '새로 발급된 Refresh Token' })
  refreshToken: string;
}
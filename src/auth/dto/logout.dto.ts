import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty } from 'class-validator';

export class LogoutDto {
  @ApiProperty({ description: '현재 발급된 Refresh Token' })
  @IsNotEmpty()
  refreshToken: string;
}
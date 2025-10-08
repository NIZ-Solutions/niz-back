import { ApiProperty } from '@nestjs/swagger';

export class LogoutResponseDto {
  @ApiProperty({ example: true, description: '성공 여부' })
  success: boolean;

  @ApiProperty({ example: '로그아웃 되었습니다.', description: '결과 메시지' })
  message: string;
}
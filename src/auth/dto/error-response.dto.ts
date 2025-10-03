import { ApiProperty } from '@nestjs/swagger';

export class ErrorResponseDto {
  @ApiProperty({ example: false })
  success: boolean;

  @ApiProperty({
    example: { code: 401, message: 'Unauthorized' },
  })
  error: {
    code: number;
    message: string;
  };
}
import { ApiProperty } from '@nestjs/swagger';

export class ResponseDto<T> {
  @ApiProperty({ example: true })
  success: boolean;

  @ApiProperty({ description: '응답 데이터', required: false })
  data?: T;
}
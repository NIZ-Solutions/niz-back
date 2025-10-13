import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsDateString, IsOptional, IsString } from 'class-validator';

export class CreatePaymentDto {
  @ApiProperty({ example: 'pay_1234567890' })
  @IsNotEmpty()
  paymentId: string;

  @ApiProperty({ example: '홍길동' })
  @IsNotEmpty()
  name: string;

  @ApiProperty({ example: '01012345678' })
  @IsNotEmpty()
  phone: string;

  @ApiProperty({ example: 'user@example.com' })
  @IsNotEmpty()
  email: string;

  @ApiProperty({
    example: '2025-10-20T15:00:00Z',
    description: '예약 일시',
  })
  @IsNotEmpty()
  @IsDateString()
  advicedAt: string;

  @ApiProperty({ example: '추가 요청사항', required: false })
  @IsOptional()
  @IsString()
  otherText?: string;
}
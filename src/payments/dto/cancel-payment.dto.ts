import { ApiProperty } from '@nestjs/swagger';
import { IsString } from 'class-validator';

export class CancelPaymentDto {
  @ApiProperty({
    example: 'pay_1234567890',
    description: '결제 식별자 (PortOne paymentId)',
  })
  @IsString()
  paymentId: string;
}

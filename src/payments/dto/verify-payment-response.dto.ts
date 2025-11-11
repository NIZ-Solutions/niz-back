import { ApiProperty } from '@nestjs/swagger';
import { PaymentResponseDto } from './payment-response.dto';

export class VerifyPaymentResponseDto {
  @ApiProperty({ example: true, description: '결제 성공 여부' })
  success: boolean;

  @ApiProperty({
    description: '결제 상세 정보',
    type: PaymentResponseDto,
  })
  payment: PaymentResponseDto;
}

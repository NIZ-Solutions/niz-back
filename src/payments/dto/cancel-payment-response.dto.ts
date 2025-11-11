import { ApiProperty } from '@nestjs/swagger';
import { PaymentResponseDto } from './payment-response.dto';

export class CancelPaymentResponseDto {
  @ApiProperty({ example: true, description: '결제 취소 성공 여부' })
  success: boolean;

  @ApiProperty({
    description: '취소된 결제 정보',
    type: PaymentResponseDto,
  })
  data: PaymentResponseDto;
}

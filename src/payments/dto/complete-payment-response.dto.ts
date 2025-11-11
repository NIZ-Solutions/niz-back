import { ApiProperty } from '@nestjs/swagger';
import { PaymentResponseDto } from './payment-response.dto';

export class CompletePaymentResponseDto {
  @ApiProperty({ example: true, description: '결제 완료 여부' })
  success: boolean;

  @ApiProperty({
    description: '결제 완료된 결제 정보',
    type: PaymentResponseDto,
  })
  data: PaymentResponseDto;
}

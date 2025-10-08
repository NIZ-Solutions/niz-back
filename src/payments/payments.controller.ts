import { Body, Controller, Post, UseGuards, Req } from '@nestjs/common';
import { PaymentsService } from './payments.service';
import { CreatePaymentDto } from './dto/create-payment.dto';
import { PaymentResponseDto } from './dto/payment-response.dto';
import { ApiOperation, ApiTags, ApiCreatedResponse, ApiBearerAuth } from '@nestjs/swagger';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';

@ApiTags('payments')
@Controller('payments')
export class PaymentsController {
  constructor(private readonly paymentsService: PaymentsService) {}

  @UseGuards(JwtAuthGuard) 
  @ApiBearerAuth('access-token')
  @Post('complete')
  @ApiOperation({ summary: '카드 결제 완료 처리' })
  @ApiCreatedResponse({ description: '결제 완료', type: PaymentResponseDto })
  async complete(
    @Body() dto: CreatePaymentDto,
    @Req() req,
  ): Promise<PaymentResponseDto> {
    console.log('PaymentsController user:', req.user);
    return this.paymentsService.completePayment(dto);
  }
}
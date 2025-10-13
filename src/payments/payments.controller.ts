import { Body, Controller, Post, UseGuards, Req } from '@nestjs/common';
import { PaymentsService } from './payments.service';
import { CreatePaymentDto } from './dto/create-payment.dto';
import { PaymentResponseDto } from './dto/payment-response.dto';
import {
  ApiOperation,
  ApiTags,
  ApiCreatedResponse,
  ApiBearerAuth,
} from '@nestjs/swagger';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';

@ApiTags('Payments')
@Controller('payments')
export class PaymentsController {
  constructor(private readonly paymentsService: PaymentsService) {}

  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('access-token')
  @Post('complete')
  @ApiOperation({ summary: '카드 결제 완료 처리' })
  @ApiCreatedResponse({
    description: '결제 완료',
    schema: {
      example: {
        success: true,
        data: {
          id: '1',
          paymentId: 'pay_1234567890',
          userId: '1',
          amount: 10000,
          status: 'PAID',
          advicedAt: '2025-10-20T15:00:00.000Z',
          name: '홍길동',
          phone: '01012345678',
          email: 'user@example.com',
          otherText: '추가 요청사항입니다.',
          createdAt: '2025-10-07T12:34:56.000Z',
        },
      },
    },
  })
  async complete(
    @Body() dto: CreatePaymentDto,
    @Req() req,
  ): Promise<PaymentResponseDto> {
    const userId = BigInt(req.user.id);
    console.log('PaymentsController user:', req.user);
    return this.paymentsService.completePayment(dto, userId);
  }
}
import {
  Body,
  Controller,
  Post,
  UseGuards,
  Req,
  BadRequestException,
  Logger,
} from '@nestjs/common';
import {
  ApiOperation,
  ApiTags,
  ApiCreatedResponse,
  ApiOkResponse,
  ApiBearerAuth,
} from '@nestjs/swagger';
import { PaymentsService } from './payments.service';
import { CreatePaymentDto } from './dto/create-payment.dto';
import { CancelPaymentDto } from './dto/cancel-payment.dto';
import { PaymentResponseDto } from './dto/payment-response.dto';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';

@ApiTags('Payments')
@Controller('payments')
export class PaymentsController {
  private readonly logger = new Logger(PaymentsController.name);

  constructor(private readonly paymentsService: PaymentsService) {}

  // (1) 결제 완료 (PC 전용 / 로그인 필요)
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('access-token')
  @Post('complete')
  @ApiOperation({ summary: '카드 결제 완료 처리 (PC)' })
  @ApiCreatedResponse({ description: '결제 완료', type: PaymentResponseDto })
  async complete(
    @Body() dto: CreatePaymentDto,
    @Req() req,
  ): Promise<PaymentResponseDto> {
    this.logger.log('결제 완료 요청', { body: dto, user: req.user });

    if (!req.user?.id)
      throw new BadRequestException('인증 정보가 누락되었습니다.');

    let userId: bigint;
    try {
      userId = BigInt(req.user.id);
    } catch {
      throw new BadRequestException('잘못된 사용자 ID 형식입니다.');
    }

    if (!dto?.paymentId)
      throw new BadRequestException('결제 정보가 불완전합니다.');

    try {
      return await this.paymentsService.completePayment(dto, userId);
    } catch (error) {
      this.logger.error('결제 완료 처리 중 오류', error);
      throw error;
    }
  }

  // (2) 결제 검증 (모바일 redirectUrl 전용 / 비로그인)
  @Post('verify')
  @ApiOperation({ summary: '결제 검증 (모바일 리디렉션 대응)' })
  @ApiOkResponse({ description: '결제 검증 결과', type: PaymentResponseDto })
  async verify(@Body() body: { paymentId?: string; imp_uid?: string }) {
    const { paymentId, imp_uid } = body;

    if (!paymentId && !imp_uid)
      throw new BadRequestException('paymentId 또는 imp_uid가 필요합니다.');

    try {
      const targetId = (paymentId || imp_uid) as string;
      const result = await this.paymentsService.verifyPayment(targetId);
      return { success: result.status === 'PAID', payment: result };
    } catch (error) {
      this.logger.error('결제 검증 실패', error);
      throw error;
    }
  }

  // (3) 결제 취소
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('access-token')
  @Post('cancel')
  @ApiOperation({ summary: '결제 취소 처리' })
  @ApiOkResponse({ description: '결제 취소 완료', type: PaymentResponseDto })
  async cancel(@Body() dto: CancelPaymentDto): Promise<PaymentResponseDto> {
    if (!dto.paymentId)
      throw new BadRequestException('paymentId가 필요합니다.');

    try {
      return await this.paymentsService.cancelPayment(dto.paymentId);
    } catch (error) {
      this.logger.error('결제 취소 처리 중 오류', error);
      throw error;
    }
  }

  // (4) 포트원 Webhook
  @Post('webhook')
  @ApiOperation({ summary: '포트원 Webhook 수신 (자동 승인 통보용)' })
  async handleWebhook(@Body() payload: any) {
    this.logger.log('포트원 Webhook 수신', payload);

    try {
      const { imp_uid, merchant_uid, status } = payload;
      if (!imp_uid || !merchant_uid || !status)
        throw new BadRequestException('필수 파라미터가 누락되었습니다.');

      await this.paymentsService.handleWebhook(imp_uid, merchant_uid, status);
      this.logger.log(`Webhook 처리 완료: ${merchant_uid} (${status})`);
      return { success: true };
    } catch (err) {
      this.logger.error('Webhook 처리 실패', err);
      return { success: false, error: err.message };
    }
  }
}

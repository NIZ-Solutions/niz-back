import {
  Body,
  Controller,
  Post,
  UseGuards,
  Req,
  BadRequestException,
  InternalServerErrorException,
  Logger,
} from '@nestjs/common';
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
  private readonly logger = new Logger(PaymentsController.name);

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
    this.logger.log('Payment complete request', {
      body: dto,
      user: req.user,
    });

    // 1. 인증 정보 확인
    if (!req.user || !req.user.id) {
      throw new BadRequestException('인증 정보가 누락되었습니다.');
    }

    // 2. BigInt 변환 방어
    let userId: bigint;
    try {
      userId = BigInt(req.user.id);
    } catch {
      throw new BadRequestException('잘못된 사용자 ID 형식입니다.');
    }

    // 3. 요청 데이터 검증
    if (!dto || !dto.paymentId) {
      throw new BadRequestException('결제 정보가 불완전합니다.');
    }

    // 4. 실제 결제 완료 처리
    try {
      const result = await this.paymentsService.completePayment(dto, userId);
      return result;
    } catch (error) {
      this.logger.error('결제 완료 처리 중 오류 발생', error);
      throw new InternalServerErrorException('결제 처리 중 서버 오류가 발생했습니다.');
    }
  }
}
import {
  Injectable,
  BadRequestException,
  InternalServerErrorException,
  ConflictException,
  Logger,
} from '@nestjs/common';
import { PrismaService } from '../prisma.service';
import { PaymentClient } from '@portone/server-sdk';
import { CreatePaymentDto } from './dto/create-payment.dto';
import { PaymentResponseDto } from './dto/payment-response.dto';

@Injectable()
export class PaymentsService {
  private readonly logger = new Logger(PaymentsService.name);
  private readonly paymentClient: PaymentClient;

  constructor(private prisma: PrismaService) {
    this.paymentClient = PaymentClient({
      secret: process.env.V2_API_SECRET!,
    });
  }

  async completePayment(
    dto: CreatePaymentDto,
    userId: bigint,
  ): Promise<PaymentResponseDto> {
    try {
      // 1. PortOne API 검증
      const payment = await this.paymentClient.getPayment({
        paymentId: dto.paymentId,
      });

      if (!payment) {
        throw new BadRequestException('결제 정보를 불러올 수 없습니다.');
      }

      if (payment.status !== 'PAID') {
        throw new BadRequestException('결제가 완료되지 않았습니다.');
      }

      // 2. DB 저장
      const saved = await this.prisma.payment.create({
        data: {
          paymentId: dto.paymentId,
          amount: payment.amount.total,
          status: payment.status,
          advicedAt: new Date(dto.advicedAt ?? Date.now()),
          name: dto.name,
          phone: dto.phone,
          email: dto.email,
          otherText: dto.otherText ?? null,
          userId,
        },
      });

      // 3. DTO 반환
      return {
        id: saved.id.toString(),
        paymentId: saved.paymentId,
        userId: saved.userId.toString(),
        amount: saved.amount,
        status: saved.status,
        advicedAt: saved.advicedAt,
        name: saved.name,
        phone: saved.phone,
        email: saved.email,
        otherText: saved.otherText ?? undefined,
        createdAt: saved.createdAt,
      };
    } catch (err: any) {
      if (err.data?.type === 'PAYMENT_NOT_FOUND') {
        throw new BadRequestException('결제 건을 찾을 수 없습니다.');
      }

      if (err.code === 'P2002' && err.meta?.target?.includes('paymentId')) {
        throw new ConflictException('이미 처리된 결제입니다.');
      }

      this.logger.error('결제 완료 처리 중 오류', err);
      throw new InternalServerErrorException('결제 처리 중 서버 오류가 발생했습니다.');
    }
  }
}
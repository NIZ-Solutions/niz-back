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

  // 결제 완료 처리
  async completePayment(
    dto: CreatePaymentDto,
    userId: bigint,
  ): Promise<PaymentResponseDto> {
    try {
      const payment = await this.paymentClient.getPayment({
        paymentId: dto.paymentId,
      });

      if (!payment)
        throw new BadRequestException('결제 정보를 불러올 수 없습니다.');
      if (payment.status !== 'PAID')
        throw new BadRequestException('결제가 완료되지 않았습니다.');

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

      return this.formatResponse(saved);
    } catch (err: any) {
      console.error('==== 결제 오류 상세 ====');
      console.error('code:', err?.code);
      console.error('message:', err?.message);
      console.error('meta:', err?.meta);
      console.error('response data:', err?.response?.data);
      console.error('=======================');

      if (err.data?.type === 'PAYMENT_NOT_FOUND')
        throw new BadRequestException('결제 건을 찾을 수 없습니다.');

      if (err.code === 'P2002' && err.meta?.target?.includes('paymentId'))
        throw new ConflictException('이미 처리된 결제입니다.');

      this.logger.error('결제 완료 처리 중 오류', err);
      throw new InternalServerErrorException('결제 처리 중 서버 오류가 발생했습니다.');
    }
  }

  // 결제 취소 처리
  async cancelPayment(paymentId: string): Promise<PaymentResponseDto> {
    try {
      const payment = await this.paymentClient.getPayment({ paymentId });

      if (!payment)
        throw new BadRequestException('결제 정보를 불러올 수 없습니다.');
      if (payment.status !== 'CANCELLED')
        throw new BadRequestException('아직 결제가 취소되지 않았습니다.');

      const updated = await this.prisma.payment.update({
        where: { paymentId },
        data: { status: 'CANCELED' }, // DB 저장은 미국식
      });

      return this.formatResponse(updated);
    } catch (err: any) {
      console.error('==== 결제 취소 오류 상세 ====');
      console.error('code:', err?.code);
      console.error('message:', err?.message);
      console.error('meta:', err?.meta);
      console.error('response data:', err?.response?.data);
      console.error('=======================');

      this.logger.error('결제 취소 처리 중 오류', err);
      throw new InternalServerErrorException('결제 취소 중 서버 오류가 발생했습니다.');
    }
  }

  // 공통 DTO 포맷터
  private formatResponse(p: any): PaymentResponseDto {
    return {
      id: p.id.toString(),
      paymentId: p.paymentId,
      userId: p.userId.toString(),
      amount: p.amount,
      status: p.status,
      advicedAt: p.advicedAt,
      name: p.name,
      phone: p.phone,
      email: p.email,
      otherText: p.otherText ?? undefined,
      createdAt: p.createdAt,
    };
  }
}
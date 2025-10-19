import {
  Injectable,
  BadRequestException,
  InternalServerErrorException,
  ConflictException,
  Logger,
  ServiceUnavailableException,
} from '@nestjs/common';
import { PrismaService } from '../prisma.service';
import { PaymentClient } from '@portone/server-sdk';
import { CreatePaymentDto } from './dto/create-payment.dto';
import { PaymentResponseDto } from './dto/payment-response.dto';
import { Prisma, Payment as PrismaPayment } from '@prisma/client';
import type { Payment as PortonePayment } from '@portone/server-sdk/payment';

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
    const { paymentId } = dto;

    const existing = await this.prisma.payment.findUnique({
      where: { paymentId },
    });
    if (existing) return this.formatResponse(existing);

    let payment: PortonePayment;
    try {
      payment = await this.paymentClient.getPayment({
        paymentId: dto.paymentId,
      });
    } catch {
      throw new ServiceUnavailableException('PAYMENT_PROVIDER_UNAVAILABLE');
    }

    if (!payment)
      throw new BadRequestException('결제 정보를 불러올 수 없습니다.');
    if (payment.status !== 'PAID')
      throw new BadRequestException('결제가 완료되지 않았습니다.');

    const data: Prisma.PaymentUncheckedCreateInput = {
      paymentId: dto.paymentId,
      amount: payment.amount.total,
      status: payment.status,
      advicedAt: new Date(dto.advicedAt ?? Date.now()),
      name: dto.name,
      phone: dto.phone,
      email: dto.email,
      otherText: typeof dto.otherText === 'string' ? dto.otherText : null,
      userId,
    };

    try {
      const saved: PrismaPayment = await this.prisma.payment.create({ data });
      return this.formatResponse(saved);
    } catch (e: unknown) {
      if (
        typeof (e as { code?: unknown }).code === 'string' &&
        (e as { code: string }).code === 'P2002'
      ) {
        const current = await this.prisma.payment.findUnique({
          where: { paymentId },
        });
        if (current) return this.formatResponse(current);
        throw new ConflictException('DUPLICATE_PAYMENT');
      }
      throw e;
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
      throw new InternalServerErrorException(
        '결제 취소 중 서버 오류가 발생했습니다.',
      );
    }
  }

  // 공통 DTO 포맷터
  private formatResponse(p: PrismaPayment): PaymentResponseDto {
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

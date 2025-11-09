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

  // ✅ (1) 결제 완료 처리 (PC)
  async completePayment(
    dto: CreatePaymentDto,
    userId: bigint,
  ): Promise<PaymentResponseDto> {
    try {
      const payment: any = await this.paymentClient.getPayment({
        paymentId: dto.paymentId,
      });

      if (!payment)
        throw new BadRequestException('결제 정보를 불러올 수 없습니다.');
      if (payment.status !== 'PAID')
        throw new BadRequestException('결제가 완료되지 않았습니다.');

      this.logger.log('💳 포트원 결제 응답', {
        paymentId: payment.id,
        orderName: payment.orderName,
        amount: payment.amount?.total,
        status: payment.status,
      });

      const saved = await this.prisma.payment.create({
        data: {
          paymentId: dto.paymentId,
          amount: payment.amount?.total ?? 0,
          status: payment.status,
          advicedAt: new Date(dto.advicedAt ?? Date.now()),
          name: dto.name ?? payment.orderName ?? '미지정',
          phone: dto.phone ?? payment.customer?.phone ?? '',
          email: dto.email ?? payment.customer?.email ?? '',
          otherText: dto.otherText ?? null,
          userId,
        },
      });

      return this.formatResponse(saved);
    } catch (err: any) {
      this.logger.error('❌ 결제 완료 처리 중 오류', err);
      if (err.data?.type === 'PAYMENT_NOT_FOUND')
        throw new BadRequestException('결제 건을 찾을 수 없습니다.');
      if (err.code === 'P2002' && err.meta?.target?.includes('paymentId'))
        throw new ConflictException('이미 처리된 결제입니다.');
      throw new InternalServerErrorException('결제 처리 중 서버 오류가 발생했습니다.');
    }
  }

  // ✅ (2) 결제 검증 (모바일 리디렉션)
  async verifyPayment(paymentId: string): Promise<PaymentResponseDto> {
    try {
      const payment: any = await this.paymentClient.getPayment({ paymentId });

      if (!payment)
        throw new BadRequestException('결제 정보를 불러올 수 없습니다.');

      this.logger.log('🔍 결제 검증 결과', {
        paymentId,
        status: payment.status,
        amount: payment.amount?.total,
      });

      return {
        id: '0',
        paymentId: payment.id,
        userId: payment.customer?.id?.toString() ?? '0',
        amount: payment.amount?.total ?? 0,
        status: payment.status,
        advicedAt: new Date(),
        name: payment.orderName ?? 'NIZ',
        phone: payment.customer?.phone ?? '',
        email: payment.customer?.email ?? '',
        otherText: undefined,
        createdAt: new Date(),
      };
    } catch (err) {
      this.logger.error('❌ 결제 검증 중 오류', err);
      throw new InternalServerErrorException('결제 검증 중 서버 오류가 발생했습니다.');
    }
  }

  // ✅ (3) 결제 취소
  async cancelPayment(paymentId: string): Promise<PaymentResponseDto> {
    try {
      const payment: any = await this.paymentClient.getPayment({ paymentId });

      if (!payment)
        throw new BadRequestException('결제 정보를 불러올 수 없습니다.');
      if (payment.status !== 'CANCELLED')
        throw new BadRequestException('아직 결제가 취소되지 않았습니다.');

      const updated = await this.prisma.payment.update({
        where: { paymentId },
        data: { status: 'CANCELED' },
      });

      return this.formatResponse(updated);
    } catch (err) {
      this.logger.error('❌ 결제 취소 처리 중 오류', err);
      throw new InternalServerErrorException('결제 취소 중 서버 오류가 발생했습니다.');
    }
  }

  // ✅ (4) Webhook 처리
  async handleWebhook(
    impUid: string,
    merchantUid: string,
    status: string,
  ): Promise<void> {
    this.logger.log(
      `Webhook 처리 시작 | imp_uid=${impUid}, merchant_uid=${merchantUid}, status=${status}`,
    );

    try {
      const payment: any = await this.paymentClient.getPayment({ paymentId: impUid });
      if (!payment)
        throw new BadRequestException('포트원 결제 내역을 불러올 수 없습니다.');

      const existing = await this.prisma.payment.findUnique({
        where: { paymentId: impUid },
      });

      if (!existing) {
        await this.prisma.payment.create({
          data: {
            paymentId: impUid,
            amount: payment.amount.total,
            status: payment.status ?? status,
            advicedAt: new Date(),
            name: payment.orderName ?? '미지정',
            phone: payment.customer?.phone ?? '',
            email: payment.customer?.email ?? '',
            otherText: null,
            userId: BigInt(payment.customer?.id ?? 0),
          },
        });
        this.logger.log(`신규 결제 생성 (${impUid})`);
      } else {
        await this.prisma.payment.update({
          where: { paymentId: impUid },
          data: { status: payment.status ?? status },
        });
        this.logger.log(`기존 결제 상태 업데이트 (${impUid})`);
      }
    } catch (err) {
      this.logger.error('❌ Webhook 처리 중 오류', err);
      throw new InternalServerErrorException('Webhook 처리 중 서버 오류가 발생했습니다.');
    }
  }

  // ✅ 공통 응답 DTO 포맷터
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

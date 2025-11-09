import {
  Injectable,
  BadRequestException,
  ConflictException,
  InternalServerErrorException,
  Logger,
  ServiceUnavailableException,
} from '@nestjs/common';
import { PrismaService } from '../prisma.service';
import { PaymentClient } from '@portone/server-sdk';
import { CreatePaymentDto } from './dto/create-payment.dto';
import { PaymentResponseDto } from './dto/payment-response.dto';
import { Prisma, Payment as PrismaPayment } from '@prisma/client';

@Injectable()
export class PaymentsService {
  private readonly logger = new Logger(PaymentsService.name);
  private readonly paymentClient: PaymentClient;

  constructor(private prisma: PrismaService) {
    this.paymentClient = PaymentClient({
      secret: process.env.V2_API_SECRET!,
    });
  }

  // (1) 결제 완료 처리 (PC)
  async completePayment(
    dto: CreatePaymentDto,
    userId: bigint,
  ): Promise<PaymentResponseDto> {
    const { paymentId } = dto;

    // 중복 결제 방지
    const existing = await this.prisma.payment.findUnique({ where: { paymentId } });
    if (existing) return this.formatResponse(existing);

    let payment: any; 
    try {
      payment = (await this.paymentClient.getPayment({ paymentId })) as any;
    } catch {
      throw new ServiceUnavailableException('PAYMENT_PROVIDER_UNAVAILABLE');
    }

    if (!payment)
      throw new BadRequestException('결제 정보를 불러올 수 없습니다.');
    if (payment.status !== 'PAID')
      throw new BadRequestException('결제가 완료되지 않았습니다.');

    const data: Prisma.PaymentUncheckedCreateInput = {
      paymentId,
      amount: payment.amount?.total ?? 0,
      status: payment.status,
      advicedAt: new Date(dto.advicedAt ?? Date.now()),
      name: dto.name ?? payment.orderName ?? '미지정',
      phone: dto.phone ?? payment.customer?.phone ?? '',
      email: dto.email ?? payment.customer?.email ?? '',
      otherText: typeof dto.otherText === 'string' ? dto.otherText : null,
      userId,
    };

    try {
      const saved = await this.prisma.payment.create({ data });
      return this.formatResponse(saved);
    } catch (e: any) {
      if (e.code === 'P2002') {
        const current = await this.prisma.payment.findUnique({ where: { paymentId } });
        if (current) return this.formatResponse(current);
        throw new ConflictException('DUPLICATE_PAYMENT');
      }
      this.logger.error('결제 DB 저장 중 오류', e);
      throw new InternalServerErrorException('DB_WRITE_FAILED');
    }
  }

  // (2) 결제 검증 (모바일 리디렉션)
  async verifyPayment(paymentId: string): Promise<PaymentResponseDto> {
    let payment: any; // 🔸 타입 단언
    try {
      payment = (await this.paymentClient.getPayment({ paymentId })) as any;
    } catch {
      throw new ServiceUnavailableException('PAYMENT_PROVIDER_UNAVAILABLE');
    }

    if (!payment)
      throw new BadRequestException('결제 정보를 불러올 수 없습니다.');

    this.logger.log('결제 검증 결과', {
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
  }

  // (3) 결제 취소
  async cancelPayment(paymentId: string): Promise<PaymentResponseDto> {
    let payment: any;
    try {
      payment = (await this.paymentClient.getPayment({ paymentId })) as any;
    } catch {
      throw new ServiceUnavailableException('PAYMENT_PROVIDER_UNAVAILABLE');
    }

    if (!payment)
      throw new BadRequestException('결제 정보를 불러올 수 없습니다.');
    if (payment.status !== 'CANCELLED')
      throw new BadRequestException('아직 결제가 취소되지 않았습니다.');

    try {
      const updated = await this.prisma.payment.update({
        where: { paymentId },
        data: { status: 'CANCELED' },
      });
      return this.formatResponse(updated);
    } catch (err) {
      this.logger.error('결제 취소 처리 중 오류', err);
      throw new InternalServerErrorException('CANCEL_FAILED');
    }
  }

  // (4) Webhook 처리
  async handleWebhook(
    impUid: string,
    merchantUid: string,
    status: string,
  ): Promise<void> {
    this.logger.log(
      `Webhook 처리 시작 | imp_uid=${impUid}, merchant_uid=${merchantUid}, status=${status}`,
    );

    let payment: any;
    try {
      payment = (await this.paymentClient.getPayment({ paymentId: impUid })) as any;
    } catch {
      throw new ServiceUnavailableException('PAYMENT_PROVIDER_UNAVAILABLE');
    }

    if (!payment)
      throw new BadRequestException('포트원 결제 내역을 불러올 수 없습니다.');

    const existing = await this.prisma.payment.findUnique({
      where: { paymentId: impUid },
    });

    if (!existing) {
      await this.prisma.payment.create({
        data: {
          paymentId: impUid,
          amount: payment.amount?.total ?? 0,
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
  }

  // (5) 공통 DTO 포맷터
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

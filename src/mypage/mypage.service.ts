import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma.service';
import { MypageResponseDto } from './dto/mypage-response.dto';

@Injectable()
export class MypageService {
  constructor(private prisma: PrismaService) {}

  async getUserPayments(userId: bigint): Promise<MypageResponseDto> {
    const payments = await this.prisma.payment.findMany({
      where: { userId },
      orderBy: { createdAt: 'desc' },
    });

    const formatted = payments.map((p) => ({
      paymentId: p.paymentId,
      amount: p.amount,
      status: p.status,
      advicedAt: p.advicedAt,
      name: p.name,
      phone: p.phone,
      email: p.email,
      otherText: p.otherText ?? undefined,
      createdAt: p.createdAt,
    }));

    return { success: true, data: formatted };
  }
}
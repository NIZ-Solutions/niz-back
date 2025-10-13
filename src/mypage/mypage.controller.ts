import { Controller, Get, UseGuards, Req } from '@nestjs/common';
import { MypageService } from './mypage.service';
import {
  ApiOperation,
  ApiTags,
  ApiOkResponse,
  ApiBearerAuth,
} from '@nestjs/swagger';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';

@ApiTags('Mypage')
@Controller('mypage')
export class MypageController {
  constructor(private readonly mypageService: MypageService) {}

  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('access-token')
  @Get()
  @ApiOperation({ summary: '결제 목록 조회' })
  @ApiOkResponse({
    description: '결제 내역 목록',
    schema: {
      example: {
        success: true,
        data: [
          {
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
          {
            id: '2',
            paymentId: 'pay_9876543210',
            userId: '1',
            amount: 20000,
            status: 'PAID',
            advicedAt: '2025-10-22T15:00:00.000Z',
            name: '홍길동',
            phone: '01012345678',
            email: 'user@example.com',
            otherText: null,
            createdAt: '2025-10-08T12:34:56.000Z',
          },
        ],
      },
    },
  })
  async getMyPayments(@Req() req) {
    const userId = req.user?.id;
    const result = await this.mypageService.getUserPayments(userId);
    return result.data;
  }
}
import { Controller, Get, Query, UseGuards } from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiOkResponse,
  ApiOperation,
  ApiQuery,
  ApiTags,
} from '@nestjs/swagger';
import { PaymentsService } from '../payments/payments.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { Roles } from '../common/decorators/roles.decorator';

@ApiTags('Admin Payments')
@ApiBearerAuth('access-token')
@Controller('admin/payments')
@UseGuards(JwtAuthGuard)
export class AdminPaymentsController {
  constructor(private readonly paymentsService: PaymentsService) {}

  @Get()
  @Roles('ADMIN')
  @ApiOperation({ summary: '관리자 - 전체 결제 내역 조회' })
  @ApiOkResponse({
    description: '결제 내역 목록 (관리자용)',
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
        ],
        meta: {
          page: 1,
          limit: 20,
          total: 1,
          totalPages: 1,
        },
      },
    },
  })
  @ApiQuery({ name: 'userId', required: false, description: '특정 유저 ID 필터' })
  @ApiQuery({
    name: 'status',
    required: false,
    description: '결제 상태 (PAID, CANCELLED 등)',
  })
  @ApiQuery({ name: 'page', required: false, example: 1 })
  @ApiQuery({ name: 'limit', required: false, example: 20 })
  async getAllPayments(
    @Query('userId') userId?: string,
    @Query('status') status?: string,
    @Query('page') page = '1',
    @Query('limit') limit = '20',
  ) {
    return this.paymentsService.getPaymentsForAdmin({
      userId,
      status,
      page: Number(page),
      limit: Number(limit),
    });
  }
}

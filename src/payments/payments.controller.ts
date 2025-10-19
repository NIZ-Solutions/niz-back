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
import { CancelPaymentDto } from './dto/cancel-payment.dto';
import { PaymentResponseDto } from './dto/payment-response.dto';
import {
  ApiOperation,
  ApiTags,
  ApiCreatedResponse,
  ApiOkResponse,
  ApiBearerAuth,
} from '@nestjs/swagger';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';

@ApiTags('Payments')
@Controller('payments')
export class PaymentsController {
  private readonly logger = new Logger(PaymentsController.name);

  constructor(private readonly paymentsService: PaymentsService) {}

  // 결제 완료
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('access-token')
  @Post('complete')
  @ApiOperation({ summary: '카드 결제 완료 처리' })
  @ApiCreatedResponse({
    description: '결제 완료',
    type: PaymentResponseDto,
  })
  async complete(
    @Body() dto: CreatePaymentDto,
    @Req() req,
  ): Promise<PaymentResponseDto> {
    this.logger.log('Payment complete request', { body: dto, user: req.user });

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

    // try {
    //   return await this.paymentsService.completePayment(dto, userId);
    // } catch (error) {
    //   this.logger.error('결제 완료 처리 중 오류 발생', error);
    //   throw new InternalServerErrorException('결제 처리 중 서버 오류가 발생했습니다.');
    // }

    // 위에있는 catch가 오류를 단순한 500으로 내뱉게끔 하고 있어서 
    // 이렇게 수정해주시면 감사하겠습니다.
    // 결제 취소도 추후에 테스트후에 그냥 return문으로 수정해주세요.
    return this.paymentsService.completePayment(dto, userId);
  }

  // 결제 취소
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('access-token')
  @Post('cancel')
  @ApiOperation({ summary: '결제 취소 처리' })
  @ApiOkResponse({
    description: '결제 취소 완료',
    type: PaymentResponseDto,
  })
  async cancel(@Body() dto: CancelPaymentDto): Promise<PaymentResponseDto> {
    if (!dto.paymentId)
      throw new BadRequestException('paymentId가 필요합니다.');

    // ex.
    // return this.paymentsService.cancelPayment(dto.paymentId);
    try {
      return await this.paymentsService.cancelPayment(dto.paymentId);
    } catch (error) {
      this.logger.error('결제 취소 처리 중 오류 발생', error);
      throw new InternalServerErrorException('결제 취소 중 서버 오류가 발생했습니다.');
    }
  }
}

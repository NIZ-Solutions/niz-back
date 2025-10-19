import { ApiProperty } from '@nestjs/swagger';

export class PaymentResponseDto {
  @ApiProperty({ description: '결제 고유 ID', example: '1' })
  id: string;

  @ApiProperty({ description: 'PortOne 결제 ID', example: 'pay_1234567890' })
  paymentId: string;

  @ApiProperty({ description: '회원 ID', example: 1 })
  userId: string;

  @ApiProperty({ description: '결제 금액', example: 10000 })
  amount: number;

  @ApiProperty({ description: '결제 상태', example: 'PAID' })
  status: string;

  @ApiProperty({
    description: '예약 일시',
    example: '2025-10-20T15:00:00.000Z',
  })
  advicedAt: Date;

  @ApiProperty({ description: '구매자 이름', example: '홍길동' })
  name: string;

  @ApiProperty({ description: '구매자 전화번호', example: '01012345678' })
  phone: string;

  @ApiProperty({ description: '구매자 이메일', example: 'user@example.com' })
  email: string;

  @ApiProperty({
    description: '추가 요청사항',
    example: '추가 요청사항입니다.',
    required: false,
  })
  otherText?: string;

  @ApiProperty({ description: '생성일시', example: '2025-10-07T12:34:56.000Z' })
  createdAt: Date;
}

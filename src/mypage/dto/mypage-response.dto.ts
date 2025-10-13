import { ApiProperty } from '@nestjs/swagger';

export class MypagePaymentDto {
  @ApiProperty({ example: 'pay_1234567890', description: '결제 고유 ID' })
  paymentId: string;

  @ApiProperty({ example: 10000, description: '결제 금액' })
  amount: number;

  @ApiProperty({ example: 'PAID', description: '결제 상태' })
  status: string;

  @ApiProperty({ example: '2025-10-20T15:00:00.000Z', description: '상담 예약 일시' })
  advicedAt: Date;

  @ApiProperty({ example: '홍길동', description: '결제자 이름' })
  name: string;

  @ApiProperty({ example: '01012345678', description: '결제자 전화번호' })
  phone: string;

  @ApiProperty({ example: 'user@example.com', description: '결제자 이메일', required: false })
  email?: string;

  @ApiProperty({ example: '추가 요청사항입니다.', required: false })
  otherText?: string | null;

  @ApiProperty({ example: '2025-10-07T12:34:56.000Z', description: '결제 생성 일시' })
  createdAt: Date;
}

export class MypageResponseDto {
  @ApiProperty({ example: true, description: '성공 여부' })
  success: boolean;

  @ApiProperty({
    type: [MypagePaymentDto],
    description: '사용자의 결제 내역 목록',
  })
  data: MypagePaymentDto[];
}
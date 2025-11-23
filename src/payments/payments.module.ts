import { Module } from '@nestjs/common';
import { PaymentsService } from './payments.service';
import { PaymentsController } from './payments.controller';
import { PrismaService } from '../prisma.service';
import { AdminPaymentsController } from '../admin/admin-payments.controller';

@Module({
  controllers: [PaymentsController, AdminPaymentsController],
  providers: [PaymentsService, PrismaService],
})
export class PaymentsModule {}
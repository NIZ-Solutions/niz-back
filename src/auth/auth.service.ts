import { Injectable, ConflictException } from '@nestjs/common';
import { PrismaService } from '../prisma.service';
import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService) {}

  async signup(email: string, password: string, name: string, phone: string) {
    // 이메일 중복 체크
    const existing = await this.prisma.user.findUnique({ where: { email } });
    if (existing) {
      throw new ConflictException('이미 가입된 이메일입니다.');
    }

    // 비밀번호 해시
    const passwordHash = await bcrypt.hash(password, 10);

    try {
      const user = await this.prisma.user.create({
        data: {
          email,
          passwordHash,
          name,
          phone,
        },
      });

      return {
        userId: user.id,
        email: user.email,
        name: user.name,
        phone: user.phone,
        createdAt: user.createdAt,
      };
    } catch (err) {
      console.error('Prisma Error:', err);
      throw err;
    }
  }
}
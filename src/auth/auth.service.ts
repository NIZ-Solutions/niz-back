import { Injectable, ConflictException, UnauthorizedException } from '@nestjs/common';
import { PrismaService } from '../prisma.service';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { SignupDto } from './dto/signup.dto';
import { LoginDto } from './dto/login.dto';
import { UserResponseDto } from './dto/user-response.dto';
import { LoginResponseDto } from './dto/login-response.dto';
import { RefreshResponseDto } from './dto/refresh-response.dto';
import * as crypto from 'crypto';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
  ) {}

  async signup(dto: SignupDto): Promise<UserResponseDto> {
    try {
        const passwordHash = await bcrypt.hash(dto.password, 10);

        const user = await this.prisma.user.create({
        data: {
            userId: dto.userId,
            passwordHash,
            name: dto.name,
            phone: dto.phone,
        },
        });

        return {
        id: user.id.toString(),
        userId: user.userId,
        name: user.name,
        phone: user.phone,
        createdAt: user.createdAt,
        };
    } catch (err: any) {
        if (err.code === 'P2002' && err.meta?.target?.includes('userId')) {
        throw new ConflictException('이미 존재하는 아이디입니다.');
        }
        throw err;
    }
   }

  async login(dto: LoginDto): Promise<LoginResponseDto> {
    const user = await this.prisma.user.findUnique({
      where: { userId: dto.userId },
    });
    if (!user) {
      throw new UnauthorizedException('아이디 또는 비밀번호가 올바르지 않습니다.');
    }

    const isPasswordValid = await bcrypt.compare(dto.password, user.passwordHash);
    if (!isPasswordValid) {
      throw new UnauthorizedException('아이디 또는 비밀번호가 올바르지 않습니다.');
    }
      // 토큰 발급
    const payload = { sub: user.id.toString(), userId: user.userId };
    const accessToken = await this.jwtService.signAsync(payload, { expiresIn: '1h' });
    const refreshToken = await this.jwtService.signAsync(payload, { expiresIn: '7d' });

    // Refresh Token 저장 (hash로 DB에 보관)
    const tokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

    await this.prisma.refreshToken.create({
      data: {
        userId: user.id,
        tokenHash,
        expiresAt,
      },
    });

    const userResponse: UserResponseDto = {
      id: user.id.toString(),
      userId: user.userId,
      name: user.name,
      phone: user.phone,
      createdAt: user.createdAt,
    };

    return { user: userResponse, accessToken, refreshToken };
  }

  async refreshToken(token: string): Promise<RefreshResponseDto> {
    try {
      const payload = await this.jwtService.verifyAsync(token, {
        secret: process.env.JWT_SECRET,
      });
      const userId = BigInt(payload.sub);

      // refreshToken hash 검증
      const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
      const stored = await this.prisma.refreshToken.findFirst({
        where: { userId, tokenHash, revoked: false },
      });
      if (!stored || stored.expiresAt < new Date()) {
        throw new UnauthorizedException('유효하지 않은 Refresh Token입니다.');
      }

      // 새 토큰 발급
      const newPayload = { sub: userId.toString(), userId: payload.userId };
      const newAccessToken = await this.jwtService.signAsync(newPayload, {
        expiresIn: '1h',
      });
      const newRefreshToken = await this.jwtService.signAsync(newPayload, {
        expiresIn: '7d',
      });

      // 기존 토큰 revoke
      await this.prisma.refreshToken.update({
        where: { id: stored.id },
        data: { revoked: true },
      });

      // 새 토큰 저장
      const newTokenHash = crypto.createHash('sha256').update(newRefreshToken).digest('hex');
      const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
      await this.prisma.refreshToken.create({
        data: {
          userId,
          tokenHash: newTokenHash,
          expiresAt,
        },
      });

      return { accessToken: newAccessToken, refreshToken: newRefreshToken };
    } catch {
      throw new UnauthorizedException('Refresh Token 검증 실패');
    }
  }
}
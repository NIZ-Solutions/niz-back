import {
  Injectable,
  BadRequestException,
  ConflictException,
  UnauthorizedException,
  Logger,
} from '@nestjs/common';
import { PrismaService } from '../prisma.service';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { SignupDto } from './dto/signup.dto';
import { LoginDto } from './dto/login.dto';
import { SignupResponseDto } from './dto/signup-response.dto';
import { LoginResponseDto } from './dto/login-response.dto';
import { RefreshResponseDto } from './dto/refresh-response.dto';
import { LogoutResponseDto } from './dto/logout-response.dto';
import * as crypto from 'crypto';
import { HttpService } from '@nestjs/axios';
import { firstValueFrom } from 'rxjs';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
    private readonly httpService: HttpService,
  ) {}

  // 회원가입
  async signup(dto: SignupDto): Promise<SignupResponseDto> {
    if (!dto.privacyPolicy || !dto.termsOfService || !dto.paymentPolicy) {
      throw new BadRequestException('필수 약관에 모두 동의해야 회원가입이 가능합니다.');
    }

    const passwordHash = await bcrypt.hash(dto.password, 10);
    const user = await this.prisma.user.create({
      data: {
        userId: dto.userId,
        passwordHash,
        name: dto.name,
        phone: dto.phone,
        privacyPolicy: dto.privacyPolicy,
        termsOfService: dto.termsOfService,
        paymentPolicy: dto.paymentPolicy,
      },
    });

    return this.issueLoginTokens(user);
  }

  // 로그인
  async login(dto: LoginDto): Promise<LoginResponseDto> {
    const user = await this.prisma.user.findUnique({ where: { userId: dto.userId } });
    if (!user) throw new BadRequestException('아이디가 올바르지 않습니다.');
    if (!user.passwordHash)
      throw new BadRequestException('비밀번호 로그인 불가 계정입니다.');

    const valid = await bcrypt.compare(dto.password, user.passwordHash);
    if (!valid) throw new BadRequestException('비밀번호가 올바르지 않습니다.');

    return this.issueLoginTokens(user);
  }

  // Refresh Token 재발급
  async refreshToken(token: string): Promise<RefreshResponseDto> {
    try {
      const payload = await this.jwtService.verifyAsync(token, {
        secret: process.env.JWT_SECRET,
      });

      const userId = BigInt(payload.sub);
      const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
      const stored = await this.prisma.refreshToken.findFirst({
        where: { userId, tokenHash, revoked: false },
      });

      if (!stored) throw new UnauthorizedException('INVALID');
      if (stored.expiresAt < new Date()) {
        await this.prisma.refreshToken.update({
          where: { id: stored.id },
          data: { revoked: true },
        });
        throw new UnauthorizedException('EXPIRED');
      }

      await this.prisma.refreshToken.update({
        where: { id: stored.id },
        data: { revoked: true },
      });

      const user = await this.prisma.user.findUnique({ where: { id: userId } });
      if (!user) throw new UnauthorizedException('USER_NOT_FOUND');

      return this.issueRefreshTokens(user);
    } catch (err: any) {
      if (err.name === 'TokenExpiredError') {
        throw new UnauthorizedException('EXPIRED');
      }
      if (err.name === 'JsonWebTokenError') {
        throw new UnauthorizedException('INVALID');
      }
      if (err instanceof UnauthorizedException) throw err;
      throw new UnauthorizedException('UNKNOWN');
    }
  }

  // 로그아웃
  async logout(userId: string, refreshToken: string): Promise<LogoutResponseDto> {
    const tokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');
    await this.prisma.refreshToken.updateMany({
      where: { userId: BigInt(userId), tokenHash, revoked: false },
      data: { revoked: true },
    });
    return { success: true, message: '로그아웃 되었습니다.' };
  }

  // ===== 내부 =====
  private async issueLoginTokens(user: any): Promise<LoginResponseDto> {
    const payload = { sub: user.id.toString(), userId: user.userId };

    // 👇 테스트용 짧은 만료시간
    const accessToken = await this.jwtService.signAsync(payload, { expiresIn: '30s' });
    const refreshToken = await this.jwtService.signAsync(payload, { expiresIn: '2m' });

    await this.saveRefreshToken(user.id, refreshToken);
    return {
      id: user.id.toString(),
      userId: user.userId,
      name: user.name,
      phone: user.phone,
      createdAt: user.createdAt,
      accessToken,
      refreshToken,
    };
  }

  private async issueRefreshTokens(user: any): Promise<RefreshResponseDto> {
    const payload = { sub: user.id.toString(), userId: user.userId };
    const accessToken = await this.jwtService.signAsync(payload, { expiresIn: '30s' });
    const refreshToken = await this.jwtService.signAsync(payload, { expiresIn: '2m' });

    await this.saveRefreshToken(user.id, refreshToken);
    return { accessToken, refreshToken };
  }

  private async saveRefreshToken(userId: bigint, refreshToken: string) {
    const tokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');
    const expiresAt = new Date(Date.now() + 2 * 60 * 1000); // 2분

    await this.prisma.refreshToken.updateMany({
      where: { userId, revoked: false },
      data: { revoked: true },
    });

    await this.prisma.refreshToken.create({
      data: { userId, tokenHash, expiresAt },
    });
  }
}
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

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
  ) {}

  // 회원가입 (토큰 포함)
  async signup(dto: SignupDto): Promise<SignupResponseDto> {
    if (!dto.privacyPolicy) {
      throw new BadRequestException('필수 약관에 모두 동의해야 회원가입이 가능합니다.');
    }

    try {
      const passwordHash = await bcrypt.hash(dto.password, 10);

      const user = await this.prisma.user.create({
        data: {
          userId: dto.userId,
          passwordHash,
          name: dto.name,
          phone: dto.phone,
          privacyPolicy: dto.privacyPolicy,
        },
      });

      const payload = { sub: user.id.toString(), userId: user.userId };
      const accessToken = await this.jwtService.signAsync(payload, { expiresIn: '1h' });
      const refreshToken = await this.jwtService.signAsync(payload, { expiresIn: '7d' });
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
    } catch (err: any) {
      if (err.code === 'P2002' && err.meta?.target?.includes('userId')) {
        throw new ConflictException('이미 존재하는 아이디입니다.');
      }
      this.logger.error('회원가입 중 오류 발생', err);
      throw err;
    }
  }

  // 로그인
  async login(dto: LoginDto): Promise<LoginResponseDto> {
    const user = await this.prisma.user.findUnique({ where: { userId: dto.userId } });
    if (!user) throw new UnauthorizedException('아이디가 올바르지 않습니다.');
    if (!user.passwordHash)
      throw new UnauthorizedException('비밀번호 로그인 불가 계정입니다.');

    const isPasswordValid = await bcrypt.compare(dto.password, user.passwordHash);
    if (!isPasswordValid) throw new UnauthorizedException('비밀번호가 올바르지 않습니다.');

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
      if (!stored || stored.expiresAt < new Date()) {
        throw new UnauthorizedException('유효하지 않은 Refresh Token입니다.');
      }

      await this.prisma.refreshToken.update({
        where: { id: stored.id },
        data: { revoked: true },
      });

      const user = await this.prisma.user.findUnique({ where: { id: userId } });
      if (!user) throw new UnauthorizedException('사용자를 찾을 수 없습니다.');

      return this.issueRefreshTokens(user);
    } catch (err) {
      this.logger.error('Refresh Token 검증 실패', err);
      throw new UnauthorizedException('Refresh Token 검증 실패');
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

  // 내부 공통 메서드
  private async issueLoginTokens(user: any): Promise<LoginResponseDto> {
    const payload = { sub: user.id.toString(), userId: user.userId };
    const accessToken = await this.jwtService.signAsync(payload, { expiresIn: '1h' });
    const refreshToken = await this.jwtService.signAsync(payload, { expiresIn: '7d' });

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
    const accessToken = await this.jwtService.signAsync(payload, { expiresIn: '1h' });
    const refreshToken = await this.jwtService.signAsync(payload, { expiresIn: '7d' });

    await this.saveRefreshToken(user.id, refreshToken);

    return { accessToken, refreshToken };
  }

  private async saveRefreshToken(userId: bigint, refreshToken: string) {
    const tokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

    await this.prisma.refreshToken.updateMany({
      where: { userId, revoked: false },
      data: { revoked: true },
    });

    await this.prisma.refreshToken.create({
      data: { userId, tokenHash, expiresAt },
    });
  }
}
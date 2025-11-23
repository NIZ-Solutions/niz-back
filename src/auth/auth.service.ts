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
import { Role } from '@prisma/client';

interface KakaoTokenResponse {
  access_token: string;
}

interface KakaoUserResponse {
  id: number;
  kakao_account: {
    profile: {
      nickname: string;
    };
    email?: string;
  };
}

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
    private readonly httpService: HttpService,
  ) {}

  // ======================
  // 일반 회원가입
  // ======================
  async signup(dto: SignupDto): Promise<SignupResponseDto> {
    if (!dto.privacyPolicy || !dto.termsOfService || !dto.paymentPolicy) {
      throw new BadRequestException('필수 약관 동의가 필요합니다.');
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
          termsOfService: dto.termsOfService,
          paymentPolicy: dto.paymentPolicy,
          role: Role.USER, // 기본 유저
        },
      });

      return this.issueLoginTokens(user);
    } catch (err: any) {
      if (err.code === 'P2002') {
        throw new ConflictException('이미 존재하는 아이디입니다.');
      }
      this.logger.error('회원가입 중 오류 발생', err);
      throw err;
    }
  }

  // ======================
  // 일반 로그인
  // ======================
  async login(dto: LoginDto): Promise<LoginResponseDto> {
    const user = await this.prisma.user.findUnique({
      where: { userId: dto.userId },
    });

    if (!user) throw new UnauthorizedException('아이디가 올바르지 않습니다.');
    if (!user.passwordHash)
      throw new UnauthorizedException('비밀번호 로그인 불가 계정입니다.');

    const isPasswordValid = await bcrypt.compare(
      dto.password,
      user.passwordHash,
    );
    if (!isPasswordValid)
      throw new UnauthorizedException('비밀번호가 올바르지 않습니다.');

    return this.issueLoginTokens(user);
  }

  // ======================
  // 관리자 로그인 (role = ADMIN 필수)
  // ======================
  async adminLogin(dto: LoginDto): Promise<LoginResponseDto> {
    const user = await this.prisma.user.findUnique({
      where: { userId: dto.userId },
    });

    if (!user || user.role !== Role.ADMIN) {
      throw new UnauthorizedException(
        '관리자 계정이 아니거나 아이디가 올바르지 않습니다.',
      );
    }

    if (!user.passwordHash)
      throw new UnauthorizedException('비밀번호 로그인 불가 계정입니다.');

    const isPasswordValid = await bcrypt.compare(
      dto.password,
      user.passwordHash,
    );
    if (!isPasswordValid)
      throw new UnauthorizedException('비밀번호가 올바르지 않습니다.');

    return this.issueLoginTokens(user);
  }

  // ======================
  // 카카오 로그인
  // ======================
  async kakaoLoginByCode(code: string): Promise<LoginResponseDto> {
    try {
      const tokenRes = await firstValueFrom(
        this.httpService.post<KakaoTokenResponse>(
          'https://kauth.kakao.com/oauth/token',
          new URLSearchParams({
            grant_type: 'authorization_code',
            client_id: process.env.KAKAO_CLIENT_ID!,
            redirect_uri: process.env.KAKAO_REDIRECT_URI!,
            code,
            client_secret: process.env.KAKAO_CLIENT_SECRET!,
          }),
          { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } },
        ),
      );

      const accessToken = tokenRes.data.access_token;

      const userRes = await firstValueFrom(
        this.httpService.get<KakaoUserResponse>(
          'https://kapi.kakao.com/v2/user/me',
          { headers: { Authorization: `Bearer ${accessToken}` } },
        ),
      );

      const kakaoId = String(userRes.data.id);
      const kakaoProfile = userRes.data.kakao_account?.profile;

      const existingAuth = await this.prisma.userAuth.findUnique({
        where: { providerId: kakaoId },
        include: { user: true },
      });

      let user;
      if (existingAuth) {
        user = existingAuth.user;
      } else {
        const existingUser = await this.prisma.user.findUnique({
          where: { userId: `kakao_${kakaoId}` },
        });

        if (existingUser) {
          user = existingUser;
        } else {
          user = await this.prisma.user.create({
            data: {
              userId: `kakao_${kakaoId}`,
              name: kakaoProfile?.nickname ?? '카카오사용자',
              phone: '',
              privacyPolicy: true,
              termsOfService: true,
              paymentPolicy: true,
              role: Role.USER,
              auths: {
                create: {
                  provider: 'kakao',
                  providerId: kakaoId,
                },
              },
            },
          });
        }
      }

      return this.issueLoginTokens(user);
    } catch (error) {
      this.logger.error('카카오 로그인 실패', error);
      throw new UnauthorizedException(
        '카카오 로그인 처리 중 오류가 발생했습니다.',
      );
    }
  }

  // ======================
  // 토큰 재발급
  // ======================
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

      if (!stored || stored.expiresAt < new Date())
        throw new UnauthorizedException('유효하지 않은 Refresh Token입니다.');

      await this.prisma.refreshToken.update({
        where: { id: stored.id },
        data: { revoked: true },
      });

      const user = await this.prisma.user.findUnique({ where: { id: userId } });
      if (!user) throw new UnauthorizedException('사용자를 찾을 수 없습니다.');

      return this.issueRefreshTokens(user);
    } catch (err: any) {
      if (err.name === 'TokenExpiredError')
        throw new UnauthorizedException('Refresh Token이 만료되었습니다.');
      throw new UnauthorizedException('유효하지 않은 Refresh Token입니다.');
    }
  }

  // ======================
  // 로그아웃
  // ======================
  async logout(
    userId: string,
    refreshToken: string,
  ): Promise<LogoutResponseDto> {
    const tokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');
    await this.prisma.refreshToken.updateMany({
      where: { userId: BigInt(userId), tokenHash, revoked: false },
      data: { revoked: true },
    });
    return { success: true, message: '로그아웃 되었습니다.' };
  }

  // ======================
  // 토큰 발급 (role 포함)
  // ======================
  private async issueLoginTokens(user: any): Promise<LoginResponseDto> {
    const payload = {
      sub: user.id.toString(),
      userId: user.userId,
      role: user.role,
    };
    const accessToken = await this.jwtService.signAsync(payload, {
      expiresIn: '1h',
    });
    const refreshToken = await this.jwtService.signAsync(payload, {
      expiresIn: '7d',
    });
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
    const payload = {
      sub: user.id.toString(),
      userId: user.userId,
      role: user.role,
    };
    const accessToken = await this.jwtService.signAsync(payload, {
      expiresIn: '1h',
    });
    const refreshToken = await this.jwtService.signAsync(payload, {
      expiresIn: '7d',
    });
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
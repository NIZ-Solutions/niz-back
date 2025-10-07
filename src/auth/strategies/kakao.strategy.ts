import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-kakao';

@Injectable()
export class KakaoStrategy extends PassportStrategy(Strategy, 'kakao') {
  constructor() {
    super({
      clientID: process.env.KAKAO_CLIENT_ID,
      clientSecret: process.env.KAKAO_CLIENT_SECRET,
      callbackURL: process.env.KAKAO_REDIRECT_URI,
    });
  }

  async validate(accessToken: string, refreshToken: string, profile: any) {
    const idStr = String(profile.id);
    const nickname =
      profile.username ??
      profile.displayName ??
      profile._json?.properties?.nickname ??
      null;

    return {
      provider: 'kakao',
      providerId: idStr,        
      nickname,                  
      email: profile._json?.kakao_account?.email ?? null,
    };
  }
}
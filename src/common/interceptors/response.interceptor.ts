import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { map } from 'rxjs/operators';

@Injectable()
export class ResponseInterceptor implements NestInterceptor {
  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    return next.handle().pipe(
      map((data) => {
        // 1) 이미 success가 있으면, 한 번 감싼 응답으로 보고 그대로 반환
        if (data && typeof data === 'object' && 'success' in data) {
          return data;
        }

        // 2) items + meta 형식이면 → 리스트 응답으로 간주
        if (
          data &&
          typeof data === 'object' &&
          'items' in data &&
          'meta' in data
        ) {
          const { items, meta, ...rest } = data as any;
          return {
            success: true,
            data: items,
            meta,
            ...rest,
          };
        }

        // 3) 그 외엔 기본 패턴 → { success, data }
        return {
          success: true,
          data,
        };
      }),
    );
  }
}

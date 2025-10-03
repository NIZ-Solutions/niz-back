import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
  HttpStatus,
} from '@nestjs/common';

@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
  catch(exception: unknown, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse();

    let status = HttpStatus.INTERNAL_SERVER_ERROR;
    let message = 'Internal server error';

    // HttpException 처리
    if (exception instanceof HttpException) {
      status = exception.getStatus();
      const res = exception.getResponse();

      if (typeof res === 'string') {
        message = res;
      } else if (res && typeof res === 'object') {
        const msg: any = (res as any).message;
        if (msg) {
          message = Array.isArray(msg) ? msg[0] : msg;
        }
      }
    }

    // 예외 로그 찍기
    else {
      console.error('Non-HttpException caught:', exception);
    }

    response.status(status).json({
      success: false,
      error: {
        code: status,   //숫자 상태 코드
        message,
      },
    });
  }
}
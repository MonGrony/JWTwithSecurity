package study.jwt.common.security.exception.errorcode;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import study.jwt.common.exception.errorcode.ErrorCode;

@Getter
@RequiredArgsConstructor
public enum SecurityErrorCode implements ErrorCode {
    INVALID_JWT_SIGNATURE(HttpStatus.BAD_REQUEST, "유효하지 않는 토큰입니다."),
    EXPIRED_JWT_TOKEN(HttpStatus.BAD_REQUEST, "만료된 토큰입니다."),
    NOT_FOUND_TOKEN(HttpStatus.BAD_REQUEST, "토큰을 찾을 수 없습니다."),
    RESIGN_USER(HttpStatus.BAD_REQUEST, "탈퇴한 유저입니다."),
    MISMATCH_TOKEN(HttpStatus.BAD_REQUEST, "토큰 정보 불일치입니다."),
    AUTH_USER_FORBIDDEN(HttpStatus.FORBIDDEN, "접근 권한이 없습니다.")
    ;

    private final HttpStatus httpStatus;
    private final String message;
}

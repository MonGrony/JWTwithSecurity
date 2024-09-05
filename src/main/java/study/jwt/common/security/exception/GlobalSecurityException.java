package study.jwt.common.security.exception;

import study.jwt.common.exception.errorcode.ErrorCode;

public interface GlobalSecurityException {

    ErrorCode getErrorCode();

    String getMessage();
}

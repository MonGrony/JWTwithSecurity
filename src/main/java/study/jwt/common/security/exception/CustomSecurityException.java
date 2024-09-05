package study.jwt.common.security.exception;

import lombok.Getter;
import study.jwt.common.exception.errorcode.ErrorCode;

@Getter
public class CustomSecurityException extends RuntimeException implements GlobalSecurityException {
    private final ErrorCode errorCode;
    private final String errorMessage;

    public CustomSecurityException(ErrorCode errorCode) {
        super(errorCode.getMessage());
        this.errorCode = errorCode;
        this.errorMessage = errorCode.getMessage();
    }

    public CustomSecurityException(ErrorCode errorCode, String errorMessage) {
        super(errorMessage);
        this.errorCode = errorCode;
        this.errorMessage = errorMessage;
    }
}

package study.jwt.common.exception.customexception.universalcustomexception;

import lombok.Getter;
import study.jwt.common.exception.errorcode.ErrorCode;

@Getter
public class CustomNotFoundException extends RuntimeException{

    private final ErrorCode errorCode;

    public CustomNotFoundException(ErrorCode errorCode) {
        super(errorCode.getMessage());
        this.errorCode = errorCode;
    }
}

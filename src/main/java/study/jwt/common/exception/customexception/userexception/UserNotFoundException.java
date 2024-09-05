package study.jwt.common.exception.customexception.userexception;

import study.jwt.common.exception.customexception.universalcustomexception.CustomNotFoundException;
import study.jwt.common.exception.errorcode.ErrorCode;

public class UserNotFoundException extends CustomNotFoundException {
    public UserNotFoundException(ErrorCode errorCode) {
        super(errorCode);
    }
}

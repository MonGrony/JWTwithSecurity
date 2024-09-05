package study.jwt.common.exception.customexception.userexception;

import study.jwt.common.exception.customexception.universalcustomexception.CustomNotFoundException;
import study.jwt.common.exception.errorcode.ErrorCode;

public class UserDuplicatedException extends CustomNotFoundException {
    public UserDuplicatedException(ErrorCode errorCode) {
        super(errorCode);
    }
}

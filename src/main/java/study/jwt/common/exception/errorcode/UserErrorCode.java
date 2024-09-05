package study.jwt.common.exception.errorcode;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;

@Getter
@RequiredArgsConstructor
public enum UserErrorCode implements ErrorCode {

    //auth
    NOT_USER(HttpStatus.NOT_FOUND, "회원가입후 이용해주세요."),
    NOT_AUTH_USER(HttpStatus.NOT_FOUND, "로그인후 이용해주세요."),
    DUPLICATED_USER(HttpStatus.BAD_REQUEST, "중복등록되어 있습니다."),
    ;

    private final HttpStatus httpStatus;
    private final String message;


}

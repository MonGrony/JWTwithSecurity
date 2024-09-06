package study.jwt.common.exception.errorResponse;

import lombok.Getter;
import org.springframework.http.HttpStatus;
import study.jwt.common.exception.errorcode.ErrorCode;
import study.jwt.common.response.RestApiResponse;

@Getter
public class ErrorResponse<T> extends RestApiResponse {

    protected ErrorResponse(boolean success, HttpStatus code, String message) {
        super(success, code, message, null);
    }

    protected ErrorResponse(boolean success, HttpStatus code, String message, T data) {
        super(success, code, message, data);
    }

    public static <T> ErrorResponse of(ErrorCode errorCode) {
        return new ErrorResponse<>(false,
                errorCode.getHttpStatus(),
                errorCode.getMessage());
    }

    public static <T> ErrorResponse of(ErrorCode errorCode, T data) {
        return new ErrorResponse<>(false,
                errorCode.getHttpStatus(),
                errorCode.getMessage(),
                data);
    }

}

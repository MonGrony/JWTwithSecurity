package study.jwt.common.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public class RestApiResponse<T> {

    private final boolean success;
    private final HttpStatus code;
    private final String message;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    private final T data;

    protected RestApiResponse(boolean success, HttpStatus code, String message, T data) {
        this.success = success;
        this.code = code;
        this.message = message;
        this.data = data;
    }

    public static <T> RestApiResponse<T> of(HttpStatus code, String message) {
        return new RestApiResponse<>(true, code, message, null);
    }

    public static <T> RestApiResponse<T> of(HttpStatus code, String message, T data) {
        return new RestApiResponse<>(true, code, message, data);
    }
    public static <T> RestApiResponse<T> of(String message) {
        return new RestApiResponse<>(true, HttpStatus.OK, message, null);
    }

}

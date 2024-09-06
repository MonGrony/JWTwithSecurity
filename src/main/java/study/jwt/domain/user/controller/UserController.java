package study.jwt.domain.user.controller;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import study.jwt.common.response.RestApiResponse;
import study.jwt.domain.user.dto.SignupRequestDto;
import study.jwt.domain.user.service.UserService;

import static org.springframework.http.HttpStatus.CREATED;
import static study.jwt.common.management.AppManagement.VERSION;

@RestController
@RequiredArgsConstructor
@RequestMapping(VERSION)
public class UserController {

    private final UserService userService;

    /**
     * 회원가입
     *
     * @param requestDto
     * @return
     */
    @PostMapping("/signup")
    public ResponseEntity<RestApiResponse<?>> Signup(@Valid @RequestBody SignupRequestDto requestDto
    ) {
        userService.Signup(requestDto);

        return ResponseEntity.status(CREATED).body(RestApiResponse.of("회원가입에 성공했습니다."));
    }

    /**
     * 로그인 실패시
     *
     * @param error
     * @param exception
     * @param model
     * @return url
     */
    @GetMapping("/login")
    public String loginForm(@RequestParam(value = "error", required = false) String error,
                            @RequestParam(value = "exception", required = false) String exception, Model model) {
        model.addAttribute("error", error);
        model.addAttribute("exception", exception);

        return VERSION + "/login";
    }
}

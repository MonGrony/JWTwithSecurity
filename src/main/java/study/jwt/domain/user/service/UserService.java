package study.jwt.domain.user.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import study.jwt.common.exception.customexception.userexception.UserDuplicatedException;
import study.jwt.domain.user.dto.SignupRequestDto;
import study.jwt.domain.user.entity.User;
import study.jwt.domain.user.repository.UserRepository;

import static study.jwt.common.exception.errorcode.UserErrorCode.DUPLICATED_USER;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public void Signup(SignupRequestDto requestDto) {

        checkDuplicateUsername(requestDto.getUsername());
        User userData = User.saveUser(requestDto);
        userRepository.save(userData);
    }

    private void checkDuplicateUsername(String username) {
        userRepository.findByUsername(username).ifPresent(u -> {
                    throw new UserDuplicatedException(DUPLICATED_USER);
                }
        );
    }


}

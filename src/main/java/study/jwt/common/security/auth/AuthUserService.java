package study.jwt.common.security.auth;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;
import study.jwt.common.exception.customexception.userexception.UserNotFoundException;
import study.jwt.domain.user.entity.User;

@Service
@RequiredArgsConstructor
public class AuthUserService implements UserDetailsService {

    private final AuthenticatedUserRepository repository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UserNotFoundException {
        User user = repository.findByUsername(username);
        return new AuthenticatedUser(user);
    }
}

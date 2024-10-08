package study.jwt.domain.user.entity;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum UserRoleType {

    USER("ROLE_USER"),
    ADMIN("ROLE_ADMIN");

    private final String userRoleName;

}

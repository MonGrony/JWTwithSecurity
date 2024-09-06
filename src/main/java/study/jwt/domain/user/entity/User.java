package study.jwt.domain.user.entity;

import jakarta.persistence.*;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import study.jwt.domain.base.BaseTime;
import study.jwt.domain.user.dto.SignupRequestDto;

@Entity
@Getter
@NoArgsConstructor
public class User extends BaseTime {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "user_id")
    private Long id;

    @Column(nullable = false, unique = true)
    private String username; //로그인용

    @Column(nullable = false)
    private String password;

    @Column(nullable = false, length = 20)
    private String nickname;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private UserRoleType userRoleName;

    @Column(columnDefinition = "TEXT")
    private String refreshToken;

    @Builder
    public User(Long id, String username, String password, String nickname, UserRoleType userRoleName, String refreshToken) {
        this.id = id;
        this.username = username;
        this.password = password;
        this.nickname = nickname;
        this.userRoleName = userRoleName;
        this.refreshToken = refreshToken;
    }

    public static User saveUser(SignupRequestDto requestDto) {
        return User.builder()
                .username(requestDto.getUsername())
                .nickname(requestDto.getNickname())
                .userRoleName(UserRoleType.USER)
                .build();
    }

    public void updateRefreshToken(String newRefreshToken) {
        this.refreshToken = newRefreshToken;
    }

    //마지막 접속 날짜 필요할 듯
}

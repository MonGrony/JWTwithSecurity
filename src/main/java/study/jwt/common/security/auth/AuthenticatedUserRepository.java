package study.jwt.common.security.auth;

import jakarta.persistence.EntityManager;
import jakarta.persistence.NoResultException;
import jakarta.persistence.NonUniqueResultException;
import jakarta.persistence.TypedQuery;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;
import study.jwt.common.exception.customexception.userexception.UserDuplicatedException;
import study.jwt.common.exception.customexception.userexception.UserNotFoundException;
import study.jwt.domain.user.entity.User;

import static study.jwt.common.exception.errorcode.UserErrorCode.DUPLICATED_USER;
import static study.jwt.common.exception.errorcode.UserErrorCode.NOT_AUTH_USER;

@Repository
@RequiredArgsConstructor
public class AuthenticatedUserRepository {

    private final EntityManager em;

    public void saveUser(User user){
        em.persist(user);
    }

    public User findByUsername(String username) {
        TypedQuery<User> query = em.createQuery("select m from User as m where m.username = ?1", User.class)
                .setParameter(1, username);
        try {
            return query.getSingleResult();
        } catch (NoResultException e) {
            throw new UserNotFoundException(NOT_AUTH_USER);
        } catch (NonUniqueResultException e) {
            throw new UserDuplicatedException(DUPLICATED_USER);
        }
    }
}

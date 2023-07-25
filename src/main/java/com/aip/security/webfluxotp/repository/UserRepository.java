package com.aip.security.webfluxotp.repository;

import com.aip.security.webfluxotp.domain.document.User;
import org.springframework.data.mongodb.repository.ReactiveMongoRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;

/**
 * Spring Data MongoDB repository for the {@link User} entity.
 */
@Repository
public interface UserRepository extends ReactiveMongoRepository<User, String> {

    Mono<User> findOneByEmailIgnoreCase(String email);
    Mono<User> findOneByUsernameIgnoreCase(String login);

}

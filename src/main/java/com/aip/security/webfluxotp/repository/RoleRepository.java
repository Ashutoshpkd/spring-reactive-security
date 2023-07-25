package com.aip.security.webfluxotp.repository;

import com.aip.security.webfluxotp.domain.document.Role;
import org.springframework.data.mongodb.repository.ReactiveMongoRepository;
import reactor.core.publisher.Mono;

/**
 * Spring Data MongoDB repository for the {@link Role} entity.
 */
public interface RoleRepository extends ReactiveMongoRepository<Role, String> {
    Mono<Role> findByName(String roleName);
}

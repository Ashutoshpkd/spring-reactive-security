package com.aip.security.webfluxotp.service;

import com.aip.security.webfluxotp.common.exception.RoleAlreadyUsedException;
import com.aip.security.webfluxotp.domain.document.Role;
import com.aip.security.webfluxotp.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * Service class for managing roles.
 */
@Slf4j
@RequiredArgsConstructor
@Service
public class RoleServiceImpl implements RoleService {

    private final RoleRepository roleRepository;

    @Override
    public Mono<Role> createRole(String roleName) {

        return roleRepository.findByName(roleName)
                .flatMap(existingRole -> Mono.error(new RoleAlreadyUsedException()))
                .cast(Role.class)
                .switchIfEmpty(Mono.defer(() -> roleRepository.save(Role.builder().name(roleName).build())));
    }


    @Override
    public Mono<Role> getRoleByName(String roleName) {
        return roleRepository.findByName(roleName)
                .switchIfEmpty(Mono.error(new ResponseStatusException(HttpStatus.NOT_FOUND,
                        String.format("Unable to find Role. Role with ID: '%s' Not Found.", roleName))));
    }

    @Override
    public Flux<Role> getAllRoles() {
        return roleRepository.findAll()
                .switchIfEmpty(Mono.error(new ResponseStatusException(HttpStatus.NO_CONTENT, "There aren't any roles in DB.")));
    }

}

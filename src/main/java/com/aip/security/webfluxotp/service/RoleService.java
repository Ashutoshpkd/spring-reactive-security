package com.aip.security.webfluxotp.service;

import com.aip.security.webfluxotp.domain.document.Role;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

public interface RoleService {

    Mono<Role> createRole(String roleName);

    Mono<Role> getRoleByName(String roleName);

    Flux<Role> getAllRoles();
}

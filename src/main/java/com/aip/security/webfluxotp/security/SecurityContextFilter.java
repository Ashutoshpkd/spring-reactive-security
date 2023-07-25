package com.aip.security.webfluxotp.security;

import com.aip.security.webfluxotp.common.AppConstant;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.Optional;


/**
 * Filters incoming requests and installs a Spring Security principal if a header corresponding to a valid user is
 * found.
 */
@Slf4j
public class SecurityContextFilter implements WebFilter {

    private TokenProvider tokenProvider;

    public SecurityContextFilter(TokenProvider tokenProvider) {
        this.tokenProvider = tokenProvider;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        Optional<String> jwt = resolveToken(exchange.getRequest());
        if (jwt.isPresent() && tokenProvider.validateToken(jwt.get())) {
            Authentication authentication = tokenProvider.getAuthentication(jwt.get());
//            authentication.setAuthenticated(true);
            LOGGER.info("Authentication object before setting in SecurityContextHolder: {}", authentication);
            SecurityContext securityContext = new SecurityContextImpl(authentication);
            LOGGER.info("Authentication object before setting in SecurityContextHolder: {}", securityContext);
            return chain.filter(exchange)
                    .subscriberContext(ReactiveSecurityContextHolder
                            .withSecurityContext(Mono.just(securityContext)));
        }
        return chain.filter(exchange);
    }

    private Optional<String> resolveToken(ServerHttpRequest request) {
        String bearerToken = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(AppConstant.TOKEN_PREFIX)) {
            return Optional.of(bearerToken.substring(7));
        }
        return Optional.empty();
    }

}

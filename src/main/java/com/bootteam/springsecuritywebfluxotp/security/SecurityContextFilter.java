package com.bootteam.springsecuritywebfluxotp.security;

import com.bootteam.springsecuritywebfluxotp.common.AppConstant;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
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
@RequiredArgsConstructor
@Slf4j
public class SecurityContextFilter implements WebFilter {

    private final TokenProvider tokenProvider;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        Optional<String> jwt = resolveToken(exchange.getRequest());
        if (jwt.isPresent() && tokenProvider.validateToken(jwt.get())) {
            Authentication authentication = tokenProvider.getAuthentication(jwt.get());
//            authentication.setAuthenticated(true);
            LOGGER.info("Authentication object before setting in SecurityContextHolder: {}", authentication);
            SecurityContextHolder.getContext().setAuthentication(authentication);
            ReactiveSecurityContextHolder.getContext().contextWrite(ctx -> {
                SecurityContext sc = ctx.get(SecurityContext.class);
                sc.setAuthentication(authentication);
                return ctx;
            });
            chain.filter(exchange)
                    .contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication));
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

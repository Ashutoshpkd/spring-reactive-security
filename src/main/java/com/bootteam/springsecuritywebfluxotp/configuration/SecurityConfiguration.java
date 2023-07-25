package com.bootteam.springsecuritywebfluxotp.configuration;

import com.bootteam.springsecuritywebfluxotp.common.exception.CustomAccessDeniedHandler;
import com.bootteam.springsecuritywebfluxotp.common.exception.CustomAuthenticationEntryPoint;
import com.bootteam.springsecuritywebfluxotp.security.SecurityContextFilter;
import com.bootteam.springsecuritywebfluxotp.security.TokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UserDetailsRepositoryReactiveAuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.security.web.server.util.matcher.NegatedServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.OrServerWebExchangeMatcher;

import static org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers.pathMatchers;

@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {

    private final String[] permitAllPatterns = new String[] {"/api/user/login","/api/user/register"};
    private final ReactiveUserDetailsService userDetailsService;
    private final TokenProvider tokenProvider;
    private final CustomAccessDeniedHandler accessDeniedHandler;
    private final CustomAuthenticationEntryPoint authenticationEntryPoint;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public ReactiveAuthenticationManager reactiveAuthenticationManager() {
        UserDetailsRepositoryReactiveAuthenticationManager authenticationManager
                = new UserDetailsRepositoryReactiveAuthenticationManager (
                userDetailsService
        );
        authenticationManager.setPasswordEncoder(passwordEncoder());
        return authenticationManager;
    }

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        return http
                .securityMatcher(new NegatedServerWebExchangeMatcher(new OrServerWebExchangeMatcher(
                        pathMatchers("/webjars/**","/app/**", "/i18n/**", "/content/**", "/swagger-ui/**", "/v3/api-docs/**", "/test/**"),
                        pathMatchers(HttpMethod.OPTIONS, "/**")
                )))
                .addFilterAt(new SecurityContextFilter(tokenProvider), SecurityWebFiltersOrder.AUTHENTICATION)
                .authenticationManager(reactiveAuthenticationManager())
                .authorizeExchange()
                .pathMatchers(permitAllPatterns).permitAll()
                .pathMatchers("/api/user/**").authenticated()
                .and()
                .exceptionHandling()
                .authenticationEntryPoint(authenticationEntryPoint)
                .accessDeniedHandler(accessDeniedHandler)
                .and()
                .csrf().disable()
                .httpBasic(httpBasicSpec -> httpBasicSpec.disable())
                .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
                .build();
    }
}

package com.bootteam.springsecuritywebfluxotp.security;

import com.bootteam.springsecuritywebfluxotp.common.AppConstant;
import com.bootteam.springsecuritywebfluxotp.common.DateUtils;
import io.jsonwebtoken.*;
import io.jsonwebtoken.jackson.io.JacksonSerializer;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;


@Slf4j
@Component
public class TokenProvider {

    private final Key key;
    private final JwtParser jwtParser;

    public TokenProvider() {
        key = Keys.hmacShaKeyFor(AppConstant.TOKEN_SECRET.getBytes(StandardCharsets.UTF_8));
        jwtParser = Jwts.parserBuilder().setSigningKey(key).build();
    }

    public String generateToken(Authentication authentication, boolean isTempToken) {
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority).collect(Collectors.joining(","));

        LOGGER.info("Authorities for the user: {}, authorities: {}", authentication.getName(), authorities);

        long now = (DateUtils.convertFromLocalDateToDate()).getTime();
        Date validity = new Date(now + (isTempToken ? AppConstant.TOKEN_TEMP_VALIDITY_TIME : AppConstant.TOKEN_VALIDITY_TIME));
        return Jwts
                .builder()
                .setSubject(authentication.getName())
                .claim(AppConstant.AUTHORITIES_KEY, isTempToken ? "PRE_AUTH" : authorities)
                .setId(UUID.randomUUID().toString())
                .signWith(key, SignatureAlgorithm.HS512)
                .setExpiration(validity)
                .setIssuedAt(Date.from(Instant.now()))
                .serializeToJsonWith(new JacksonSerializer())
                .compact();
    }

    public Authentication getAuthentication(String token) {
        Claims claims = jwtParser.parseClaimsJws(token).getBody();
        LOGGER.info("Claims in getAuthentication: {}", claims);
        List<? extends GrantedAuthority> authorities = Arrays
            .stream(claims.get(AppConstant.AUTHORITIES_KEY).toString().split(","))
            .filter(auth -> !auth.trim().isEmpty())
            .map(SimpleGrantedAuthority::new)
            .toList();

        LOGGER.info("Authorities in getAuthentication: {}", authorities);

        User principal = new User(claims.getSubject(), "", authorities);
        LOGGER.info("Principal user in GetAuth: {}", principal);

        Authentication authentication
                = new UsernamePasswordAuthenticationToken(principal, token, authorities);
//        authentication.setAuthenticated(true);
        return authentication;
    }

    public boolean validateToken(String authToken) {
        try {
            var claims = jwtParser.parseClaimsJws(authToken);
            LOGGER.info("Claims for current user -> {}", claims);
            return true;
        } catch (ExpiredJwtException | SignatureException | MalformedJwtException | UnsupportedJwtException e) {
            LOGGER.error("Invalid JWT token: {}", e.getMessage());
            throw e;
        } catch (IllegalArgumentException e) {
            LOGGER.error("Token validation error {}", e.getMessage());
            throw e;
        }
    }

    public Mono<Authentication> getCurrentUserAuthentication() {
        return ReactiveSecurityContextHolder
                .getContext()
                .map(SecurityContext::getAuthentication);
    }

}

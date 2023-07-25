package com.aip.security.webfluxotp.service;

import com.aip.security.webfluxotp.domain.document.User;
import com.aip.security.webfluxotp.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.hibernate.validator.internal.constraintvalidators.hv.EmailValidator;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.text.MessageFormat;

@Slf4j
@RequiredArgsConstructor
@Component("userDetailsService")
public class UserDetailsService implements ReactiveUserDetailsService {
    private final AccountStatusUserDetailsChecker detailsChecker = new AccountStatusUserDetailsChecker();
    private final UserRepository userRepository;

    @Override
    public Mono<UserDetails> findByUsername(final String login) {
        LOGGER.info("Authenticating with {}", login);
        String username = StringUtils.trimToNull(login.toLowerCase());

        if (new EmailValidator().isValid(username, null)) {
            return userRepository
                    .findOneByEmailIgnoreCase(username)
                    .switchIfEmpty(Mono.error(new UsernameNotFoundException(MessageFormat.format("User with email {0} was not found.", username))))
                    .map(this::getUserDetails);
        }
        return userRepository
                .findOneByUsernameIgnoreCase(username)
                .switchIfEmpty(Mono.error(new UsernameNotFoundException(MessageFormat.format("User {0} was not found", username))))
                .map(this::getUserDetails);
    }


    private UserDetails getUserDetails(User user) {
        detailsChecker.check(user);
        return user;
    }

}

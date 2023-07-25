package com.bootteam.springsecuritywebfluxotp.service;

import com.bootteam.springsecuritywebfluxotp.common.DateUtils;
import com.bootteam.springsecuritywebfluxotp.common.exception.EmailAlreadyUsedException;
import com.bootteam.springsecuritywebfluxotp.common.exception.OtpCheckingException;
import com.bootteam.springsecuritywebfluxotp.common.exception.UsernameAlreadyUsedException;
import com.bootteam.springsecuritywebfluxotp.domain.document.User;
import com.bootteam.springsecuritywebfluxotp.domain.model.OtpChannel;
import com.bootteam.springsecuritywebfluxotp.domain.model.OtpRequest;
import com.bootteam.springsecuritywebfluxotp.repository.RoleRepository;
import com.bootteam.springsecuritywebfluxotp.repository.UserRepository;
import com.bootteam.springsecuritywebfluxotp.security.TokenProvider;
import com.bootteam.springsecuritywebfluxotp.service.mapper.UserMapper;
import com.bootteam.springsecuritywebfluxotp.service.mapper.dto.OtpTokenDTO;
import com.bootteam.springsecuritywebfluxotp.service.mapper.dto.UserPasswordDTO;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.StringUtils;
import org.hibernate.validator.internal.constraintvalidators.hv.EmailValidator;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import javax.validation.constraints.NotNull;

@Slf4j
@RequiredArgsConstructor
@Service
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final RoleRepository roleRepository;
    private final TokenProvider tokenProvider;
    private final UserMapper mapper;
    private final OTPMailService otpMailService;

    @Override
    public Mono<String> checkCode(String authenticationName, @NotNull String code) {

        Mono<User> userMono = getUserMono(authenticationName);

        return userMono.flatMap(u -> {
                    if(code.equals(u.getOtpRequest().getCode())){
                        if (DateUtils.getLocalDateTimeNow().isAfter(u.getOtpRequest().getTime())){
                            return  Mono.error(new OtpCheckingException("Otp code expired"));
                        }
                    }else {
                        return Mono.error(new OtpCheckingException("OTP code not valid"));
                    }
                    return setOtpRequest(u, true);
                }).flatMap(u -> tokenProvider.getCurrentUserAuthentication())
                .flatMap(t -> Mono.just(tokenProvider.generateToken(t, false)));
    }

    @Override
    public Mono<OtpTokenDTO> resendCode(String authenticationName) {

        Mono<User> userMono = getUserMono(authenticationName);

        return userMono.flatMap(user ->
                        setOtpRequest(user, false))
                .zipWhen(u ->
                        tokenProvider
                                .getCurrentUserAuthentication()
                                .flatMap(authentication ->
                                        Mono.just(tokenProvider
                                                .generateToken(authentication, true))))
                .flatMap(t -> Mono.just(new OtpTokenDTO(t.getT2(), t.getT1()))).doOnSuccess(t -> sendOtp(t.user()));
    }

    @Override
    public Mono<User> createUser(UserPasswordDTO userPasswordDTO) {

        return userRepository.findOneByUsernameIgnoreCase(userPasswordDTO.getUsername().toLowerCase())
                .flatMap(existingUser -> Mono.error(new UsernameAlreadyUsedException()))
                .cast(User.class)

                .switchIfEmpty(Mono.defer(() -> userRepository.findOneByEmailIgnoreCase(userPasswordDTO.getEmail()))
                        .flatMap(existingUser -> Mono.error(new EmailAlreadyUsedException()))
                        .cast(User.class)

                        .switchIfEmpty(Mono.defer(() -> {

                                   // check and add roles
                                    userPasswordDTO.getRoles().forEach(r -> roleRepository.findByName(r.getName())
                                            .switchIfEmpty(Mono.defer(() -> roleRepository.save(r))));

                                    userPasswordDTO.setUsername(userPasswordDTO.getUsername().toLowerCase());
                                    User newUser = mapper.userPasswordDTOToUser(userPasswordDTO);

                                    String encryptedPassword = passwordEncoder.encode(userPasswordDTO.getPassword());
                                    newUser.setPassword(encryptedPassword);
                                    return userRepository.save(newUser);
                                })
                        )
                );
    }

    @Override
    public Mono<OtpTokenDTO> setUserOtp(Authentication authentication) {
        LOGGER.info("Authentication: {}", authentication.toString());
        Mono<User> userMono = getUserMono(authentication.getName());

        return userMono.flatMap(user -> setOtpRequest(user, false))
                .zipWhen(token -> Mono.just(tokenProvider.generateToken(authentication, true)))
               .flatMap(t -> Mono.just(new OtpTokenDTO(t.getT2(), t.getT1())));
    }

    private void sendOtp(User user){
        LOGGER.info("send code {} to user {}, User: {}", user.getOtpRequest().getCode(), user.getEmail(), user);
        otpMailService.sendLoginOTPEmail(user);
    }

    private Mono<User> setOtpRequest(User user, boolean erase) {
        OtpRequest otpRequest = (erase) ? new OtpRequest() : new OtpRequest(RandomStringUtils.randomAlphanumeric(4), DateUtils.getLocalDateTimeNow().plusMinutes(10), OtpChannel.EMAIL);
        user.setOtpRequest(otpRequest);
        return userRepository.save(user);
    }

    private Mono<User> getUserMono(String authenticationName) {
        String username = StringUtils.trimToNull(authenticationName.toLowerCase());
        return (new EmailValidator().isValid(username, null)) ? userRepository.findOneByEmailIgnoreCase(username)
                : userRepository.findOneByUsernameIgnoreCase(username);
    }
}

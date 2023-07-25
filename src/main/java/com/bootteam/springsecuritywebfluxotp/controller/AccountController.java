package com.bootteam.springsecuritywebfluxotp.controller;

import com.bootteam.springsecuritywebfluxotp.common.exception.ValidatorException;
import com.bootteam.springsecuritywebfluxotp.service.UserService;
import com.bootteam.springsecuritywebfluxotp.service.mapper.dto.ApiResponseDTO;
import com.bootteam.springsecuritywebfluxotp.service.mapper.dto.LoginDTO;
import com.bootteam.springsecuritywebfluxotp.service.mapper.dto.UserPasswordDTO;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;
import javax.validation.ConstraintViolation;
import javax.validation.Valid;
import javax.validation.Validator;
import java.security.Principal;

@RestController
@RequestMapping("/api/user")
@RequiredArgsConstructor
public class AccountController {
    private final Logger LOG = LoggerFactory.getLogger(AccountController.class);
    private final UserService userService;
    private final Validator validator;
    private final ReactiveAuthenticationManager authenticationManager;

    @PreAuthorize("hasRole('ROLE_USER') AND hasRole('ROLE_ADMIN')")
    @PostMapping("/authenticate")
    public Mono<ApiResponseDTO> isAuthenticated(Principal principal) {
        return Mono.just(new ApiResponseDTO(principal.getName(), "Current user is authenticated"));
    }

    @PostMapping(value = "/register", produces = MediaType.APPLICATION_JSON_VALUE)
    public Mono<ApiResponseDTO> register(@RequestBody @Valid UserPasswordDTO userPasswordDTO) {
        return Mono.just(userPasswordDTO)
                .filter(user -> validator.validate(userPasswordDTO).isEmpty())
                .switchIfEmpty(Mono.error(new ValidatorException(validator.validate(userPasswordDTO).stream().map(ConstraintViolation::getMessage).toList().toString())))
                .flatMap(userService::createUser)
                .map(savedUser -> new ApiResponseDTO(savedUser, "User created successfully"));
    }

    @PostMapping(value = "/login", produces = MediaType.APPLICATION_JSON_VALUE)
    public Mono<ApiResponseDTO> login(@RequestBody @Valid LoginDTO loginDTO) {
        return Mono.just(loginDTO)
                .filter(login -> validator.validate(loginDTO).isEmpty())
                .switchIfEmpty(Mono.error(new ValidatorException(validator.validate(loginDTO).stream().map(ConstraintViolation::getMessage).toList().toString())))
                .flatMap(login ->
                        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(login.getUsername(), login.getPassword()))
                                .flatMap(userService::setUserOtp)
                )
                .map(jwt -> new ApiResponseDTO(jwt.token(), "Partially successful user login - an OTP code has been sent to your email address"));
    }

    @PreAuthorize("hasRole('PRE_AUTH')")
    @GetMapping("/otp/{code}")
    public Mono<ApiResponseDTO> optCheckCode(@PathVariable String code, Principal principal) {
        LOG.info("Request is in the optCheckCode controller - code: {}, principal: ", code, principal);
        return userService.checkCode(principal.getName(), code)
                .map(token -> new ApiResponseDTO(token, "Otp checking success"));
    }

    @PreAuthorize("hasRole('PRE_AUTH')")
    @PostMapping("/resend/code")
    public Mono<ApiResponseDTO> optResendCode(Principal principal) {
        LOG.info("Request is in the controller - {}", principal);
        return userService.resendCode(principal.getName())
                .map(token -> new ApiResponseDTO(token, "Otp checking success"));
    }
}

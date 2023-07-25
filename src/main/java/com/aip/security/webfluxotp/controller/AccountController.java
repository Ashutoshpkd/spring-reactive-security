package com.aip.security.webfluxotp.controller;

import com.aip.security.webfluxotp.common.exception.ValidatorException;
import com.aip.security.webfluxotp.service.UserService;
import com.aip.security.webfluxotp.service.ValidateAuthorityService;
import com.aip.security.webfluxotp.service.mapper.dto.ApiResponseDTO;
import com.aip.security.webfluxotp.service.mapper.dto.LoginDTO;
import com.aip.security.webfluxotp.service.mapper.dto.UserPasswordDTO;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;
import javax.validation.ConstraintViolation;
import javax.validation.Valid;
import javax.validation.Validator;
import java.security.Principal;
import java.util.HashSet;
import java.util.Set;

@RestController
@RequestMapping("/api/user")
@RequiredArgsConstructor
public class AccountController {

    private final UserService userService;
    private final Validator validator;
    private final ReactiveAuthenticationManager authenticationManager;
    private final ValidateAuthorityService validateAuth;

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

    @GetMapping("/otp/{code}")
    public Mono<ApiResponseDTO> optCheckCode(@PathVariable String code, Principal principal) {
        Set<String> rolesMain = new HashSet<>();
        rolesMain.add("PRE_AUTH");
        validateAuth.validateAuthorityForPrincipal(principal, rolesMain);
        return userService.checkCode(principal.getName(), code)
                .map(token -> new ApiResponseDTO(token, "Otp checking success"));
    }

    @GetMapping("/resend/code")
    public Mono<ApiResponseDTO> optResendCode(Principal principal) {
        Set<String> rolesMain = new HashSet<>();
        rolesMain.add("PRE_AUTH");
        validateAuth.validateAuthorityForPrincipal(principal, rolesMain);
        return userService.resendCode(principal.getName())
                .map(token -> new ApiResponseDTO(token, "Otp has been successfully sent"));
    }

    @GetMapping("/authenticate")
    public Mono<ApiResponseDTO> isAuthenticated(Principal principal) {
        Set<String> rolesMain = new HashSet<>();
        rolesMain.add("ROLE_ADMIN");
        rolesMain.add("ROLE_USER");
        validateAuth.validateAuthorityForPrincipal(principal, rolesMain);
        return Mono.just(new ApiResponseDTO(principal.getName(), "Current user is authenticated"));
    }
}

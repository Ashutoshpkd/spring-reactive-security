package com.aip.security.webfluxotp.controller;

import com.aip.security.webfluxotp.common.exception.ValidatorException;
import com.aip.security.webfluxotp.domain.model.OtpChannel;
import com.aip.security.webfluxotp.service.UserService;
import com.aip.security.webfluxotp.service.ValidateAuthorityService;
import com.aip.security.webfluxotp.service.mapper.dto.ApiResponseDTO;
import com.aip.security.webfluxotp.service.mapper.dto.LoginDTO;
import com.aip.security.webfluxotp.service.mapper.dto.UserPasswordDTO;
import com.aip.security.webfluxotp.service.mapper.dto.VerifyDTO;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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

    private static final Logger logger = LoggerFactory.getLogger(AccountController.class);

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
                                .flatMap(userService::login)
                )
                .map(jwt -> new ApiResponseDTO(jwt.token(), "Partially successful user login - please verify yourself"));
    }

    @GetMapping(value = "/fetch/{channel}", produces = MediaType.APPLICATION_JSON_VALUE)
    public Mono<ApiResponseDTO> verify(@PathVariable @Valid OtpChannel channel, Principal principal) {
        String username = validateAuth.getUsernameFromPrincipal(principal);
        return userService.fetchOTP(username, channel)
                .map(jwt -> new ApiResponseDTO(jwt.token(), "OTP has been successfully sent!"));
    }

    @PostMapping("/verify")
    public Mono<ApiResponseDTO> optCheckCode(@RequestBody @Valid VerifyDTO verifyDTO, Principal principal) {
        Set<String> rolesMain = new HashSet<>();
        rolesMain.add("PRE_AUTH");
        logger.info("Validating the OTP for channel: {}, and code: {}", verifyDTO.getOtpChannel(), verifyDTO.getCode());
        validateAuth.validateAuthorityForPrincipal(principal, rolesMain);
        return userService.checkCode(principal.getName(), verifyDTO.getOtpChannel(), verifyDTO.getCode())
                .map(token -> new ApiResponseDTO(token, "Otp checking success"));
    }

    @GetMapping("/resend/code/{channel}")
    public Mono<ApiResponseDTO> optResendCode(@PathVariable OtpChannel channel, Principal principal) {
        Set<String> rolesMain = new HashSet<>();
        rolesMain.add("PRE_AUTH");
        validateAuth.validateAuthorityForPrincipal(principal, rolesMain);
        return userService.resendCode(principal.getName(), channel)
                .map(token -> new ApiResponseDTO(token, "Otp has been successfully sent"));
    }

    @GetMapping("/authenticate")
    public Mono<ApiResponseDTO> isAuthenticated(Principal principal) {
        Set<String> rolesMain = new HashSet<>();
        rolesMain.add("ROLE_ADMIN");
        rolesMain.add("ROLE_USER");
        validateAuth.validateAuthorityForPrincipal(principal, rolesMain);
        return userService.getAuthenticatedUser(principal.getName());
    }
}

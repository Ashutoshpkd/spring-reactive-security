package com.aip.security.webfluxotp.service;

import com.aip.security.webfluxotp.domain.document.User;
import com.aip.security.webfluxotp.service.mapper.dto.ApiResponseDTO;
import com.aip.security.webfluxotp.service.mapper.dto.OtpTokenDTO;
import com.aip.security.webfluxotp.service.mapper.dto.UserPasswordDTO;
import org.springframework.security.core.Authentication;
import reactor.core.publisher.Mono;

import javax.validation.constraints.NotNull;

public interface UserService {

    Mono<User> createUser(UserPasswordDTO userPasswordDTO);

    /**
     * @param authenticationName authentication Name
     * @param code otp code
     * @return jwt temp token
     */
    Mono<String> checkCode(String authenticationName, @NotNull String code);

    /**
     * @param authenticationName authentication Name
     * @return Mono OtpTokenDTO
     */
    Mono<OtpTokenDTO> resendCode(String authenticationName);

    /**
     * @param authentication  security authentication
     * @return Mono OtpTokenDTO
     */
    Mono<OtpTokenDTO> setUserOtp(Authentication authentication);

    /**
     * @param username  security authentication
     * @return Mono User
     */
    Mono<ApiResponseDTO> getAuthenticatedUser(String username);
}

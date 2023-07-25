package com.aip.security.webfluxotp.service.mapper.dto;

import com.aip.security.webfluxotp.domain.document.User;

public record OtpTokenDTO(String token, User user) {}

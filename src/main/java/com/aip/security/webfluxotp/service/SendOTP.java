package com.aip.security.webfluxotp.service;

import com.aip.security.webfluxotp.domain.document.User;

public interface SendOTP {
    void sendOTP(User user);
}

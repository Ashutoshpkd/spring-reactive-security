package com.aip.security.webfluxotp.common.exception;

public class OtpNotSentException extends RuntimeException {
    public OtpNotSentException(String message) {
        super(message);
    }
}

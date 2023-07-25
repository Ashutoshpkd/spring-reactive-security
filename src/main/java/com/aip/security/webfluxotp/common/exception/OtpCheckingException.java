package com.aip.security.webfluxotp.common.exception;

public class OtpCheckingException extends RuntimeException {

    public OtpCheckingException() {
    }

    public OtpCheckingException(String message) {
        super(message);
    }

    public OtpCheckingException(String message, Throwable throwable) {
        super(message, throwable);
    }
}

package com.aip.security.webfluxotp.factory;

import com.aip.security.webfluxotp.domain.model.OtpChannel;
import com.aip.security.webfluxotp.service.SendOTP;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

@Component
public class SendOTPFactory {

    @Autowired
    @Qualifier("OTPMailService")
    private SendOTP otpMailService;

    @Autowired
    @Qualifier("OTPPhoneService")
    private SendOTP otpPhoneService;

    public SendOTP getInstance(OtpChannel METHOD) {
        switch (METHOD) {
            case SMS:
                return otpPhoneService;
            case EMAIL:
                return otpMailService;
            default:
                throw new IllegalArgumentException("Invalid OTP sending method: " + METHOD);
        }
    }
}

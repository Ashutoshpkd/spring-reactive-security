package com.aip.security.webfluxotp.service;

import com.aip.security.webfluxotp.configuration.PhoneProperties;
import com.aip.security.webfluxotp.domain.document.User;
import com.twilio.Twilio;
import com.twilio.rest.api.v2010.account.Message;
import com.twilio.type.PhoneNumber;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

@Service
public class OTPPhoneService implements SendOTP {

    @Autowired
    private PhoneProperties properties;

    @Override
    @Async
    public void sendOTP(User user) {
        try {
            Twilio.init(properties.getACCOUNT_SID(), properties.getAUTH_TOKEN());
            Message message = Message.creator(
                            new PhoneNumber(user.getPhone()),
                            new PhoneNumber("+18149924361"),
                            "Your AIP OTP is " + user.getOtpRequest().getCode())
                    .create();

            System.out.println(message.getSid());
        } catch (RuntimeException err) {
            throw err;
        }
    }
}

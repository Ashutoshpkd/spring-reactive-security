package com.aip.security.webfluxotp.configuration;

import lombok.Data;
import lombok.ToString;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Data
@ToString
@Configuration
@ConfigurationProperties(prefix = "phone")
public class PhoneProperties {
    private String ACCOUNT_SID;
    private String AUTH_TOKEN;
}

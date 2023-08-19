package com.aip.security.webfluxotp.service.mapper.dto;

import com.aip.security.webfluxotp.domain.model.OtpChannel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Builder
@Data
@AllArgsConstructor
@NoArgsConstructor
public class VerifyDTO {
    private OtpChannel otpChannel;
    private String code;
}

package com.aip.security.webfluxotp.service.mapper.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class ApiResponseDTO {

    @JsonProperty("data")
    private Object data;

    @JsonProperty("message")
    private String message;

}

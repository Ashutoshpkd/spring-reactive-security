package com.aip.security.webfluxotp.domain.document;

import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import javax.validation.constraints.Size;
import java.io.Serial;
import java.io.Serializable;


@Builder
@Data
@NoArgsConstructor
@AllArgsConstructor
@ToString
@EqualsAndHashCode
@Document(collection="roles")
public class Role implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    @Size(min = 5, max = 10)
    @Id
    private String name;
}

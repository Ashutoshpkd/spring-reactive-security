package com.aip.security.webfluxotp.service.mapper;

import com.aip.security.webfluxotp.domain.document.User;
import com.aip.security.webfluxotp.service.mapper.dto.UserPasswordDTO;
import com.aip.security.webfluxotp.service.mapper.dto.UserDTO;
import org.mapstruct.Mapper;

/**
 * Mapper for the entity {@link User} and its DTO {@link UserDTO}.
 */
@Mapper
public interface UserMapper {

    User toEntity(UserDTO dto);

    UserDTO toDto(User entity);


    default User userPasswordDTOToUser(UserPasswordDTO userPasswordDTO){
        return User.builder()
                .username(userPasswordDTO.getUsername())
                .email(userPasswordDTO.getEmail()).firstName(userPasswordDTO.getFirstName())
                .lastName(userPasswordDTO.getLastName()).password(userPasswordDTO.getPassword())
                .roles(userPasswordDTO.getRoles()).enabled(true).accountNonLocked(false)
                .accountNonExpired(false).credentialsNonExpired(false)
                .build();
    }
}

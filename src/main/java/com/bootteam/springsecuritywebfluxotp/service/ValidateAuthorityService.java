package com.bootteam.springsecuritywebfluxotp.service;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Principal;
import java.util.Collection;
import java.util.Set;

@Service
public class ValidateAuthorityService {

    public void validateAuthorityForPrincipal(Principal principal, Set<String> requiredRoles) {
        if (principal instanceof UsernamePasswordAuthenticationToken) {
            UsernamePasswordAuthenticationToken authenticationToken = (UsernamePasswordAuthenticationToken) principal;
            Object principalObject = authenticationToken.getPrincipal();

            if (principalObject instanceof UserDetails) {
                UserDetails userDetails = (UserDetails) principalObject;
                Collection<? extends GrantedAuthority> authorities = userDetails.getAuthorities();

                if (!hasAllRequiredRoles(authorities, requiredRoles)) {
                    throw new AccessDeniedException("Insufficient permission to access this endpoint");
                }
            } else {
                throw new AccessDeniedException("Invalid user principal");
            }
        } else {
            throw new AccessDeniedException("Invalid authentication token");
        }
    }

    private boolean hasAllRequiredRoles(Collection<? extends GrantedAuthority> authorities, Set<String> requiredRoles) {
        return authorities.stream().map(GrantedAuthority::getAuthority).allMatch(requiredRoles::contains);
    }
}

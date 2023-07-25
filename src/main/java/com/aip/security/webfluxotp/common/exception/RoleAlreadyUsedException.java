package com.aip.security.webfluxotp.common.exception;

public class RoleAlreadyUsedException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public RoleAlreadyUsedException() {
        super("Role name already exist!");
    }
}

package com.secure.notes.security.response;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.List;

@Data
@AllArgsConstructor
public class LoginResponse {

    private String jwt;
    private String username;
    private List<String> roles;
}
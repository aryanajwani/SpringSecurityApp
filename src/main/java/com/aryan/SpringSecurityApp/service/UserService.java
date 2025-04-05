package com.aryan.SpringSecurityApp.service;

import java.util.Base64;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.aryan.SpringSecurityApp.model.User;
import com.aryan.SpringSecurityApp.repo.UserRepo;

import jakarta.servlet.http.HttpServletRequest;

@Service
public class UserService {

    private static final String BEARER_PREFIX = "Bearer ";
    private static final String BASIC_PREFIX = "Basic ";

    @Autowired
    private UserRepo repo;

    @Autowired
    private PasswordEncoder encoder;

    @Autowired
    private AuthenticationManager authManager;

    @Autowired
    private JWTService jwtService;

    public User signUp(User user) {
        user.setPassword(encoder.encode(user.getPassword()));
        ;
        return repo.save(user);
    }

    public User findByUsername(String username) {
        return repo.findByUsername(username);
    }

    public String verify(User user) {
        try {
            authManager.authenticate(new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword()));
            return jwtService.generateToken(user.getUsername());
        } catch (AuthenticationException e) {
            return "unauthorized";
        }
    }

    public String getUsernameFromRequest(HttpServletRequest request) throws UsernameNotFoundException{
        String authorization = request.getHeader("Authorization");

        if(authorization.startsWith(BEARER_PREFIX)) {
            String jwtToken = authorization.substring(7);
            return jwtService.extractUserName(jwtToken);
        }

        else if(authorization.startsWith(BASIC_PREFIX)){
            String base64Cred = authorization.substring(6);
            byte[] decodedBytes = Base64.getDecoder().decode(base64Cred);
            String decodedString  = new String(decodedBytes);
            String[] cred = decodedString.split(":", 2);
            if(cred.length == 2){
                return cred[0];
            }
        }
        throw new UsernameNotFoundException("Authorization must be JWT or Basic Auth");
    }

}

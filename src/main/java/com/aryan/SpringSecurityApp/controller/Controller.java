package com.aryan.SpringSecurityApp.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.aryan.SpringSecurityApp.model.User;
import com.aryan.SpringSecurityApp.service.JWTService;
import com.aryan.SpringSecurityApp.service.UserService;

import jakarta.servlet.http.HttpServletRequest;

@RestController
public class Controller {

    @Autowired
    UserService service;

    @Autowired
    JWTService jwtService;

    @GetMapping("/csrf-token")
    public CsrfToken getCSRFToken(HttpServletRequest request) {
        return (CsrfToken) request.getAttribute("_csrf");
    }

    @GetMapping("/")
    public String greet(HttpServletRequest request) {
        String username = service.getUsernameFromRequest(request);
        return "Hello " + username;
    }

    @PostMapping("/signup")
    public ResponseEntity<String> signUp(@RequestBody User user) {
        User u = service.findByUsername(user.getUsername());
        if (u != null) {
            return new ResponseEntity<>("Account Already Exists", HttpStatus.CONFLICT);
        }

        u = service.signUp(user);
        String msg = "Hey " + u.getUsername() + ", Account Created Successfully!";
        return new ResponseEntity<>(msg, HttpStatus.CREATED);
    }

    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody User user) {
        String response = service.verify(user);
        if (response == "unauthorized") {
            return new ResponseEntity<>("Bad Credentials", HttpStatus.UNAUTHORIZED);
        }
        return new ResponseEntity<>("Welcome Back, " + user.getUsername() + "\n" + response, HttpStatus.OK);
    }
}

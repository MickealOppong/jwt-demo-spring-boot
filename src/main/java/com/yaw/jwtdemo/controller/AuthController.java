package com.yaw.jwtdemo.controller;

import com.yaw.jwtdemo.service.AppUserDetailsService;
import com.yaw.jwtdemo.service.TokenGeneratorService;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RequestMapping(value = "/auth",consumes = "application/json")
@RestController
public class AuthController {


    private final TokenGeneratorService tokenGeneratorService;
    private AppUserDetailsService appUserDetailsService;

    public AuthController(TokenGeneratorService tokenGeneratorService) {
        this.tokenGeneratorService = tokenGeneratorService;
    }


    @GetMapping("/welcome")
    public String welcome(){
        return "Hello ,welcome";
    }



    @PostMapping("/token")
    public String getToken(Authentication authentication){
       String token = tokenGeneratorService.generateToken(authentication);
        return token;
    }
}

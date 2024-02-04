package com.yaw.jwtdemo.controller;

import com.yaw.jwtdemo.model.AppUser;
import com.yaw.jwtdemo.repository.AppUserRepository;
import com.yaw.jwtdemo.service.AppUserDetailsService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;

@RequestMapping("/user")
@RestController
public class AppUserController {

    private AppUserDetailsService appUserDetailsService;
    private AppUserRepository appUserRepository;

    public AppUserController(AppUserDetailsService appUserDetailsService,
                             AppUserRepository appUserRepository) {
        this.appUserDetailsService = appUserDetailsService;
        this.appUserRepository = appUserRepository;
    }

    @PostMapping("/addUser")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public String addUser(@RequestBody AppUser appUser){
        appUserDetailsService.addUser(appUser);
        return "user created successfully";
    }
    @GetMapping("/me")
    public ResponseEntity<UserDetails> me(Principal principal){
       AppUser appUser = appUserRepository.findByUsername(principal.getName()).get();
        return ResponseEntity.ok(appUser);
    }
}

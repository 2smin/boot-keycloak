package com.tmax.keycloaktest.controller;

import org.keycloak.KeycloakSecurityContext;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/test")
public class TestController {

    @RequestMapping(value = "/permitAll", method = RequestMethod.GET)
    public ResponseEntity<String> permitAll(){
        return ResponseEntity.ok("all guest available");
    }

    @RequestMapping(value = "/authenticated", method = RequestMethod.GET)
    public ResponseEntity<String> authenticated(@RequestHeader String Authorization){


        SecurityContext ctx = SecurityContextHolder.getContext();
        System.out.println(ctx.getAuthentication());
        System.out.println(ctx.getAuthentication().getCredentials());
        return ResponseEntity.ok("authenticated successed");
    }

    @PreAuthorize("hasAnyRole('user')")
    @RequestMapping(value = "/user", method = RequestMethod.GET)
    public ResponseEntity<String> user(){
        return ResponseEntity.ok("only user available");
    }

    @PreAuthorize("hasAnyRole(('admin'))")
    @RequestMapping(value = "/admin", method = RequestMethod.GET)
    public ResponseEntity<String> admin(@RequestHeader String Authorization){

        return ResponseEntity.ok("only admin available");
    }
}

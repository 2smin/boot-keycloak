package com.tmax.keycloaktest.controller;

import org.keycloak.KeycloakPrincipal;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.adapters.jetty.core.AbstractKeycloakJettyAuthenticator;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.security.RolesAllowed;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;

@RestController
public class TestController {

    @RequestMapping(value = "/permitAll", method = RequestMethod.GET)
    public ResponseEntity<String> permitAll(){
        return ResponseEntity.ok("all guest available");
    }

    @RequestMapping(value = "/logout", method = RequestMethod.GET)
    public void logout(HttpServletResponse response) {

        try{
            response.sendRedirect("http://192.168.9.160:8080/auth/realms/springBoot/protocol/openid-connect/logout?redirect_uri=http://192.168.9.160:8080/auth/realms/springBoot/account/");

        }catch (Exception e){
            e.printStackTrace();
        }

    }

    @RequestMapping(value = "/authenticated", method = RequestMethod.GET)
    public ResponseEntity<String> authenticated(){


        SecurityContext ctx = SecurityContextHolder.getContext();
        System.out.println(ctx.getAuthentication());
        System.out.println(ctx.getAuthentication().getCredentials());
        return ResponseEntity.ok("authenticated successed");
    }


    @RolesAllowed("user")
    @RequestMapping(value = "/user", method = RequestMethod.GET)
    public ResponseEntity<String> user(){
        SecurityContext ctx = SecurityContextHolder.getContext();
        System.out.println(ctx.getAuthentication());
        System.out.println(ctx.getAuthentication().getCredentials());
        return ResponseEntity.ok("only user available");
    }

    @RolesAllowed("admin")
    @RequestMapping(value = "/admin", method = RequestMethod.GET)
    public ResponseEntity<String> admin(HttpServletRequest request) throws UnsupportedEncodingException {
        SecurityContext ctx = SecurityContextHolder.getContext();
        System.out.println(ctx.getAuthentication());
        System.out.println(ctx.getAuthentication().getDetails());
        System.out.println("========");
        KeycloakPrincipal keycloakPrincipal = (KeycloakPrincipal) ctx.getAuthentication().getPrincipal();
//        System.out.println("[[[PRINCIPAL]]]");
//        System.out.println(keycloakPrincipal.getName());
//        System.out.println(keycloakPrincipal.getKeycloakSecurityContext());
        KeycloakSecurityContext keycloakSecurityContext = keycloakPrincipal.getKeycloakSecurityContext();
//        System.out.println("[[[[ID TOKEN]]]]");
//        System.out.println(keycloakSecurityContext.getIdTokenString());
        AccessToken accessToken = keycloakSecurityContext.getToken();
        System.out.println("[[[[ACCESS TOKEN]]]]");
        System.out.println("exp: " + keycloakSecurityContext.getTokenString());
        System.out.println("accesstoken toString: " + accessToken.toString());
        System.out.println("AccessTOKEN scope: " + accessToken.getScope());
        System.out.println("AccessTOKEN realmAccess: " + accessToken.getRealmAccess().getRoles());
        System.out.println("AccessTOKEN mapper: " + accessToken.getOtherClaims().keySet());
        HttpSession session =request.getSession();
        System.out.println("JsessionID!!!");
        Cookie[] cookies = request.getCookies();
        for(Cookie cookie : cookies){
            System.out.println("cookie name: " + cookie.getName());
            System.out.println("cookie value: " + URLDecoder.decode(cookie.getValue(),"UTF-8"));
        }
        System.out.println();
        return ResponseEntity.ok("only admin available");
    }

    @RequestMapping("/app")
    public String app(HttpServletRequest request){
        System.out.println(request.toString());
        System.out.println(request.getHeader("Connection"));
        System.out.println("keycloakcontexthttp name: " + KeycloakSecurityContext.class.getName());
        try {
            KeycloakSecurityContext keycloakSecurityContext = (KeycloakSecurityContext) request.getAttribute(KeycloakSecurityContext.class.getName());
            if(keycloakSecurityContext == null) {
                System.out.println("KeycloakSecurityContext not available in the HttpServletRequest.");
            } else {
                System.out.println(keycloakSecurityContext);
                System.out.println("IDTOKEN: " + keycloakSecurityContext.getIdTokenString());
                System.out.println("ACCESSTOKEN: " + keycloakSecurityContext.getTokenString());

                System.out.println();
                System.out.println("CTX");
                //아래는 Authorizaition 활성화 해주어야 쓸수 있을거같은 느낌????
//                System.out.println(keycloakSecurityContext.getAuthorizationContext().toString());
//                System.out.println(keycloakSecurityContext.getAuthorizationContext().getPermissions());
//                System.out.println(keycloakSecurityContext.getAuthorizationContext().isGranted());
            }
        } catch (NoClassDefFoundError ncdfe) {
                ncdfe.printStackTrace();
        }
        return "this is app";
    }
}

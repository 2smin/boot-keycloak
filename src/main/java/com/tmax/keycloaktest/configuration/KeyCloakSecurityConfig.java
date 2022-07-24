package com.tmax.keycloaktest.configuration;

import org.keycloak.adapters.springsecurity.KeycloakConfiguration;
import org.keycloak.adapters.springsecurity.authentication.KeycloakAuthenticationProvider;
import org.keycloak.adapters.springsecurity.client.KeycloakClientRequestFactory;
import org.keycloak.adapters.springsecurity.config.KeycloakWebSecurityConfigurerAdapter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

import java.security.ProtectionDomain;

//FilterChain을 구성하는 configuration

@KeycloakConfiguration //@EnableWebSecurity를 포함하고있다. 이 어노테이션을 붙이면 SpringSecurityFilterChain에 등록된다
@EnableWebSecurity(debug = true)
@EnableGlobalMethodSecurity(jsr250Enabled = true, prePostEnabled = true) // 사전에 prePost로 권한체크를 하겠다는 설정
public class KeyCloakSecurityConfig extends KeycloakWebSecurityConfigurerAdapter {

    //keycloakAuthenticationProvider를 springboot authentication manager에 등록
    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception{

        KeycloakAuthenticationProvider keycloakAuthenticationProvider = keycloakAuthenticationProvider();

        keycloakAuthenticationProvider.setGrantedAuthoritiesMapper(new SimpleAuthorityMapper());
        auth.authenticationProvider(keycloakAuthenticationProvider);
    }

    //session 관리 커스터마이징
    @Bean
    @Override
    protected SessionAuthenticationStrategy sessionAuthenticationStrategy(){
        return new RegisterSessionAuthenticationStrategy(new SessionRegistryImpl());
    }

    //keycloak용 filterchain 구성
    @Override
    protected void configure(HttpSecurity http) throws Exception{
        super.configure(http);
        http.authorizeRequests()
                .antMatchers("/test/permitAll").permitAll() //keycloak에서 관리하는 role을 url과 매핑한다
                .anyRequest().authenticated();
        http.csrf().disable();
    }
}

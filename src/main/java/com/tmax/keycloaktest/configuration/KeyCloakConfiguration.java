package com.tmax.keycloaktest.configuration;

import org.keycloak.adapters.springboot.KeycloakSpringBootConfigResolver;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class KeyCloakConfiguration {

    //keycloak.json 대신 springboot.yaml을 설정파일로 쓰도록 함
    //원래는 keycloakConfigResolver를 bean으로 등록해서 json 파일을 읽게하는게 일반적
    @Bean
    public KeycloakSpringBootConfigResolver keycloakSpringBootConfigResolver(){
        return new KeycloakSpringBootConfigResolver();
    }
}

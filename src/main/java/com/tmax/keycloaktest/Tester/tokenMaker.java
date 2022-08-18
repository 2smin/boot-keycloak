package com.tmax.keycloaktest.Tester;

import org.keycloak.representations.AccessToken;

public class tokenMaker {

    AccessToken accessToken = new AccessToken();

    public void makeToken(){

        accessToken.expiration(5);
        accessToken.exp(4L);
        accessToken.iat(4l);

    }
}

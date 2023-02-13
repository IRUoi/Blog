package com.markerhub.shiro;

import org.apache.shiro.authc.AuthenticationToken;

/**
 * @Auther: ZHU(lc))
 * @Date: 2/12/2023-02-12-4:31 PM
 * @Description：com.markerhub.shiro
 */
public class JwtToken implements AuthenticationToken {

    private String token;

    public JwtToken(String jwt){
        this.token = jwt;
    }

    @Override
    public Object getPrincipal() {



        return token;
    }

    @Override
    public Object getCredentials() {
        return token;
    }
}

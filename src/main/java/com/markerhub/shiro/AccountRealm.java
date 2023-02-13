package com.markerhub.shiro;

import cn.hutool.core.bean.BeanUtil;
import com.markerhub.entity.User;
import com.markerhub.service.UserService;
import com.markerhub.util.JwtUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.net.Authenticator;

/**
 * @Auther: ZHU(lc))
 * @Date: 2/12/2023-02-12-2:28 AM
 * @Description：com.markerhub.shiro
 */
@Component
public class AccountRealm extends AuthorizingRealm {

    @Autowired
    JwtUtils jwtUtils;

    @Autowired
    UserService userService;

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        return null;
    }

    @Override
    public boolean supports(AuthenticationToken token) {
        return token instanceof JwtToken;
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {

        JwtToken jwtToken = (JwtToken) authenticationToken;

        String userId = jwtUtils.getClaimByToken((String) jwtToken.getPrincipal()).getSubject();

        User user = userService.getById(Long.valueOf(userId));

        if(user == null){
            throw new UnknownAccountException("账户不存在");
        }

        if(user.getStatus() == -1){
            throw new LockedAccountException("账户已被锁定");

        }

        AccountProfile profile = new AccountProfile();
        BeanUtil.copyProperties(user,profile);

        return new SimpleAuthenticationInfo(profile,jwtToken.getCredentials(),getName());
    }
}

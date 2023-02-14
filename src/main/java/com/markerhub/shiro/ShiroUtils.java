package com.markerhub.shiro;

import org.apache.shiro.SecurityUtils;

/**
 * @Auther: ZHU(lc))
 * @Date: 2/14/2023-02-14-3:51 PM
 * @Description：com.markerhub.shiro
 */
public class ShiroUtils {
    public static AccountProfile getProfile(){
        return (AccountProfile) SecurityUtils.getSubject().getPrincipal();
    }
}

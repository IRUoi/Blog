package com.markerhub.shiro;

import lombok.Data;

import java.io.Serializable;

/**
 * @Auther: ZHU(lc))
 * @Date: 2/12/2023-02-12-11:52 PM
 * @Description：com.markerhub.shiro
 */
@Data
public class AccountProfile implements Serializable {

    private Long id;

    private String username;

    private String avatar;

    private String email;

}

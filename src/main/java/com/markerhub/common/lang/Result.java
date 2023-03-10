package com.markerhub.common.lang;

import lombok.Data;

import javax.annotation.Resource;
import java.io.Serializable;

/**
 * @Auther: ZHU(lc))
 * @Date: 2/11/2023-02-11-6:13 PM
 * @Description：com.markerhub.common.lang
 */
@Data
public class Result implements Serializable {
    private int code; //200是正常，非200表示异常
    private String msg;
    private Object data;

    public static Result succ(Object data){

        return succ(200,"操作成功",data);
    }


    public static Result succ(int code, String msg, Object data){
        Result result = new Result();
        result.setCode(code);
        result.setMsg(msg);
        result.setData(data);

        return result;
    }

    public static Result fail(String msg){

        return fail(400,msg,null);
    }


    public static Result fail(int code, String msg, Object data){
        Result result = new Result();
        result.setCode(code);
        result.setMsg(msg);
        result.setData(data);

        return result;
    }

}

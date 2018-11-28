package com.xmage.dm01.utils;

import lombok.Data;

import java.io.Serializable;

/**
 * 返回对象包装类(带泛型) .
 * 
 */
@Data
public class ResponseResult<T> implements Serializable {

    /**
     * 序列化id
     */
    private static final long serialVersionUID = -6883482050087865474L;

    /**
     * 成功
     */
    public static final int SUCCESS = 1;
    
    static final String SUCCESSMSG = "success";

    /**
     * 失败
     */
    public static final int FAILED = 0;
    
    static final String FAILEDMSG = "fail";

    
    /**
     * 返回的信息(主要出错的时候使用)
     */
    private String message;

    /**
     * 接口返回码
     */
    private Integer code;

    /**
     * 返回的数据
     */
    private T data;

    /**
     * 构造函数
     */
    public ResponseResult() {
        super();
    }

    /**
     * 有参构造函数
     * 
     * @param data
     */
    public ResponseResult(T data) {
    	super();
    	SuccessResponse(data);
    }
    
    /**
     * 有参构造函数
     * 
     * @param data
     */
    public ResponseResult(T data,Integer status) {
    	super();
    	if(status>0){
    		SuccessResponse(data);
    	}else{
    		FailedResponse(data);
    	}
    }

    /**
     * success response
     * @param data
     */
    public void SuccessResponse(T data) { 
    	this.message = SUCCESSMSG;
    	this.code = SUCCESS;
    	this.data = data;
    }
    
    /**
     * failed response
     * @param data
     */
    public void FailedResponse(T data) { 
    	this.message = FAILEDMSG;
    	this.code = FAILED;
    	this.data = data;
    }

}

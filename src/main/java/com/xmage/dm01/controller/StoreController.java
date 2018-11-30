package com.xmage.dm01.controller;

import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.alibaba.fastjson.JSON;
import com.xmage.dm01.model.User;
import com.xmage.dm01.utils.AesUtil;
import com.xmage.dm01.utils.Base64Test;

@RestController
@RequestMapping("/shop")
public class StoreController {

	static final private List<User> customers  = new ArrayList<User>();

	
	@RequestMapping(value = "/{id}", method = RequestMethod.GET, produces = "application/json")
    public User getStoreById(@PathVariable("id") Long id,ModelMap model) { 
		 Long i = id;
		 int ii = Integer.parseInt(String.valueOf(id)); 
		 customers.add(new User(i,"user-"+i+1,20+ii,"gz-"+i+1));

		 User userObj = customers.get(0);
		
		return userObj;
    }
	
	@RequestMapping(value = "/base64", method = RequestMethod.POST)
    public Map<String, Object> test64Demo(
    		@RequestParam(value = "code", required = true, defaultValue = "") String code,
    		@RequestParam(value = "key", required = true, defaultValue = "Fquo7wacJLG5EOgGbYKMQpWxuSIHrpnMSjX87QwJWoTD70Fzo0I7BKXgLpFGPXoT") String pkey,
    		@RequestParam(value = "iv", required = false, defaultValue = "147abcdefg258369") String piv,
    		@RequestParam(value = "uid", required = false, defaultValue = "10831918") Long userId,
    		@RequestParam(value = "rand", required = false, defaultValue = "1543204765.2344618") String rand,
    		@RequestParam(value = "ts", required = false, defaultValue = "1543386581") String timestamp
    		) {  
		
		Base64Test base64Algorithm = Base64Test.getInstance();
		String iv = piv;
	    String key = pkey;	    
	    
	    // rand = base64Algorithm.createRandChar(8);
	    Object[] arrParams={userId,rand, timestamp};
	    String plain = JSON.toJSONString(arrParams);  
        System.out.println("plain text:" + plain); 
        String encodeStr = "";
        String decodeStr = "";
        String inputEncode = code;
        String inputDecode = "";
        
        try {
        	
        	String string = "hello 世界小姐";
            byte[] bytes = string.getBytes();//获得byte数组
            System.out.println("bytes-->" + Arrays.toString(bytes));//打印byte数组
            System.out.println("string-->" + new String(bytes));
        	
        	encodeStr = base64Algorithm.encrypt(plain, key,iv);
        	//encodeStr = Base64Test.java_openssl_encrypt(plain,key, iv);
        	decodeStr = base64Algorithm.decrypt(encodeStr, key,iv);
        	
        	System.out.println("加密后的密文为：" + encodeStr);
        	//System.out.println("解密密文为：" + cm.decodeCrypt(encodeByte, ckey));
        	System.out.println("解密密文为：" + decodeStr);

        	inputDecode = base64Algorithm.decrypt(inputEncode, key,iv);
        	System.out.println("input密文输入为：" + inputEncode);
        	System.out.println("input密文解密为：" + inputDecode);
        	
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        
        Map<String, Object> map = new HashMap<String, Object>();
        map.put("encode", encodeStr);
        map.put("decode", decodeStr);
        map.put("input_encode", inputEncode);
        map.put("input_decode", inputDecode);
        
        return map;
    }
	
	@RequestMapping(value = "/encode/php", method = RequestMethod.POST)
    public Map<String, Object> base64formphp(
    		@RequestParam(value = "code", required = true, defaultValue = "") String code,
    		@RequestParam(value = "key", required = true, defaultValue = "Fquo7wacJLG5EOgGbYKMQpWxuSIHrpnMSjX87QwJWoTD70Fzo0I7BKXgLpFGPXoT") String pkey
    		) {  
		
		Base64Test base64Algorithm = Base64Test.getInstance();

        String inputDecode = "";
        
        try {

        	inputDecode = base64Algorithm.decryptFormPhp(code, pkey);

        	System.out.println("input密文输入为：" + code);
        	System.out.println("input密文解密为：" + inputDecode);
        	
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        
        Map<String, Object> map = new HashMap<String, Object>();
        map.put("input_encode", code);
        map.put("input_decode", inputDecode);
        
        return map;
    }
	
	@RequestMapping(value = "/aes256", method = RequestMethod.POST)
    public Map<String, Object> genrateAes(
    		@RequestParam(value = "code", required = true, defaultValue = "") String code,
    		@RequestParam(value = "key", required = true, defaultValue = "Fquo7wacJLG5EOgGbYKMQpWxuSIHrpnMSjX87QwJWoTD70Fzo0I7BKXgLpFGPXoT") String pkey,
    		@RequestParam(value = "iv", required = false, defaultValue = "147abcdefg258369") String piv,
    		@RequestParam(value = "uid", required = false, defaultValue = "10831918") Long userId,
    		@RequestParam(value = "rand", required = false, defaultValue = "1543204765.2344618") String rand,
    		@RequestParam(value = "ts", required = false, defaultValue = "1543386581") String timestamp
    		) {  
		
		String iv = piv;
	    String key = pkey;
	    Object[] arrParams={userId,rand, timestamp};
	    /*
	    Base64Test base64Algorithm = Base64Test.getInstance();
	    Long nowst = (new Date()).getTime();
	    String timestamp = String.valueOf(nowst/1000);//通过整除将最后的三位去掉,保证是纯正时间戳
	    String randStr = base64Algorithm.createRandChar(8);
	    Object[] arrParams={"10831918",String.format("%s.%s",String.valueOf(nowst),randStr), timestamp};
	    */
	    String plain = JSON.toJSONString(arrParams);  
        System.out.println("aes plain:" + plain); 
        String encodeStr = "";
        String decodeStr = "";
        String mixedToken = "";
        String mixedTokenRaw = "";
        
        try {
        	byte[] data = plain.getBytes("UTF-8");
        	encodeStr = AesUtil.encrypt(data, key, iv, 256);
        	System.out.println("aesEncrypted256:"+encodeStr);

        	decodeStr = AesUtil.decrypt(encodeStr, key, 256);
        	System.out.println("aesDecrypted256:"+decodeStr);

        	mixedToken = AesUtil.encryptMixed(data, key, iv, 256);
        	System.out.println("mixed token result:"+mixedToken);
        	
        	
        	mixedTokenRaw = AesUtil.decryptMixed(code, key,256);
        	System.out.println("mixed token raw:"+mixedTokenRaw);

        } catch (Exception e) {
        	// TODO Auto-generated catch block
        	e.printStackTrace();
        }
        
        Map<String, Object> map = new HashMap<String, Object>();
        map.put("encode", encodeStr);
        map.put("decode", decodeStr);
        map.put("mixedToken", mixedToken);
        map.put("mixedTokenRaw", mixedTokenRaw);
        return map;	   
   }

}
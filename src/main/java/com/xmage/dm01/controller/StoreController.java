package com.xmage.dm01.controller;

import java.sql.Timestamp;
import java.util.ArrayList;
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
    		@RequestParam(value = "key", required = true, defaultValue = "") String skey
    		) {  
		Base64Test base64Algorithm = Base64Test.getInstance();
	    //String key = "SOME-ENCRYPTION-KEY-USED-ONLY-16-OR-32-BYTES";
	    //String key = "Fquo7wacJLG5EOgGbYKMQpWxuSIHrpnMSjX87QwJWoTD70Fzo0I7BKXgLpFGPXoT";	  
	    String key = skey;	
	    //String[] arrParams={"10831918","1543204765.2344618","1543204765"};
	    //String timestamp = "1543386581";
	    Long nowst = (new Date()).getTime();
	    String timestamp = String.valueOf(nowst/1000);//通过整除将最后的三位去掉,保证是纯正时间戳
	    String randStr = base64Algorithm.createRandChar(8);
	    Object[] arrParams={"10831918",String.format("%s.%s",String.valueOf(nowst),randStr), timestamp};
	    String plain = JSON.toJSONString(arrParams);  
        System.out.println("plain text:" + plain); 
        String encodeStr = "";
        String decodeStr = "";
        String inputEncode = code;
        String inputDecode = "";
        
        try {
        	
        	encodeStr = base64Algorithm.encrypt(plain, key);
        	decodeStr = base64Algorithm.decrypt(encodeStr, key);
        	
        	System.out.println("加密后的密文为：" + encodeStr);
        	//System.out.println("解密密文为：" + cm.decodeCrypt(encodeByte, ckey));
        	System.out.println("解密密文为：" + decodeStr);

        	inputDecode = base64Algorithm.decrypt(inputEncode, key);
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
	
	@RequestMapping(value = "/aes256", method = RequestMethod.POST)
    public Map<String, Object> genrateAes(
    		@RequestParam(value = "code", required = true, defaultValue = "") String code,
    		@RequestParam(value = "key", required = true, defaultValue = "") String skey
    		) {  
		
		String iv = "SOME-INITIAL-VECTOR-USED-ONLY-16-BYTES";
	    String key = skey;	
	    String timestamp = "1543386581";
	    Object[] arrParams={"10831918","1543204765.2344618", timestamp};
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
package com.xmage.dm01.controller;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;

import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

import com.alibaba.fastjson.JSON;

import com.xmage.dm01.model.User;
import com.xmage.dm01.utils.AesCBC;
import com.xmage.dm01.utils.AesUtil;
import com.xmage.dm01.utils.CipherUtil;

@Controller
@RequestMapping("/user")
public class UserController {
    

	@GetMapping("/login")
    public String login() {
        return "/login";
    }
	
    //@RequestMapping("/{id}") 
    @RequestMapping(value = "/{id}", method = RequestMethod.GET)
    public String  getUser(@PathVariable Long id,ModelMap model) {     
        model.addAttribute("user",new User(id,"张三",20,"中国广州"));
        return "/user/detail";
    }
    
    @RequestMapping("/list")
    public String  listUser(ModelMap model) {
        List<User> userList = new ArrayList<User>();
        for (int i = 0; i <10; i++) {
        	Long ii = (long)i;
            userList.add(new User(ii,"张三"+ii,20+i,"中国广州"));
        }
        
        model.addAttribute("users", userList);
        return "/user/list";
    }
    
    public String getFormatDateTime(){
    	SimpleDateFormat sd = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
		
		//获取当前时间
		String time = sd.format(new Date());
		//输出当前时间
		System.out.println("输出当前时间:"+time);
		
		//时间转换为时间戳
		Date date = null;
		try {
			date = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").parse(time);
		} catch (ParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		//java中时间戳毫秒计/1000 换算为秒
		long unixTimestamp = date.getTime() / 1000;
		
		//输出时间戳
		System.out.println("输出时间戳:"+unixTimestamp);
		
		
		//时间戳转换为当前时间
		String ntime = sd.format(unixTimestamp * 1000);
		
		//输出当前时间
		System.out.println("输出当前时间[时间戳转换]:"+ntime);
		
		return ntime;
    }
    
	@RequestMapping(value = "/aes/encrypt", method = RequestMethod.POST)
    public String aesEncrypt(
    		@RequestParam(value = "code", required = true, defaultValue = "") String code,
    		ModelMap model
    		) { 
    	String aesEncrypted256 = code;
    	String key = "Fquo7wacJLG5EOgGbYKMQpWxuSIHrpnMSjX87QwJWoTD70Fzo0I7BKXgLpFGPXoT";	     
    	String iv = "SOME-INITIAL-VECTOR-USED-ONLY-16-BYTES";
    	String aesDecrypted256 = "";
    	try {
    		AesUtil.cipherIv = iv;
    		aesDecrypted256 = AesUtil.decrypt(aesEncrypted256, key, 256);

    		System.out.println("aesDecrypted256::"+aesDecrypted256);
    		


    	} catch (Exception e) {
    		//e.printStackTrace();
    		
    	}
    	
    	List<User> userList = new ArrayList<User>();
        for (int i = 0; i <10; i++) {
        	Long ii = (long)i;
            userList.add(new User(ii,"张三"+ii,20+i,String.format("中国广州:%s",aesDecrypted256)));
        }
        
        model.addAttribute("users", userList);
        return "/user/list";
    }
    
    @RequestMapping("/aes")
    public String genrateAes(ModelMap model){
	    //String key = "SOME-ENCRYPTION-KEY-USED-ONLY-16-OR-32-BYTES";
	    String key = "Fquo7wacJLG5EOgGbYKMQpWxuSIHrpnMSjX87QwJWoTD70Fzo0I7BKXgLpFGPXoT";
	    String iv = "SOME-INITIAL-VECTOR-USED-ONLY-16-BYTES";
	    
	    String[] arrParams={"10831918","1543204765.2344618","1543386581"};
	    String plain = JSON.toJSONString(arrParams);  
        System.out.println("aes plain:" + plain); 

	    
	    try {
	      System.out.println("plain::"+plain);
	      System.out.println("key::"+key);
	      
	      byte[] data = plain.getBytes("UTF-8");
	      String aesEncrypted256 = AesUtil.encrypt(data, key, iv, 256);
	      System.out.println("aesEncrypted256:"+aesEncrypted256);

	      String aesDecrypted256 = AesUtil.decrypt(aesEncrypted256, key, 256);
	      System.out.println("aesDecrypted256:"+aesDecrypted256);
	      
	      
	      String mixedToken = AesUtil.encryptMixed(data, key, iv, 256);
	      System.out.println("mixedToken:"+mixedToken);
	      
	    } catch (Exception e) {
	      e.printStackTrace();
	    }
	    
	    model.addAttribute("user",new User((long) 1085265,"张三",20,"中国广州-aes"));
        return "/user/detail";
   }
    
    @RequestMapping(value = "/algo", method = RequestMethod.POST)
    public String getAlgoDemo(
    		@RequestParam(value = "code", required = true, defaultValue = "") String code,
    		ModelMap model
    		) {  
    	String plain = "SOME-DATA-TO-BLOCK-ENCRYPTION";
	    //String key = "SOME-ENCRYPTION-KEY-USED-ONLY-16-OR-32-BYTES";
	    //String key = "Fquo7wacJLG5EOgGbYKMQpWxuSIHrpnMSjX87QwJWoTD70Fzo0I7BKXgLpFGPXoT";	  
	    String key = "4E2BDA58E0166088612B044AA3C8755BB5F27D032F3564DEDB8EEBA7C56D1E40";
	    //String iv = "SOME-INITIAL-VECTOR-USED-ONLY-16-BYTES";
	    
	    String[] arrParams={"10831918","1543204765.2344618","1543204765"};
	    plain = JSON.toJSONString(arrParams);  
        System.out.println("plain text:" + plain); 
        
        try {
        	//key = AlgorithmUtil.getAESKey();
        	/*
        	String base64Key = key ; //Base64.getEncoder().encodeToString(key.getBytes("UTF-8"));
        	System.out.println("init key:" + key);
        	System.out.println("base64 key:" + base64Key);
        	
			String aesEncrypted256 = AlgorithmUtil.getAESEncode(base64Key, plain);			
			System.out.println("aesEncrypted256::"+aesEncrypted256);
			
			String aesDecrypted256 = new String(AlgorithmUtil.getAESDecode(base64Key, aesEncrypted256));
			System.out.println("aesDecrypted256::"+aesDecrypted256);
			*/
			   String algorithm = CipherUtil.CIPHER_INSTANCE_TYPE; // 定义加密算法,可用AES
		       //String message = "HelloWorld. 这是待加密的信息"; // 生成AES
			   String message = plain;
		       Key ckey = null;
		       CipherUtil cm = new CipherUtil(algorithm);
		       ckey = cm.initKey();		 

		       byte[] encodeByte = cm.encodeCrypt(message);
		       String encodeStr = cm.encodeBase64(encodeByte);

		       System.out.println("加密后的密文为：" + encodeStr);

		       System.out.println("密钥key为 :" + ckey.toString());

		       System.out.println("密钥BinaryKey为 :" + cm.getBinaryKey(ckey));

		       System.out.println("解密密文为：" + cm.decodeCrypt(encodeByte, ckey));
		       
		       System.out.println("base64解密密文为：" + cm.decodeCryptWithBase64(encodeStr, ckey));
		       
		       String inputCodeBase64 = code;
		       System.out.println("inputCodeBase64解密密文为：" + cm.decodeCryptWithBase64(inputCodeBase64, ckey));
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        
    	model.addAttribute("user",new User((long) 1085265,"张三SAM",20,"中国广州GZ"));
        return "/user/detail";
    }
    
       
    @GetMapping("/{userId}/profile")
    public String  getUserProfile(@PathVariable Long userId,ModelMap model) {  
    	
    	/*
         * 加密用的Key 可以用26个字母和数字组成，最好不要用保留字符，虽然不会错，至于怎么裁决，个人看情况而定
         * 此处使用AES-128-CBC加密模式，key需要为16位。
         */
        String sKey = "1234567890123456";
        // 需要加密的字串

    	//String[] pack = {"10831918","1542963263.6316852","1542963263"};
    	//String pack[] = {"10803","541wxs","558454"};
    	String content = String.join(":","10831918","1542963263.6316852","1542963263");
    	String sKeyxx = "Fquo7wacJLG5EOgGbYKMQpWxuSIHrpnMSjX87QwJWoTD70Fzo0I7BKXgLpFGPXoT";
    	System.out.println("xx len：" + sKeyxx.length());
    	
    	String aKey = "FfDaaaaaaa444aaaa7aaEFF4A76efaaaaaE5C23F5E4C3adeaaaaaaCAA796E307";
        String aEncrypted = "8AQ8SvpF1zgyNyxKwLlX\\/cGzwLE5skU58pg3kaSrt+AJt9D7\\/3vaNRPZISIKMdCUwwkQ2nxj8PVABRy0aaeBfsJN9n2Ltco6oPjdcmx8eOI";
        
        String aaaStr="";
    	try {
    		aaaStr = AesCBC.getInstance().decryptWith64Bit(aKey.getBytes(), aEncrypted);
    		 System.out.println("decryptWith64Bit：" + aaaStr);
		} catch (GeneralSecurityException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
    	//String sKey = AesCBC.sKey;
        System.out.println("明文：" + content);  
        System.out.println("key：" + sKey);  
          
        // 需要加密的字串
        //String cSrc = "123456";
        String cSrc =content;
      
        System.out.println("加密前的字串是："+cSrc);
        
        // 加密
        String enString="";
		try {
			enString = AesCBC.getInstance().encrypt(cSrc,sKey);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        System.out.println("加密后的字串是："+ enString);
        
        System.out.println("1jdzWuniG6UMtoa3T6uNLA==".equals(enString));
        
        // 解密
        String DeString="";
        //enString="xCXtuse2Axu0Ql4Jqq4VhHdVdHe8i8/GjuKevtpE+TSNQRcbULmTDmaPMzywgrADtpNQPQIjNDTE0Kp71KmB2g==";
		try {
			DeString = AesCBC.getInstance().decrypt(enString,sKey);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        System.out.println("解密后的字串是：" + DeString);
        
        model.addAttribute("user",new User(userId,"张三",20,"gzProfile"));
        return "/user/detail";
    }
    
    
    
}
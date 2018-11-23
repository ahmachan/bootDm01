package com.xmage.dm01.controller;

import java.security.GeneralSecurityException;
import java.sql.Timestamp;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;

import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import com.xmage.dm01.model.User;
import com.xmage.dm01.utils.AesCBC;
import com.xmage.dm01.utils.RSAUtil;

@Controller
@RequestMapping("/user")
public class UserController {
    
	private Long expTime = (long) 86400000;
	
	private String secret = "RSA-SHA128";
	
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
        
        //System.out.println("密文：" + RSAUtil.parseByte2HexStr(encryptResult));  
          
        //String decryptResult = RSAUtil.decryptAES256(encryptResult, password);  
        //System.out.println("解密：" + decryptResult);  
    	
    	//String content = "{name:xmage,age:25,sex:fame,address:湖南省gzone}";
    	/*
    	Map<String,Object> keyMap = new HashMap<String, Object>();
		keyMap.put("name", "xmage");
		keyMap.put("time", "15896965874");
		String content =keyMap.toString();
		*/
		/*
		Timestamp nowTimestamp = new Timestamp(new Date().getTime());	
		Long nowTime = nowTimestamp.getTime() + expTime;
		//String content ="${userId.toString()}:${nowTime}:${secret}";
		String content =String.format("%d:%d:%s",userId,nowTime,secret);

        //1.初始化公钥私钥
        String rsaPublicKey = null;
        String rsaPrivateKey = null;
        try {
            Map<String, Object> map = RSAUtil.initKey();
            rsaPublicKey = RSAUtil.getPublicKey(map);
            rsaPrivateKey = RSAUtil.getPrivateKey(map);
        } catch (Exception e) {
            e.printStackTrace();
        }

        //2.使用公钥加密
        try {
            System.out.println("加密前=="+content);
            byte[] result_m = RSAUtil.encryptByPublicKey(content.getBytes(), rsaPublicKey);
            content = RSAUtil.encryptBASE64(result_m);
            System.out.println("加密后=="+content);
        } catch (Exception e) {
            e.printStackTrace();
        }
        //3.私钥解密
        try {
            byte[] b1 = RSAUtil.decryptBASE64(content);
            byte[] b2 = RSAUtil.decryptByPrivateKey(b1, rsaPrivateKey);
            content = new String(b2);
            String[] arrStr = content.split(":");
            System.out.println("解密后=="+content);
            System.out.println("userId=="+arrStr[0]);
        } catch (Exception e) {
            e.printStackTrace();
        }


        //4.私钥加签
        String sign = null;
        try {
            sign = RSAUtil.sign(content.getBytes(), rsaPrivateKey);
            System.out.println("签名=="+sign);
        } catch (Exception e) {
            e.printStackTrace();
        }
        //5.公钥验签
        try {
            boolean flag = RSAUtil.verify(content.getBytes(), rsaPublicKey, sign);
            System.out.println("延签结果=="+flag);
        } catch (Exception e) {
            e.printStackTrace();
        }

*/
        model.addAttribute("user",new User(userId,"张三",20,"gzProfile"));
        return "/user/detail";
    }
    
}
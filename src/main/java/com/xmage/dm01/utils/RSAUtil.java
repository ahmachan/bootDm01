package com.xmage.dm01.utils;

//import sun.misc.BASE64Decoder;
//import sun.misc.BASE64Encoder;
import org.apache.commons.codec.binary.Base64;

import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;  
import javax.crypto.KeyGenerator;  
import javax.crypto.SecretKey;  
import javax.crypto.spec.SecretKeySpec;

import java.util.HashMap;
import java.util.Map;

/**
 * @ClassName: RSAUtil
 * @Description: 公钥、密钥生成和校验
 * 
 **/
public class RSAUtil {
	public static final String KEY_ALGORTHM="RSA";//加密类型
	public static final String SIGNATURE_ALGORITHM="MD5withRSA";

	public static final String CIPHER = "aes-256-cbc";

	public static final String PUBLIC_KEY = "RSAPublicKey";//公钥
	public static final String PRIVATE_KEY = "RSAPrivateKey";//私钥

	/**
	 * BASE64解密
	 * @param byteData
	 * @return
	 * @throws Exception
	 */
	public static byte[] decryptBASE64(String data){
		//String strByte = Arrays.toString(Base64.decodeBase64(str));
        //String strByte = new String(byteData);
        return Base64.decodeBase64(data);		
	}

	/**
	 * BASE64加密
	 * @param data
	 * @return
	 * @throws Exception
	 */
	public static String encryptBASE64(byte[] data) throws Exception{
		//return (new Base64()).encodeToString(data.getBytes("UTF-8"));			
		return (new Base64()).encodeToString(data);
	}


	/**
	 * 初始化密钥
	 * @return
	 * @throws Exception
	 */
	public static Map<String,Object> initKey()throws Exception{
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORTHM);
		keyPairGenerator.initialize(1024);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();

		//公钥
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		//私钥
		RSAPrivateKey privateKey =  (RSAPrivateKey) keyPair.getPrivate();

		Map<String,Object> keyMap = new HashMap<String, Object>(2);
		keyMap.put(PUBLIC_KEY, publicKey);
		keyMap.put(PRIVATE_KEY, privateKey);

		return keyMap;
	}

	/**
	 * 取得公钥，并转化为String类型
	 * @param keyMap
	 * @return
	 * @throws Exception
	 */
	public static String getPublicKey(Map<String, Object> keyMap)throws Exception{
		Key key = (Key) keyMap.get(PUBLIC_KEY);
		return encryptBASE64(key.getEncoded());
	}

	/**
	 * 取得私钥，并转化为String类型
	 * @param keyMap
	 * @return
	 * @throws Exception
	 */
	public static String getPrivateKey(Map<String, Object> keyMap) throws Exception{
		Key key = (Key) keyMap.get(PRIVATE_KEY);
		return encryptBASE64(key.getEncoded());
	}


	/**
	 * 用公钥加密
	 * @param data  加密数据
	 * @param key   密钥
	 * @return
	 * @throws Exception
	 */
	public static byte[] encryptByPublicKey(byte[] data,String key)throws Exception{
		//对公钥解密
		byte[] keyBytes = decryptBASE64(key);
		//取公钥
		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORTHM);
		Key publicKey = keyFactory.generatePublic(x509EncodedKeySpec);

		//对数据解密
		Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);

		return cipher.doFinal(data);
	}

	/**
	 * 用私钥解密
	 * @param data  加密数据
	 * @param key   密钥
	 * @return
	 * @throws Exception
	 */
	public static byte[] decryptByPrivateKey(byte[] data,String key)throws Exception{
		//对私钥解密
		byte[] keyBytes = decryptBASE64(key);

		PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORTHM);
		Key privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
		//对数据解密
		Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
		cipher.init(Cipher.DECRYPT_MODE, privateKey);

		return cipher.doFinal(data);
	}



	/**
	 *  用私钥对信息生成数字签名
	 * @param data  //加密数据
	 * @param privateKey    //私钥
	 * @return
	 * @throws Exception
	 */
	public static String sign(byte[] data,String privateKey)throws Exception{
		//解密私钥
		byte[] keyBytes = decryptBASE64(privateKey);
		//构造PKCS8EncodedKeySpec对象
		PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(keyBytes);
		//指定加密算法
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORTHM);
		//取私钥匙对象
		PrivateKey privateKey2 = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
		//用私钥对信息生成数字签名
		Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
		signature.initSign(privateKey2);
		signature.update(data);

		return encryptBASE64(signature.sign());
	}



	/**
	 * 校验数字签名
	 * @param data  加密数据
	 * @param publicKey 公钥
	 * @param sign  数字签名
	 * @return
	 * @throws Exception
	 */
	public static boolean verify(byte[] data,String publicKey,String sign)throws Exception{
		//解密公钥
		byte[] keyBytes = decryptBASE64(publicKey);
		//构造X509EncodedKeySpec对象
		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(keyBytes);
		//指定加密算法
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORTHM);
		//取公钥匙对象
		PublicKey publicKey2 = keyFactory.generatePublic(x509EncodedKeySpec);

		Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
		signature.initVerify(publicKey2);
		signature.update(data);
		//验证签名是否正常
		return signature.verify(decryptBASE64(sign));
	}
	
	public static byte[] aesDecrypt(byte[] data, byte rawKeyData[])
            throws GeneralSecurityException {
        // 处理密钥
        //SecretKeySpec key = new SecretKeySpec(rawKeyData, "DES");
        // 解密
        //Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        SecretKeySpec key = new SecretKeySpec(rawKeyData, "AES");   
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS7Padding");  
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(data);
    }
	
	 public static byte[] desEncrypt(byte[] source, byte rawKeyData[])
	            throws GeneralSecurityException {
	        // 处理密钥
	        SecretKeySpec key = new SecretKeySpec(rawKeyData, "AES");
	        // 加密
	        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS7Padding");
	        cipher.init(Cipher.ENCRYPT_MODE, key);
	        return cipher.doFinal(source);
	 }
	
	
	public static byte[] encryptAES256(String content, String password) {  
        try {  
        	
            
            //"AES"：请求的密钥算法的标准名称 -指定加密算法
        	KeyGenerator kgen = KeyGenerator.getInstance("AES");  
            //256：密钥生成参数；securerandom：密钥生成器的随机源  
            SecureRandom securerandom = new SecureRandom(tohash256Deal(password));  
            kgen.init(256, securerandom);
            //生成秘密（对称）密钥  
            SecretKey secretKey = kgen.generateKey();  
            //返回基本编码格式的密钥  
            byte[] enCodeFormat = secretKey.getEncoded();  
            //根据给定的字节数组构造一个密钥。enCodeFormat：密钥内容；"AES"：与给定的密钥内容相关联的密钥算法的名称  
            SecretKeySpec key = new SecretKeySpec(enCodeFormat, "AES");  
            //将提供程序添加到下一个可用位置  
            //Security.addProvider(new BouncyCastleProvider());  
            //创建一个实现指定转换的 Cipher对象，该转换由指定的提供程序提供。  
            //"AES/ECB/PKCS7Padding"：转换的名称；"BC"：提供程序的名称  
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS7Padding");  
  
            cipher.init(Cipher.ENCRYPT_MODE, key);  
            byte[] byteContent = content.getBytes("utf-8");  
            byte[] cryptograph = cipher.doFinal(byteContent);  
            return (new Base64()).encode(cryptograph);
            ///return Base64.encode(cryptograph);  
        } catch (Exception e) {  
            e.printStackTrace();  
        }  
        return null;  
    }  
  
    public static String decryptAES256(byte[] cryptograph, String password) {  
        try {  
            KeyGenerator kgen = KeyGenerator.getInstance("AES");  
            SecureRandom securerandom = new SecureRandom(tohash256Deal(password));  
            kgen.init(256, securerandom);  
            SecretKey secretKey = kgen.generateKey();  
            byte[] enCodeFormat = secretKey.getEncoded();  
            SecretKeySpec key = new SecretKeySpec(enCodeFormat, "AES");  
            //Security.addProvider(new BouncyCastleProvider());  
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS7Padding");  
  
            cipher.init(Cipher.DECRYPT_MODE, key);  
            //byte[] content = cipher.doFinal(Base64.decode(cryptograph)); 
            byte[] content = cipher.doFinal((new Base64()).encode(cryptograph));  
            return new String(content);  
        } catch (Exception e) {  
            e.printStackTrace();  
        }  
        return null;  
    }  
  
    public static String parseByte2HexStr(byte buf[]) {  
        StringBuffer sb = new StringBuffer();  
        for (int i = 0; i < buf.length; i++) {  
            String hex = Integer.toHexString(buf[i] & 0xFF);  
            if (hex.length() == 1) {  
                hex = '0' + hex;  
            }  
            sb.append(hex.toUpperCase());  
        }  
        return sb.toString();  
    }  
  
     
    private static byte[] tohash256Deal(String datastr) {  
        try {  
            MessageDigest digester=MessageDigest.getInstance("SHA-256");  
            digester.update(datastr.getBytes());  
            byte[] hex=digester.digest();  
            return hex;   
        } catch (NoSuchAlgorithmException e) {  
            throw new RuntimeException(e.getMessage());    
        }  
    }  
}

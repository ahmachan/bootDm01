package com.xmage.dm01.utils;

import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.Cipher;

import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;

//对称加密器
public class CipherUtil {

	public static final String CIPHER_INSTANCE_TYPE = "AES/CBC/PKCS5Padding";
	public static final String SECRET_KEY_ALGORITHM = "AES";
	private static final String DEFAULT_ENCODING = "UTF-8";
	private static final int AES_SIZE_BIT = 256;
	
	private String algorithm; // 算法，如DES,AES

    private Key key; // 根据算法生成的密钥

    private KeyGenerator keyGenerator;

    private Cipher cipher;

 

    // 函数进行初始化
    public CipherUtil(String alg) {
    	algorithm = alg;
    	// 生成Cipher对象
    	try {
    		cipher = Cipher.getInstance(algorithm);
    	} catch (NoSuchAlgorithmException e) {
    		// TODO Auto-generated catch block
    		e.printStackTrace();
    	} catch (NoSuchPaddingException e) {
    		// TODO Auto-generated catch block
    		e.printStackTrace();
    	}
    }

   /**
    *  加密:将原文加密成密文
    *  
    * @param plainText 明文
    * @return
    */
    public byte[] encodeCrypt(String plainText) {
       byte[] cipherText = null;
       try {
           // 用密钥加密明文(plainText),生成密文(cipherText)
           cipher.init(Cipher.ENCRYPT_MODE, key); // 操作模式为加密(Cipher.ENCRYPT_MODE),key为密钥
           cipherText = cipher.doFinal(plainText.getBytes());// 得到加密后的字节数组
           //String str = new String(cipherText);
       } catch(Exception e) {
           e.printStackTrace();
       }
       return cipherText;
    }

    /**
     * 解密:函数，将密文解密回原文
     * @param cipherText
     * @param k
     * @return
     */
    public String decodeCrypt(byte[] cipherText, Key k) {
       byte[] sourceText = null;
       try {
           cipher.init(Cipher.DECRYPT_MODE, k); // 操作模式为解密,key为密钥
           sourceText = cipher.doFinal(cipherText);
       } catch(Exception e) {
           e.printStackTrace();
       }
       return new String(sourceText);
    }

    /**
     * 解密:函数，将密文解密回原文
     * @param cipherText
     * @param k
     * @return
     */
    public String decodeCryptWithBase64(String base64Text, Key k) {
       byte[] sourceText = null;
       try {
    	   byte[] cipherText = this.decodeBase64(base64Text);
           cipher.init(Cipher.DECRYPT_MODE, k); // 操作模式为解密,key为密钥
           sourceText = cipher.doFinal(cipherText);
       } catch(Exception e) {
           e.printStackTrace();
       }
       return new String(sourceText);
    }
    
 
    public String encodeBase64(byte[] data){
    	return Base64.getEncoder().encodeToString(data);
    }
    
    public byte[] decodeBase64(String data){
    	return Base64.getDecoder().decode(data);
    }

    /**
     * 生成密钥
     * @return
     */
    public Key initKey() {
       try {
           // 初始化密钥key
           keyGenerator =KeyGenerator.getInstance(SECRET_KEY_ALGORITHM);
           //keyGenerator.init(56);// 选择DES算法,密钥长度必须为56位
           keyGenerator.init(AES_SIZE_BIT);// 选择AES算法,Wrong keysize: must be equal to 128, 192 or 256
           key = keyGenerator.generateKey();// 生成密钥，每次生成的密钥都是不一样的
       } catch(Exception ex) {
           ex.printStackTrace();
       }

       return key;
    }

 

    /**
     * 获取Key类型的密钥
     * @return
     */
    public Key getKey() {
       return key;
    }

    /**
     * 获取Key类型的密钥
     * @param k
     * @return
     */
    public Key getKey(byte[] k) {
       try {
           cipher.init(Cipher.UNWRAP_MODE, key);
           key = cipher.unwrap(k, algorithm,Cipher.DECRYPT_MODE);
       } catch(Exception ex) {
           ex.printStackTrace();
       }
       return key;
    }
 
    /**
     * 获取密钥包装成byte[]类型的
     * @param k
     * @return
     */
    public byte[] getBinaryKey(Key k) {
       byte[] bk = null;
       try {
           cipher.init(Cipher.WRAP_MODE, k);
           bk = cipher.wrap(k);
       } catch(Exception ex) {
           ex.printStackTrace();
       }
       return bk;
    }
}

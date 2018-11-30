package com.xmage.dm01.utils;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.CharEncoding;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;


public class Base64Test {
	
	private static final String CIPHER_INSTANCE_TYPE = "AES/CBC/PKCS5Padding";//DES/CBC/PKCS5Padding
	private static final String SECRET_KEY_ALGORITHM = "AES";//DES
	//private static final String CIPHER_INSTANCE_TYPE = "DES/CBC/PKCS5Padding";
	//private static final String SECRET_KEY_ALGORITHM = "DES";
	private static final String DEFAULT_ENCODING = "UTF-8";
	
	private final static String HEX = "0123456789EFGHIJ";
	//DES:这里IV和myKey必须是8位，超过或者少于8位会报错
	//AES:这里IV和myKey必须是16位，超过或者少于16位会报错
	private final static byte[] IV = { 0, 2, 3,4, 5, 6, 7, 9 };
	public static String myKey = "miller+u";

	private static Base64Test instance = null;
	private static Cipher cipher;
	
    private Base64Test(){
    }
    public static Base64Test getInstance(){
        if (instance==null){
        	instance = new Base64Test();

        	try {
        		cipher = Cipher.getInstance(CIPHER_INSTANCE_TYPE);
        		//instance.createRandChar(cipher.getBlockSize());//16
        		System.out.println("CIPHER IV:");
        	} catch (NoSuchAlgorithmException e) {
        		// TODO Auto-generated catch block
        		e.printStackTrace();
        	} catch (NoSuchPaddingException e) {
        		// TODO Auto-generated catch block
        		e.printStackTrace();
        	}
        }
        return instance;
    }
	
	/**
	 * 
	 * @描述：base64加密
	 * @param plainData
	 * @param secretKey
	 * @return
	 * @throws Exception
	 */
	public String encrypt(String plainData, String secretKey, String secretIv)
			throws Exception {
		secretIv = secretIv.substring(0, 16);
		byte[] ivBytes = transToSizedBytes(secretIv, cipher.getBlockSize());	
		//
		IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);//使用向量iv从而提升加密算法的强度
		//IvParameterSpec ivSpec = new IvParameterSpec(IV, 0, 16);//AES:0-16,DES:0-8
		byte[] keyBytes = transToSizedBytes(secretKey,256/8);
		//keyBytes = Arrays.copyOfRange(keyBytes,0,16);
		SecretKeySpec keySpec = new SecretKeySpec(keyBytes,SECRET_KEY_ALGORITHM);
		
		cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
		byte[] results = cipher.doFinal(plainData.getBytes());
		//return Base64.getEncoder().encodeToString(results);
		String lastStr = String.format("%s%s", new String(results),secretIv);
		System.out.println(lastStr);
		String m64 = Base64.getEncoder().encodeToString(transToSizedBytes(lastStr,64));
		String m32 = Base64.getEncoder().encodeToString(transToSizedBytes(lastStr,32));
		String m16 = Base64.getEncoder().encodeToString(transToSizedBytes(lastStr,16));
		System.out.println(m64);
		System.out.println(m32);
		System.out.println(m16);
		return m64;
	}

	/**
	 * @描述：base64解密
	 * @param base64Data
	 * @param secretKey
	 * @return
	 * @throws Exception
	 */
	public String decrypt(String base64Data, String secretKey, String secretIv) throws Exception {
		byte[] ivBytes = transToSizedBytes(secretIv, cipher.getBlockSize());		
		IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
		//IvParameterSpec ivSpec = new IvParameterSpec(IV, 0, 16);//AES:0-16,DES:0-8
		//byte[] keyBytes = secretKey.getBytes(DEFAULT_ENCODING);
		//keyBytes = Arrays.copyOfRange(keyBytes,0,16);
		byte[] keyBytes = transToSizedBytes(secretKey,256/8);
		SecretKeySpec keySpec = new SecretKeySpec(keyBytes, SECRET_KEY_ALGORITHM);
		
		cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
		byte[] result = cipher.doFinal(Base64.getDecoder().decode(base64Data));
		return new String(result,CharEncoding.UTF_8);
	}
	
	/**
	 * @描述：base64解密
	 * @param base64Data
	 * @param secretKey
	 * @return
	 * @throws Exception
	 */
	public String decryptFormPhp(String base64Data, String secretKey) throws Exception {
		base64Data = urlEncoderText(base64Data);
		byte[] decodeBytes = Base64.getUrlDecoder().decode(base64Data);
		String decodeData = new String(decodeBytes,CharEncoding.UTF_8);
		int totalLength = decodeData.length();
		int originalLength = totalLength - cipher.getBlockSize();
		String origin = decodeData.substring(0, originalLength);
		String secretIv = decodeData.substring(originalLength);
		System.out.println(origin);
		System.out.println(secretIv);
		/**/
		byte[] ivBytes = transToSizedBytes(secretIv, cipher.getBlockSize());		
		IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
		byte[] keyBytes = transToSizedBytes(secretKey,256/8);
		SecretKeySpec keySpec = new SecretKeySpec(keyBytes, SECRET_KEY_ALGORITHM);
		
		cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
		byte[] result = cipher.doFinal(origin.getBytes(CharEncoding.UTF_8));
		return new String(result,CharEncoding.UTF_8);
		
		//return decodeData;
	}
		

	public String createRandChar(int len){
		String sources = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"; // 加上一些字母，就可以生成pc站的验证码了
		Random rand = new Random();
		StringBuffer sb = new StringBuffer();
		int randRang = sources.length();
		for (int j = 0; j < len; j++) 
		{
			sb.append(sources.charAt(rand.nextInt(randRang-1)) + "");
		}
		
		return sb.toString();
	}
	
	//url进行转码
	public String urlEncoderText(String text) {
		try {
			return java.net.URLEncoder.encode(text, "utf-8");
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			//e.printStackTrace();
			return null;
		}
	}
	//url进行解码
	public String urlDecoderText(String text) {
		try {
			return java.net.URLDecoder.decode(text, "utf-8");
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			//e.printStackTrace();
			return null;
		}
	}

	
	private static byte[] transToSizedBytes(String inStr, int size) {
		byte[] bytesIn = null;
		try {
			bytesIn = inStr.getBytes(DEFAULT_ENCODING);
			
			byte[] bytesOut = new byte[size];
			int maxLen = bytesIn.length > size ? size : bytesIn.length;
			System.arraycopy(bytesIn, 0, bytesOut, 0, maxLen);
			bytesOut = new String(bytesOut, CharEncoding.UTF_8).getBytes(CharEncoding.UTF_8);
			return bytesOut;
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			//e.printStackTrace();
			return null;
		}		
	}
	
	public static String java_openssl_encrypt(String data, String pwdKey, String iv) throws Exception {
		int keyBlockSizeBit = 256;
		/*
		int keySizeBit = keyBlockSizeBit/8;//32size
        byte[] keyBytes = new byte[keySizeBit];
        byte[] pwdBytes = pwdKey.getBytes();
        for (int i = 0; i < keySizeBit; i++) {
        	keyBytes[i]=(i < pwdBytes.length?pwdBytes[i]:0);            
        }
        */
        byte[] ivBytes = transToSizedBytes(iv, cipher.getBlockSize());//16
		byte[] keyBytes = transToSizedBytes(pwdKey,keyBlockSizeBit/8);//32
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE,
        		new SecretKeySpec(keyBytes, SECRET_KEY_ALGORITHM),
        		new IvParameterSpec(ivBytes)
        		);

        byte[] dataBytes = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(dataBytes);
    }

}

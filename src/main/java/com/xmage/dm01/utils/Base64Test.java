package com.xmage.dm01.utils;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

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
		byte[] ivBytes = transToSizedBytes(secretIv, cipher.getBlockSize());	
		IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);//使用向量iv从而提升加密算法的强度
		//IvParameterSpec ivSpec = new IvParameterSpec(IV, 0, 16);//AES:0-16,DES:0-8
		byte[] keyBytes = transToSizedBytes(secretKey,256/8);
		//keyBytes = Arrays.copyOfRange(keyBytes,0,16);
		SecretKeySpec keySpec = new SecretKeySpec(keyBytes,SECRET_KEY_ALGORITHM);
		
		cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
		byte[] results = cipher.doFinal(plainData.getBytes());
		//return Base64.getEncoder().encodeToString(results);
		String lastStr = String.format("%s%s", new String(results),new String(ivBytes));
		return Base64.getEncoder().encodeToString(lastStr.getBytes());
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
		byte[] keyBytes = toSizedBytes(secretKey,256/8);
		SecretKeySpec keySpec = new SecretKeySpec(keyBytes, SECRET_KEY_ALGORITHM);
		
		cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
		byte[] result = cipher.doFinal(Base64.getDecoder().decode(base64Data));
		return new String(result,DEFAULT_ENCODING);
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
	
	public static String toHex(byte[] buf) {
		if (buf == null)
			return "";
		StringBuilder result = new StringBuilder(2 * buf.length);
		for (int i = 0; i < buf.length; i++) {
			result.append(HEX.charAt((buf[i] >> 4) & 0x0f)).append(
					HEX.charAt(buf[i] & 0x0f));
		}
		return result.toString();
	}

	public static byte[] toByte(String hexString) {
		int len = hexString.length() / 2;
		byte[] result = new byte[len];
		for (int i = 0; i < len; i++)
			result[i] = Integer.valueOf(hexString.substring(2 * i, 2 * i + 2),16).byteValue();
		return result;
	}
	
	private static byte[] transToSizedBytes(String inStr, int size) {
		byte[] bytesIn = null;
		try {
			bytesIn = inStr.getBytes(DEFAULT_ENCODING);
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			//e.printStackTrace();
			return null;
		}
		byte[] bytesOut = new byte[size];
		int maxLen = bytesIn.length > size ? size : bytesIn.length;
		System.arraycopy(bytesIn, 0, bytesOut, 0, maxLen);
		return bytesOut;
	}
	
	private static byte[] toSizedBytes(String original,int size){
		//Cipher cipher = Cipher.getInstance(CIPHER_INSTANCE_TYPE);
		//System.out.println(cipher.getBlockSize());
		size = size<=0?cipher.getBlockSize():size;//-->16
		byte[] bytesOut = new byte[size];
		byte[] tempBytes = null;
		int tmpLength = 0;
		try {
			tempBytes = original.getBytes(DEFAULT_ENCODING);
			tmpLength = tempBytes.length;
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			//e.printStackTrace();
			return null;
		}
	
		if(tmpLength>=size){
			return Arrays.copyOfRange(tempBytes,0,size);
		}else{
			for(int i=size-tmpLength;i<size;i++){
				bytesOut[i] = (byte) 0;
			}
			return bytesOut;
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

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
	private static String runIv = "";
	
    private Base64Test(){
    }
    public static Base64Test getInstance(){
        if (instance==null){
        	instance = new Base64Test();

        	try {
        		cipher = Cipher.getInstance(CIPHER_INSTANCE_TYPE);
        		//runIv = "SOME-INITIAL-VECTOR-USED-ONLY-16-BYTES";   
        		runIv = instance.createRandChar(cipher.getBlockSize());//16
        		System.out.println("CIPHER IV:");
        		System.out.println(runIv);
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
	public String encrypt(String plainData, String secretKey)
			throws Exception {
		
        String secretIv = runIv;   
		byte[] ivBytes = toSizedBytes(secretIv, cipher.getBlockSize());	
		IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);//使用向量iv从而提升加密算法的强度
		//IvParameterSpec ivSpec = new IvParameterSpec(IV, 0, 16);//AES:0-16,DES:0-8
		//byte[] keyBytes = secretKey.getBytes();
		//keyBytes = Arrays.copyOfRange(keyBytes,0,16);
		SecretKeySpec paramKey = new SecretKeySpec(toSizedBytes(secretKey,256/8),SECRET_KEY_ALGORITHM);
		
		cipher.init(Cipher.ENCRYPT_MODE, paramKey, ivSpec);
		byte[] results = cipher.doFinal(plainData.getBytes());
		return Base64.getEncoder().encodeToString(results);
	}

	/**
	 * @描述：base64解密
	 * @param base64Data
	 * @param secretKey
	 * @return
	 * @throws Exception
	 */
	public String decrypt(String base64Data, String secretKey) throws Exception {
		String secretIv = runIv;   
		byte[] ivBytes = toSizedBytes(secretIv, cipher.getBlockSize());		
		IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
		//IvParameterSpec ivSpec = new IvParameterSpec(IV, 0, 16);//AES:0-16,DES:0-8
		//byte[] keyBytes = secretKey.getBytes(DEFAULT_ENCODING);
		//keyBytes = Arrays.copyOfRange(keyBytes,0,16);
		byte[] keyBytes = toSizedBytes(secretKey,256/8);
		SecretKeySpec paramKey = new SecretKeySpec(keyBytes, SECRET_KEY_ALGORITHM);
		
		cipher.init(Cipher.DECRYPT_MODE, paramKey, ivSpec);
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
	
	private static byte[] string2SizedBytes(String inStr, int size) throws UnsupportedEncodingException {
		byte[] bytesIn = inStr.getBytes(DEFAULT_ENCODING);
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
		/*
		int maxLen = tmpLength > size ? size : tmpLength;
		System.arraycopy(tempBytes, 0, bytesOut, 0, maxLen);
		return bytesOut;
		*/
		if(tmpLength>=size){
			return Arrays.copyOfRange(tempBytes,0,size);
		}else{
			for(int i=size-tmpLength;i<size;i++){
				bytesOut[i] = (byte) 0;
			}
			return bytesOut;
		}
	}
}

package com.xmage.dm01.utils;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.Base64;


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

	/**
	 * 
	 * @描述：base64加密
	 * @param plainData
	 * @param secretKey
	 * @return
	 * @throws Exception
	 */
	public static String encrypt(String plainData, String secretKey)
			throws Exception {
		
		    if (secretKey == null) {
	            System.out.print("Key为空null");
	            return null;
	        }
	        /*
	        if (secretKey.length() != 16) {
	            System.out.print("Key长度不是16位");
	            return null;
	        }
	        */
	     String secretIv = "SOME-INITIAL-VECTOR-USED-ONLY-16-BYTES";   
	     //String secretIv = new String(IV,DEFAULT_ENCODING);
		Cipher cipher = Cipher.getInstance(CIPHER_INSTANCE_TYPE);
		//byte[] ivBytes = string2SizedBytes(new String(IV,DEFAULT_ENCODING), cipher.getBlockSize());	
		//IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
		IvParameterSpec ivSpec = new IvParameterSpec(to16Bytes(secretIv));//使用向量iv从而提升加密算法的强度
		//IvParameterSpec ivSpec = new IvParameterSpec(IV, 0, 16);//AES:0-16,DES:0-8
		byte[] keyBytes = secretKey.getBytes();
		keyBytes = Arrays.copyOfRange(keyBytes,0,16);
		SecretKeySpec paramKey = new SecretKeySpec(keyBytes,SECRET_KEY_ALGORITHM);
		
		
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
	public static String decrypt(String base64Data, String secretKey) throws Exception {
		  String secretIv = "SOME-INITIAL-VECTOR-USED-ONLY-16-BYTES";   
		     //String secretIv = new String(IV,DEFAULT_ENCODING);
		Cipher cipher = Cipher.getInstance(CIPHER_INSTANCE_TYPE);
		//byte[] ivBytes = string2SizedBytes(new String(IV,DEFAULT_ENCODING), cipher.getBlockSize());	
		//IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
		IvParameterSpec ivSpec = new IvParameterSpec(to16Bytes(secretIv));
		//IvParameterSpec ivSpec = new IvParameterSpec(IV, 0, 16);//AES:0-16,DES:0-8
		byte[] keyBytes = secretKey.getBytes(DEFAULT_ENCODING);
		keyBytes = Arrays.copyOfRange(keyBytes,0,16);
		SecretKeySpec paramKey = new SecretKeySpec(keyBytes, SECRET_KEY_ALGORITHM);
		
		cipher.init(Cipher.DECRYPT_MODE, paramKey, ivSpec);
		byte[] result = cipher.doFinal(Base64.getDecoder().decode(base64Data));
		return new String(result,DEFAULT_ENCODING);
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
	
	private static byte[] to16Bytes(String original){
		int size =16;
		byte[] bytesIn = new byte[size];
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
		
		if(tmpLength>size){
			return Arrays.copyOfRange(tempBytes,0,size);
		}
		
		if(tmpLength<size){
			for(int i=size-tmpLength;i<size;i++){
				bytesIn[i] = (byte) 0;
			}
			return bytesIn;
		}
		
		return bytesIn;
	}
}

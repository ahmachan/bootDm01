package com.xmage.dm01.utils;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AesUtil {

	private static final String CIPHER_INSTANCE_TYPE = "AES/CBC/PKCS5Padding";
	private static final String SECRET_KEY_ALGORITHM = "AES";
	private static final String DEFAULT_ENCODING = "UTF-8";
	public static String cipherIv="";


	public static String encrypt(byte[] data, String key, String iv, int keyBlockSizeBit) throws
	NoSuchAlgorithmException, NoSuchPaddingException,
	UnsupportedEncodingException, InvalidKeyException,
	InvalidAlgorithmParameterException,
	IllegalBlockSizeException, BadPaddingException
	{
		//aes-128-cbc,aes-256-cbc
		try {
			cipherIv = iv;
			Cipher ciper = Cipher.getInstance(CIPHER_INSTANCE_TYPE);

			byte[] ivBytes = transToSizedBytes(iv,ciper.getBlockSize());
			IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);// 设置向量
			byte[] keyBytes = transToSizedBytes(key, keyBlockSizeBit/8);
	    	SecretKeySpec keySpec = new SecretKeySpec(keyBytes,SECRET_KEY_ALGORITHM);
			
			ciper.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);                    
			return Base64.getEncoder().encodeToString(ciper.doFinal(data));
		} catch (NoSuchAlgorithmException
				| NoSuchPaddingException
				| InvalidKeyException
				| InvalidAlgorithmParameterException
				| IllegalBlockSizeException
				| BadPaddingException
				e) {
			throw e;
		}
	}
	
	public static String decrypt(String input, String key, int keyBlockSizeBit) throws
	NoSuchAlgorithmException, NoSuchPaddingException,
	UnsupportedEncodingException, InvalidKeyException,
	InvalidAlgorithmParameterException,
	IllegalBlockSizeException, BadPaddingException
	{
		try {
		
			String iv = cipherIv;
			byte[] data  = Base64.getDecoder().decode(input);			
			Cipher ciper = Cipher.getInstance(CIPHER_INSTANCE_TYPE);
			
			byte[] ivBytes = transToSizedBytes(iv,ciper.getBlockSize());
			IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);// 设置向量
			byte[] keyBytes = transToSizedBytes(key, keyBlockSizeBit/8);
	    	SecretKeySpec keySpec = new SecretKeySpec(keyBytes,SECRET_KEY_ALGORITHM);
			
			ciper.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
			return new String(ciper.doFinal(data));
		} catch (NoSuchAlgorithmException
				| NoSuchPaddingException
				| InvalidKeyException
				| InvalidAlgorithmParameterException
				| IllegalBlockSizeException
				| BadPaddingException
				e) {
			throw e;
		}
	}
	
	public static String encryptMixed(byte[] data, String key, String iv, int keyBlockSizeBit) throws
	NoSuchAlgorithmException, NoSuchPaddingException,
	UnsupportedEncodingException, InvalidKeyException,
	InvalidAlgorithmParameterException,
	IllegalBlockSizeException, BadPaddingException
	{
		//aes-128-cbc,aes-256-cbc
		try {
			cipherIv = iv;
			Cipher ciper = Cipher.getInstance(CIPHER_INSTANCE_TYPE);
			
			byte[] ivBytes = transToSizedBytes(iv,ciper.getBlockSize());
			IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);// 设置向量
			byte[] keyBytes = transToSizedBytes(key, keyBlockSizeBit/8);
	    	SecretKeySpec keySpec = new SecretKeySpec(keyBytes,SECRET_KEY_ALGORITHM);
			
			ciper.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
            byte[] lastBytes = ciper.doFinal(data);
            //int size =lastBytes.length + ivBytes.length;
            //byte[] unitBytes =  new byte[size];
            //System.arraycopy(lastBytes, 0, unitBytes, 0, lastBytes.length);
            //System.arraycopy(ivBytes, 0, unitBytes, lastBytes.length, ivBytes.length);
            
            String lastString = Base64.getEncoder().encodeToString(lastBytes);
            String lastIvString = Base64.getEncoder().encodeToString(ivBytes);
            String unitString =String.format("%s%s",
            		new String(lastBytes,DEFAULT_ENCODING),
            		iv
            		);
            byte[] unitBytes = unitString.getBytes(DEFAULT_ENCODING);
			return String.format("%s,%s|base64Len=%d:%d|bytesLen=%d:%d|merge:%s|total:%d", 
					lastString,
            		lastIvString,
            		lastString.length(),
            		lastIvString.length(),
            		lastBytes.length,
            		ivBytes.length,
            		Base64.getEncoder().encodeToString(unitBytes),    
            		unitBytes.length
            		);
		} catch (NoSuchAlgorithmException
				| NoSuchPaddingException
				| InvalidKeyException
				| InvalidAlgorithmParameterException
				| IllegalBlockSizeException
				| BadPaddingException
				e) {
			throw e;
		}
	}

	public static String decryptMixed(String input, String key, int keyBlockSizeBit) throws
	NoSuchAlgorithmException, NoSuchPaddingException,
	UnsupportedEncodingException, InvalidKeyException,
	InvalidAlgorithmParameterException,
	IllegalBlockSizeException, BadPaddingException
	{
		try {
		
			String ivStr = "";//cipherIv;
			String inputStr = "";
			Cipher ciper = Cipher.getInstance(CIPHER_INSTANCE_TYPE);
			
			byte[] inputBytes = Base64.getDecoder().decode(input);
			int ivBytesLength = ciper.getBlockSize();
			int inputBytesLength = inputBytes.length;
			int out1len = inputBytesLength-ivBytesLength;
			/*
			byte[] bytesOut1 = new byte[out1len];
			byte[] bytesOut2 = new byte[ivBytesLength];			
			System.arraycopy(inputBytes, out1len, bytesOut2, 0, ivBytesLength);
			System.arraycopy(inputBytes, 0, bytesOut1, 0, out1len);
			
			byte[] tempIv = Base64.getDecoder().decode(new String(bytesOut2,DEFAULT_ENCODING));
			ivStr = new String(tempIv,DEFAULT_ENCODING);
			System.out.println(ivStr);
			
			inputStr = new String(bytesOut1,DEFAULT_ENCODING);
			byte[] data  = Base64.getDecoder().decode(inputStr);
			System.out.println(new String(data,DEFAULT_ENCODING));
			*/
			/*
			byte[] ivBytes = transToSizedBytes(ivStr,ciper.getBlockSize());
			IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);// 设置向量
			byte[] keyBytes = transToSizedBytes(key, keyBlockSizeBit/8);
	    	SecretKeySpec keySpec = new SecretKeySpec(keyBytes,SECRET_KEY_ALGORITHM);
			
			ciper.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
			return new String(ciper.doFinal(data));
			*/		
			return String.format("input-bytes=%d:%d", inputBytesLength,out1len);
		} catch (NoSuchAlgorithmException
				| NoSuchPaddingException
				//| InvalidKeyException
				//| InvalidAlgorithmParameterException
				//| IllegalBlockSizeException
				//| BadPaddingException
				e) {
			throw e;
		}
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
}

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
			//iv = iv.substring(0, 16);
			cipherIv = iv;
			Cipher ciper = Cipher.getInstance(CIPHER_INSTANCE_TYPE);
			byte[] ivBytes = string2SizedBytes(iv, ciper.getBlockSize());
			byte[] keyBytes = string2SizedBytes(key, keyBlockSizeBit/8);


			SecretKeySpec keySpec = new SecretKeySpec(keyBytes,SECRET_KEY_ALGORITHM);
			IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);

			ciper.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
             /* 
            String lastRes = String.format("%s%s", 
            		Base64.getEncoder().encodeToString(ciper.doFinal(data)),
            		Base64.getEncoder().encodeToString(iv.getBytes("UTF-8"))
            		);*/
                   
			return Base64.getEncoder().encodeToString(ciper.doFinal(data));
		} catch (NoSuchAlgorithmException
				| NoSuchPaddingException
				| UnsupportedEncodingException
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
			/*
			System.out.println(input);
			iv = input.substring(input.length()- 16);
			System.out.println(iv);
			input = input.substring(0, input.length()-16);
			System.out.println(input);
			System.out.println(input.length());
			*/
			
			String iv = cipherIv;
			byte[] data  = Base64.getDecoder().decode(input);			
			Cipher ciper = Cipher.getInstance(CIPHER_INSTANCE_TYPE);
			byte[] ivBytes = string2SizedBytes(iv, ciper.getBlockSize());
			byte[] keyBytes = string2SizedBytes(key, keyBlockSizeBit/8);

			SecretKeySpec keySpec = new SecretKeySpec(keyBytes,SECRET_KEY_ALGORITHM);
			IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);

			ciper.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

			return new String(ciper.doFinal(data));
		} catch (NoSuchAlgorithmException
				| NoSuchPaddingException
				| UnsupportedEncodingException
				| InvalidKeyException
				| InvalidAlgorithmParameterException
				| IllegalBlockSizeException
				| BadPaddingException
				e) {
			throw e;
		}
	}

	private static byte[] string2SizedBytes(String in, int size) throws UnsupportedEncodingException {
		byte[] bytesIn = in.getBytes(DEFAULT_ENCODING);
		byte[] out = new byte[size];
		int maxLen = bytesIn.length > size ? size : bytesIn.length;
		System.arraycopy(bytesIn, 0, out, 0, maxLen);
		return out;
	}
}

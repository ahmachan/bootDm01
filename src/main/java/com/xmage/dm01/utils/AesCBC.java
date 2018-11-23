package com.xmage.dm01.utils;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.security.GeneralSecurityException;
import java.util.Arrays;
//java7,  Apache 提供了 Base64 的实现
//Java 8，那么就不需要再选用第三方的实现了，在 java.util 包中已经包含了 Base64 的处理
//import org.apache.commons.codec.binary.Base64;
import java.util.Base64;
/**
* AES 是一种可逆加密算法，对用户的敏感信息加密处理
* 对原始数据进行AES加密后，在进行Base64编码转化；
* 正确
*/
public class AesCBC {
/*已确认
* 加密用的Key 可以用26个字母和数字组成
* 此处使用AES-128-CBC加密模式，key需要为16位。
*/
    private static AesCBC instance=null;
    //private static 
    private AesCBC(){

    }
    public static AesCBC getInstance(){
        if (instance==null)
            instance= new AesCBC();
        return instance;
    }
    
    // 加密
    public String encrypt(String sSrc, String sKey) throws Exception {
        if (sKey == null) {
            System.out.print("Key为空null");
            return null;
        }
        // 判断Key是否为16位
        if (sKey.length() != 16) {
            System.out.print("Key长度不是16位");
            return null;
        }
        byte[] raw = sKey.getBytes();
        SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");//"算法/模式/补码方式"
        IvParameterSpec iv = new IvParameterSpec("0102030405060708".getBytes());//使用CBC模式，需要一个向量iv，可增加加密算法的强度
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
        byte[] encrypted = cipher.doFinal(sSrc.getBytes());
 
        return Base64.getEncoder().encodeToString(encrypted);//java8
        //return (new Base64()).encodeToString(encrypted);//java7 apache
    }
 
    // 解密
    public String decrypt(String sSrc, String sKey) throws Exception {
        try {
            // 判断Key是否正确
            if (sKey == null) {
                System.out.print("Key为空null");
                return null;
            }
            // 判断Key是否为16位
            if (sKey.length() != 16) {
                System.out.print("Key长度不是16位");
                return null;
            }
            byte[] raw = sKey.getBytes("ASCII");
            SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            IvParameterSpec iv = new IvParameterSpec("0102030405060708"
                    .getBytes());
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
            //先用base64解密
            //byte[] encrypted1 = Base64.decodeBase64(sSrc);//java7 apache
            byte[] encrypted1 = Base64.getDecoder().decode(sSrc);//java8
            try {
                byte[] original = cipher.doFinal(encrypted1);
                String originalString = new String(original);
                return originalString;
            } catch (Exception e) {
                System.out.println(e.toString());
                return null;
            }
        } catch (Exception ex) {
            System.out.println(ex.toString());
            return null;
        }
    }
    
    public String decryptWith64Bit(byte key[], String encrypted)
            throws GeneralSecurityException {
        /*
         * if (key.length != 32 || key.length != 48 || key.length != 64) { throw
         * new IllegalArgumentException("Invalid key size."); }
         */
    
    	
        byte[] ciphertextBytes = Base64.getDecoder().decode(encrypted.getBytes());//java8
        IvParameterSpec iv = new IvParameterSpec(ciphertextBytes, 0, 16);

        ciphertextBytes = Arrays.copyOfRange(ciphertextBytes, 16,ciphertextBytes.length);

        SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
        byte[] original = cipher.doFinal(ciphertextBytes);

        // Remove zero bytes at the end.
        int lastLength = original.length;
        for (int i = original.length - 1; i > original.length - 16; i--) {
            if (original[i] == (byte) 0) {
                lastLength--;
            } else {
                break;
            }
        }

        return new String(original, 0, lastLength); 

    }

}


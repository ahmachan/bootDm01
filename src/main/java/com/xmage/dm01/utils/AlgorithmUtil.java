package com.xmage.dm01.utils;

import java.io.UnsupportedEncodingException;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AlgorithmUtil {

    private static final String CIPHER_INSTANCE_TYPE = "AES/CBC/PKCS5Padding";
	private static final String SECRET_KEY_ALGORITHM = "AES";
	private static final String DEFAULT_ENCODING = "UTF-8";
	private static final int BLOCK_SIZE_BIT = 256;

    /**
     * 将二进制转换成16进制
     *
     * @param buf
     * @return
     */
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

    /**
     * 将16进制转换为二进制
     *
     * @param hexStr
     * @return
     */
    public static byte[] parseHexStr2Byte(String hexStr) {
        if (hexStr.length() < 1)
            return null;
        byte[] result = new byte[hexStr.length() / 2];
        for (int i = 0; i < hexStr.length() / 2; i++) {
            int high = Integer.parseInt(hexStr.substring(i * 2, i * 2 + 1), 16);
            int low = Integer.parseInt(hexStr.substring(i * 2 + 1, i * 2 + 2), 16);
            result[i] = (byte) (high * 16 + low);
        }
        return result;
    }
    
    private static byte[] string2SizedBytes(String inStr, int size) throws Exception {
		byte[] bytesIn = inStr.getBytes(DEFAULT_ENCODING);
		byte[] bytesOut = new byte[size];
		int maxLen = bytesIn.length > size ? size : bytesIn.length;
		System.arraycopy(bytesIn, 0, bytesOut, 0, maxLen);
		return bytesOut;
	}

    /**
     * 生成密钥
     * 自动生成base64 编码后的AES128位密钥
     *
     * @throws //NoSuchAlgorithmException
     * @throws //UnsupportedEncodingException
     */
    public static String getAESKey() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance(CIPHER_INSTANCE_TYPE);
        //kg.init(128);//要生成多少位，只需要修改这里即可128, 192或256
        kg.init(BLOCK_SIZE_BIT);
        SecretKey sk = kg.generateKey();
        byte[] b = sk.getEncoded();
        return parseByte2HexStr(b);//fixed java7
        //return new String(b);
    }

    /**
     * AES 加密
     *
     * @param base64Key base64编码后的 AES key
     * @param text      待加密的字符串
     * @return 加密后的字符串
     * @throws Exception
     */
    public static String getAESEncode(String base64Key, String orignData) throws Exception {
    	byte[] key = parseHexStr2Byte(base64Key);//fixed java7
        //byte[] key = base64Key.getBytes(DEFAULT_ENCODING);
        SecretKeySpec sKeySpec = new SecretKeySpec(key, SECRET_KEY_ALGORITHM);
		IvParameterSpec ivSpec = genIvParams();       

        Cipher cipher = Cipher.getInstance(CIPHER_INSTANCE_TYPE);
        cipher.init(Cipher.ENCRYPT_MODE, sKeySpec,ivSpec);        
        byte[] data = cipher.doFinal(orignData.getBytes(DEFAULT_ENCODING));
        return Base64.getEncoder().encodeToString(data);
    }
    
    private static IvParameterSpec genIvParams() throws Exception {
    	//byte[] aesIv = { 0x12, 0x34, 0x56, 0x78, (byte) 0x90, (byte) 0xAB,(byte) 0xCD, (byte) 0xEF };// 缓冲区
		byte[] aesIv ="1234567890123456".getBytes(DEFAULT_ENCODING);
		IvParameterSpec iv = new IvParameterSpec(aesIv);// 设置向量
    	return iv;
    }

    /**
     * AES解密
     *
     * @param base64Key    base64编码后的 AES key
     * @param base64Data   待解密的字符串
     * @return 解密后的byte[] 数组
     * @throws Exception
     */
    public static byte[] getAESDecode(String base64Key, String base64Data) throws Exception {
        byte[] key = parseHexStr2Byte(base64Key);//fixed java7
        //byte[] key = base64Key.getBytes(DEFAULT_ENCODING);
        byte[] data  = Base64.getDecoder().decode(base64Data);			
        SecretKeySpec sKeySpec = new SecretKeySpec(key, SECRET_KEY_ALGORITHM);
		IvParameterSpec ivSpec = genIvParams();
		
        Cipher cipher = Cipher.getInstance(CIPHER_INSTANCE_TYPE);
        cipher.init(Cipher.DECRYPT_MODE, sKeySpec,ivSpec);        
        return cipher.doFinal(data);
    }

}

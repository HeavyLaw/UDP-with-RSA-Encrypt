package com.heavylaw.utils;

import java.io.File;
import java.util.*;
import javax.crypto.Cipher;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Java RSA Utils
 *
 */
public class RSAUtils {

    private final static int KEY_SIZE = 1024;
    private static Map<Integer, String> keyMap = new HashMap<Integer, String>();

    public static void genKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(KEY_SIZE, new SecureRandom());
        KeyPair keyPair = keyPairGen.generateKeyPair();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        String publicKeyString = Base64.getEncoder().encodeToString(publicKey.getEncoded());
        String privateKeyString = Base64.getEncoder().encodeToString(privateKey.getEncoded());

        keyMap.put(0, publicKeyString);
        keyMap.put(1, privateKeyString);
    }

    public static String encrypt(String otp, String publicKey) throws Exception {

        byte[] decoded = Base64.getDecoder().decode(publicKey);
        RSAPublicKey pubKey = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(decoded));

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        String ciphertext = Base64.getEncoder().encodeToString(cipher.doFinal(otp.getBytes("UTF-8")));
        return ciphertext;
    }

    public static String decrypt(String ciphertext, String privateKey) throws Exception {

        byte[] inputByte = Base64.getDecoder().decode(ciphertext);
        byte[] decoded = Base64.getDecoder().decode(privateKey);
        RSAPrivateKey priKey = (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(decoded));

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, priKey);
        String otp = new String(cipher.doFinal(inputByte));
        return otp;
    }

    public static String sha1(String input) throws NoSuchAlgorithmException {
        MessageDigest mDigest = MessageDigest.getInstance("SHA1");
        byte[] result = mDigest.digest(input.getBytes());
        StringBuilder sb = new StringBuilder();
        for (byte b : result) {
            sb.append(Integer.toString((b & 0xff) + 0x100, 16).substring(1));
        }

        return sb.toString();
    }

    public static String getRandomString() {
        StringBuilder NA = new StringBuilder();
        for (int i = 0; i < 4; i++) {
            UUID uuid = UUID.randomUUID();
            String str = uuid.toString();
            String temp = str.substring(0, 8) + str.substring(9, 13) + str.substring(14, 18) + str.substring(19, 23) + str.substring(24);
            NA.append(temp);
        }
        return NA.toString();
    }

    public static void main(String[] args) throws Exception {
        genKeyPair();
        IOUtils.writeFile(("Bob," + sha1("12345abc")), new File("src/com/heavylaw/Alice/password.txt"));
        IOUtils.writeFile((keyMap.get(0) + '\n' + keyMap.get(1)), new File("src/com/heavylaw/Alice/key.pem"));
        String hashPk = sha1(keyMap.get(0));
        System.out.println("Hash public key:" + hashPk);
        IOUtils.writeFile(hashPk, new File("src/com/heavylaw/Bob/key.pem"));

    }
}
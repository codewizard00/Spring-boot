/* eslint-disable */
package com.example.demo;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserApplication {

    @GetMapping("/hello")
    public String Niraj(){
        return "Hello World";
    }
    
    @PostMapping("/encryption")
    public String Encryption(@RequestBody String message)throws GeneralSecurityException, UnsupportedEncodingException {
        
        String key ="fd8fe23dce7b440eb976eeb7c0351ebd";
        // public static final String ALGORITHM = "AES/CBC/PKCS5Padding";
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] messageArr = message.getBytes();
        byte[] keyparam=key.getBytes();
        SecretKeySpec keySpec = new SecretKeySpec(keyparam, "AES");
        byte[] ivParams = new byte[16];
        byte[] encoded = new byte[messageArr.length + 16];
        System.arraycopy(ivParams,0,encoded,0,16);
        System.arraycopy(messageArr, 0, encoded, 16, messageArr.length);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(ivParams));
        byte[] encryptedBytes = cipher.doFinal(encoded);
        encryptedBytes = Base64.getEncoder().encode(encryptedBytes);
        System.out.println(encryptedBytes);
        return new String(encryptedBytes);
    }
    
    @PostMapping("/decryption")
    public String Decryption(@RequestBody String entity) throws GeneralSecurityException, UnsupportedEncodingException {
    String key ="fd8fe23dce7b440eb976eeb7c0351ebd";
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    byte[] keyparam=key.getBytes();
    SecretKeySpec keySpec = new SecretKeySpec(keyparam, "AES");
    byte[] encoded = entity.getBytes();
    encoded = Base64.getDecoder().decode(encoded);
    byte[] decodedEncrypted = new byte[encoded.length-16];
    System.arraycopy(encoded, 16, decodedEncrypted, 0,encoded.length-16);
    byte[] ivParams = new byte[16];
    System.arraycopy(encoded,0, ivParams,0, ivParams.length);
    cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(ivParams));
    byte[] decryptedBytes = cipher.doFinal(decodedEncrypted);
    return new String(decryptedBytes);
    }
}

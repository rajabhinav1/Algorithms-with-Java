// 1. RSA Key Generation

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

public class RSAKeyGenerationExample {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        // Generate RSA key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048); // Key size in bits
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // Access RSA public and private keys
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        // Print key details
        System.out.println("Public Key: " + publicKey);
        System.out.println("Private Key: " + privateKey);
    }
}
// 2. RSA Encryption and Decryption

import javax.crypto.Cipher;

public class RSAEncryptionExample {
    public static void main(String[] args) throws Exception {
        String message = "Hello, RSA!";
        
        // Encrypt message using RSA public key
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());
        String encryptedMessage = Base64.getEncoder().encodeToString(encryptedBytes);
        
        // Decrypt message using RSA private key
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
        String decryptedMessage = new String(decryptedBytes);
        
        System.out.println("Encrypted Message: " + encryptedMessage);
        System.out.println("Decrypted Message: " + decryptedMessage);
    }
}
// 3. Digital Signatures with RSA:
import java.security.Signature;

public class RSADigitalSignatureExample {
    public static void main(String[] args) throws Exception {
        String message = "Hello, RSA Signature!";
        
        // Generate signature using RSA private key
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(message.getBytes());
        byte[] signatureBytes = signature.sign();
        
        // Verify signature using RSA public key
        signature.initVerify(publicKey);
        signature.update(message.getBytes());
        boolean isVerified = signature.verify(signatureBytes);
        
        System.out.println("Signature Verified: " + isVerified);
    }
}

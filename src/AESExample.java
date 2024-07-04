import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class AESExample {

    private static final String key = "aesEncryptionKey"; //16Byte == 128bit
    private static final String initVector = "encryptionIntVec"; //16Byte
    private static SecretKeySpec secretKeySpec;
    private static IvParameterSpec ivParameterSpec;

    // AES 알고리즘을 사용하여 비밀키 생성
    private static void generateKey() throws Exception {
        ivParameterSpec = new IvParameterSpec(initVector.getBytes("UTF-8"));
        secretKeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");
    }

    // 비밀키를 Base64로 인코딩하여 문자열로 반환
    private static String getKeyAsString(SecretKeySpec secretKey) {
        byte[] encoded = secretKey.getEncoded();
        return Base64.getEncoder().encodeToString(encoded);
    }

    // 문자열을 AES로 암호화
    private static String encrypt(String plainText) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    // 암호화된 문자열을 AES로 복호화
    private static String decrypt(String encryptedText) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
        byte[] decodedBytes = Base64.getDecoder().decode(encryptedText);
        byte[] decryptedBytes = cipher.doFinal(decodedBytes);
        return new String(decryptedBytes, "UTF-8");
    }

    public static void main(String[] args) {
        try {
            // 비밀키 생성
            generateKey();

            // 비밀키 내용을 출력
            String keyString = getKeyAsString(secretKeySpec);
            System.out.println("Secret Key: " + keyString);

            // 원본 문자열
            String originalString = "이것은 평문 입니다.";
            System.out.println("Original String: " + originalString);

            // 암호화
            String encryptedString = encrypt(originalString);
            System.out.println("Encrypted String: " + encryptedString);

            // 복호화
            String decryptedString = decrypt(encryptedString);
            System.out.println("Decrypted String: " + decryptedString);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

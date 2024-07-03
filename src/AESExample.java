import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.util.Base64;

public class AESExample {

    // AES 알고리즘을 사용하여 비밀키 생성
    private static SecretKey generateKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128); // 128, 192, 256 비트 중 선택 가능
        return keyGen.generateKey();
    }

    // 비밀키를 Base64로 인코딩하여 문자열로 반환
    private static String getKeyAsString(SecretKey secretKey) {
        byte[] encoded = secretKey.getEncoded();
        return Base64.getEncoder().encodeToString(encoded);
    }

    // 문자열을 AES로 암호화
    private static String encrypt(String plainText, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    // 암호화된 문자열을 AES로 복호화
    private static String decrypt(String encryptedText, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decodedBytes = Base64.getDecoder().decode(encryptedText);
        byte[] decryptedBytes = cipher.doFinal(decodedBytes);
        return new String(decryptedBytes, "UTF-8");
    }

    public static void main(String[] args) {
        try {
            // 비밀키 생성
            SecretKey secretKey = generateKey();

            // 비밀키 내용을 출력
            String keyString = getKeyAsString(secretKey);
            System.out.println("Secret Key: " + keyString);

            // 원본 문자열
            String originalString = "이것은 평문 입니다.";
            System.out.println("Original String: " + originalString);

            // 암호화
            String encryptedString = encrypt(originalString, secretKey);
            System.out.println("Encrypted String: " + encryptedString);

            // 복호화
            String decryptedString = decrypt(encryptedString, secretKey);
            System.out.println("Decrypted String: " + decryptedString);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

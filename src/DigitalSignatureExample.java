import java.security.*;
import java.util.Base64;

public class DigitalSignatureExample {

    public static void main(String[] args) {
        try {
            // 키 쌍 생성
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            KeyPair keyPair = keyGen.generateKeyPair();
            PrivateKey privateKey = keyPair.getPrivate();
            PublicKey publicKey = keyPair.getPublic();

            // 서명할 데이터
            String data = "이것은 내가 작성한 문서 입니다.";
            byte[] dataBytes = data.getBytes("UTF-8");

            // 서명 생성
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            signature.update(dataBytes);
            byte[] digitalSignature = signature.sign();
            String encodedSignature = Base64.getEncoder().encodeToString(digitalSignature);

            System.out.println("Original Data: " + data);
            System.out.println("Digital Signature: " + encodedSignature);

            // 서명 검증
            Signature signatureVerify = Signature.getInstance("SHA256withRSA");
            signatureVerify.initVerify(publicKey);
            signatureVerify.update(dataBytes);
            boolean isVerified = signatureVerify.verify(digitalSignature);

            System.out.println("Signature Verified: " + isVerified);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

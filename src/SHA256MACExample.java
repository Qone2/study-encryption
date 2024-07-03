import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class SHA256MACExample {
    public static void main(String[] args) {
        String message1 = "This is  a sample message";
        String message2 = "This is a  sample message";
        String message3 = new String("This is  a sample message");
        String secretKey = "supersecretkey";

        try {
            // 비밀 키를 사용하여 HMAC-SHA-256 Mac 객체 생성
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getBytes(), "HmacSHA256");
            mac.init(secretKeySpec);

            // 메시지 인증 코드 생성
            byte[] macData1 = mac.doFinal(message1.getBytes());
            byte[] macData2 = mac.doFinal(message2.getBytes());
            byte[] macData3 = mac.doFinal(message3.getBytes());

            // 생성된 MAC을 Base64로 인코딩하여 출력
            System.out.println("MAC1: " + Base64.getEncoder().encodeToString(macData1));
            System.out.println("MAC2: " + Base64.getEncoder().encodeToString(macData2));
            System.out.println("MAC3: " + Base64.getEncoder().encodeToString(macData3));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

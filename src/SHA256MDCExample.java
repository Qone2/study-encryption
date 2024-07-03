import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class SHA256MDCExample {
    public static void main(String[] args) {
        String message1 = "This is  a sample message";
        String message2 = "This is a sample  message";
        String message3 = new String("This is  a sample message");
        try {
            // SHA-256 MessageDigest 객체 생성
            MessageDigest md = MessageDigest.getInstance("SHA-256");

            // 메시지 다이제스트 생성
            byte[] digest1 = md.digest(message1.getBytes());
            byte[] digest2 = md.digest(message2.getBytes());
            byte[] digest3 = md.digest(message3.getBytes());

            // 생성된 다이제스트를 16진수로 변환하여 출력
            System.out.println("MDC1: " + bytesToHex(digest1));
            System.out.println("MDC2: " + bytesToHex(digest2));
            System.out.println("MDC3: " + bytesToHex(digest3));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    // 바이트 배열을 16진수 문자열로 변환하는 헬퍼 메소드
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}

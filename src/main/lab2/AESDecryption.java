//isaac kariithi Nyoro SCT211-0506/2021
//LAB WORK 2



import javax.crypto.Cipher;
        import javax.crypto.spec.IvParameterSpec;
        import javax.crypto.spec.SecretKeySpec;
        import java.math.BigInteger;
        import java.util.Arrays;
        import java.util.Base64;

public class AESDecryption {

    public static void main(String[] args) throws Exception {
        int blockSize = 16;

        System.out.println("\nCBC decryption:");
        String q1 = cbcDecrypt("140b41b22a29beb4061bda66b6747e14",
                "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81");
        String q2 = cbcDecrypt("140b41b22a29beb4061bda66b6747e14",
                "5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253");

        System.out.println("\nCTR decryption:");
        String q3 = ctrDecrypt("36f18357be4dbd77f050515c73fcf9f2",
                "69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329");
        String q4 = ctrDecrypt("36f18357be4dbd77f050515c73fcf9f2",
                "770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451");

        System.out.println("\nAnswers:");
        System.out.println("Q1. " + q1);
        System.out.println("Q2. " + q2);
        System.out.println("Q3. " + q3);
        System.out.println("Q4. " + q4);
    }

    public static String cbcDecrypt(String keyHex, String cipherHex) throws Exception {
        byte[] key = hexStringToByteArray(keyHex);
        byte[] cipherBytes = hexStringToByteArray(cipherHex);

        byte[] iv = Arrays.copyOfRange(cipherBytes, 0, 16);
        byte[] actualCipher = Arrays.copyOfRange(cipherBytes, 16, cipherBytes.length);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");
        cipher.init(Cipher.DECRYPT_MODE, skeySpec, new IvParameterSpec(iv));

        byte[] plaintext = cipher.doFinal(actualCipher);
        return new String(plaintext);
    }

    public static String ctrDecrypt(String keyHex, String cipherHex) throws Exception {
        byte[] key = hexStringToByteArray(keyHex);
        byte[] cipherBytes = hexStringToByteArray(cipherHex);

        byte[] iv = Arrays.copyOfRange(cipherBytes, 0, 16);
        byte[] ciphertext = Arrays.copyOfRange(cipherBytes, 16, cipherBytes.length);

        byte[] plaintext = new byte[ciphertext.length];
        int blockCount = (int) Math.ceil(ciphertext.length / 16.0);

        for (int i = 0; i < blockCount; i++) {
            byte[] counterBlock = incrementCounter(iv, i);
            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
            SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
            byte[] keystream = cipher.doFinal(counterBlock);

            for (int j = 0; j < 16 && i * 16 + j < ciphertext.length; j++) {
                plaintext[i * 16 + j] = (byte) (keystream[j] ^ ciphertext[i * 16 + j]);
            }
        }

        return new String(plaintext);
    }

    private static byte[] incrementCounter(byte[] iv, int blockIndex) {
        BigInteger counter = new BigInteger(1, iv);
        counter = counter.add(BigInteger.valueOf(blockIndex));
        byte[] counterBytes = counter.toByteArray();

        byte[] block = new byte[16];
        int start = Math.max(counterBytes.length - 16, 0);
        int length = Math.min(16, counterBytes.length);
        System.arraycopy(counterBytes, start, block, 16 - length, length);

        return block;
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] out = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            out[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return out;
    }
}

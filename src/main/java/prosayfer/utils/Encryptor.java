package prosayfer.utils;

import org.apache.commons.codec.digest.DigestUtils;
import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import org.springframework.security.crypto.keygen.KeyGenerators;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;

public class Encryptor {
  private static final String STRING_MODE = "STRING_MODE";
  private static final String FILE_MODE = "FILE_MODE";
  private static final String CHECK_MODE = "CHECK_MODE";
  private static final String CIPHER_MODE = "CIPHER_MODE";
  private static final int SEED_BYTES = 32;

  private static SecureRandom random = new SecureRandom();

  private static String generateSalt() {
    byte[] seed = random.generateSeed(SEED_BYTES);
    return DigestUtils.sha256Hex(new String(seed)).substring(0, 16);
  }

  private static boolean checkPassword(String password, String hash, String salt) {
    if (password == null || hash == null || salt == null) {
      return false;
    }
    return DigestUtils.sha256Hex(password + salt).equalsIgnoreCase(hash);
  }

  private static void stringEncrypt(String plaintext) {
    String salt = generateSalt();
    String hash = DigestUtils.sha256Hex(plaintext + salt);
    System.out.println("Salt: " + salt + "\nhash: " + hash);
  }

  private static void fileEncrypt(String filepath) {
    StringBuilder result = new StringBuilder();

    try (BufferedReader reader = Files.newBufferedReader(Paths.get(filepath))) {
      String tmp;

      while ((tmp = reader.readLine()) != null) {
        if (tmp.startsWith("#")) {
          result.append(tmp + System.lineSeparator());
          continue;
        }
        String[] sections = tmp.split("\\.");

        for (String section : sections) {
          if (section.startsWith("userpassword=")) {
            String plaintext = section.substring(13);
            String salt = generateSalt();
            String hash = DigestUtils.sha256Hex(plaintext + salt);
            String ciphertext = hash + ":" + salt;
            tmp = tmp.replace(plaintext, ciphertext);
          }
        }
        result.append(tmp + System.lineSeparator());
      }
    } catch (IOException e) {
      System.out.println("Wrong filepath!");
    }

    try (BufferedWriter writer = Files.newBufferedWriter(Paths.get(filepath))) {
      writer.write(result.toString());
    } catch (IOException e) {
      System.out.println("Wrong filepath!");
    }
  }

  private static void cipher(String plaintext) throws Exception {
    String password = generateSalt();
    String salt = KeyGenerators.string().generateKey();
    String key = password + ":" + salt;

    TextEncryptor encryptor = Encryptors.text(password, salt);
    String ciphertext = encryptor.encrypt(plaintext);

    encryptor = Encryptors.text(password, salt);
    if (plaintext.equals(encryptor.decrypt(ciphertext))) {
      System.out.println("Key: " + key + "\nEncrypted password: " + ciphertext);
    } else {
      System.out.println("Error");
    }
  }

  public static void main(String[] args) throws Exception {
    System.out.print(
        "> Three modes available: "
            + STRING_MODE
            + ", "
            + FILE_MODE
            + ", "
            + CHECK_MODE
            + ", "
            + CIPHER_MODE
            + "\n"
            + "> Choose one and type it (case ignored)\n"
            + "> ");

    try (BufferedReader reader = new BufferedReader(new InputStreamReader(System.in))) {
      String mode = reader.readLine();
      if (mode.equalsIgnoreCase(STRING_MODE)) {
        System.out.print("> Password:\n> ");
        String password = reader.readLine();
        stringEncrypt(password);
      } else if (mode.equalsIgnoreCase(FILE_MODE)) {
        System.out.print("> Filepath:\n> ");
        String filepath = reader.readLine().replace("\\", "/").replace("\"", "");
        fileEncrypt(filepath);
      } else if (mode.equalsIgnoreCase(CHECK_MODE)) {
        System.out.print("> Password:\n> ");
        String password = reader.readLine();

        System.out.print("> Hash:\n> ");
        String hash = reader.readLine();

        System.out.print("> Salt:\n> ");
        String salt = reader.readLine();

        System.out.println(checkPassword(password, hash, salt));
      } else if (mode.equalsIgnoreCase(CIPHER_MODE)) {
        System.out.print("> Password:\n> ");
        String password = reader.readLine();
        cipher(password);
      } else {
        System.out.println("Wrong mode!");
      }
    } catch (Exception e) {
      e.printStackTrace();
    }
  }
}

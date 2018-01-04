//package cipher;
  
import java.io.FileInputStream;
import java.security.cert.Certificate;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.KeyStore;
import java.security.PrivateKey;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.CipherInputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class cifra {
  
    public static void main(String[] args) throws Exception {
  
    //gerar uma chave aleatoria para utilizar com o AES
    KeyGenerator kg = KeyGenerator.getInstance("AES");
    kg.init(128);
    SecretKey key = kg.generateKey();
  
    // tem o codigo do algoritmo de cifra
    Cipher c = Cipher.getInstance("AES");
    c.init(Cipher.ENCRYPT_MODE, key);
  
    FileInputStream fis;
    FileOutputStream fos;
    CipherOutputStream cos;
      
    fis = new FileInputStream("bd_project.docx");
    fos = new FileOutputStream("a.cif");
  
    cos = new CipherOutputStream(fos, c);
    byte[] b = new byte[16];  
    int i = fis.read(b);
    while (i != -1) {
        cos.write(b, 0, i);
        i = fis.read(b);
    }
    cos.close();
    fis.close();
    fos.close();
   
    //DIFFERENT FROM SYMM. Now we also perform Asymmetric Encryption with RSA
    FileInputStream kfile = new FileInputStream(System.getenv("SAMPLE_JKS_FILE"));  //keystore               
    KeyStore kstore = KeyStore.getInstance("JKS");

    //password
    kstore.load(kfile, System.getenv("SAMPLE_JKS_PASSWORD").toCharArray());
    Certificate cert = kstore.getCertificate(System.getenv("SAMPLE_JKS_USER"));  //alias do utilizador
  
    Cipher c2 = Cipher.getInstance("RSA");
    c2.init(Cipher.WRAP_MODE, cert.getPublicKey());
    
    // Also different. we write a wrapped key using RSA
    FileOutputStream kos = new FileOutputStream("a.key");
    byte[] wrapped = c2.wrap(key);
    kos.write(wrapped);
    kos.close();
    kfile.close();
    }
}

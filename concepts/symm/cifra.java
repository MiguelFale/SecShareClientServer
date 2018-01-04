//package cipher;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.CipherInputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class cifra {

    public static void main(String[] args) throws Exception {

    //Generate random AES key
    KeyGenerator kg = KeyGenerator.getInstance("AES");
    kg.init(128);
    SecretKey key = kg.generateKey();

    //Get respective cipher algorithm
    Cipher c = Cipher.getInstance("AES");
    c.init(Cipher.ENCRYPT_MODE, key);

    FileInputStream fis;
    FileOutputStream fos;
    CipherOutputStream cos;
    
    //original file and respective cryptogram streams
    fis = new FileInputStream("a.txt");
    fos = new FileOutputStream("a.cif");

    //output
    cos = new CipherOutputStream(fos, c);

    byte[] b = new byte[16];  
    //Reads up to b.length bytes of data from this input stream into an array of bytes.
    //Returns total number of bytes read
    int i = fis.read(b);
    while (i != -1) {
        //Writes i bytes from the specified byte array starting at offset off to this file output stream.
        //Note that b is updated everytime due to read()
        cos.write(b, 0, i);
        //Reads up to b.length bytes of data from this input stream into an array of bytes.
        i = fis.read(b);
    }
    cos.close();
    fis.close();
    fos.close();

    // This file will contain the secret key
    byte[] keyEncoded = key.getEncoded();
    FileOutputStream kos = new FileOutputStream("a.key");
    kos.write(keyEncoded);
    kos.close();
    }
}

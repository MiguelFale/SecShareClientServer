//package cipher;
 
import java.io.*;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
 
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
 
public class decifra {
 
    /**
     * @param args
     */
    public static void main(String[] args) {

        try {
             
            File chaveWrapped = new File("a.key");
            FileInputStream kos = new FileInputStream(chaveWrapped);
            
            //criar um fileinput stream para a nossa chave simetrica
            //16 * 8 = 128 (bits da nossa chave)
            //replaced with .length for other sizes
            byte[] keyEncoded2 = new byte[(int) chaveWrapped.length()];
            kos.read(keyEncoded2);
            /*while (i != -1) {
                //Reads up to b.length bytes of data from this input stream into an array of bytes.
                i = kos.read(b);
            }*/
            
            FileInputStream kfile = new FileInputStream(System.getenv("SAMPLE_JKS_FILE"));  //keystore               
            KeyStore kstore = KeyStore.getInstance("JKS");
            kstore.load(kfile, System.getenv("SAMPLE_JKS_PASSWORD").toCharArray());           //password
            Certificate cert = kstore.getCertificate(System.getenv("SAMPLE_JKS_USER"));  //alias do utilizador
            
            PrivateKey kkk = (PrivateKey) kstore.getKey(System.getenv("SAMPLE_JKS_USER"), System.getenv("SAMPLE_JKS_PASSWORD").toCharArray());
            
            Cipher c2 = Cipher.getInstance("RSA");
            c2.init(Cipher.UNWRAP_MODE, kkk);
             
            SecretKey keySpec2 = (SecretKey) c2.unwrap(keyEncoded2, "AES", Cipher.SECRET_KEY);
            		//new SecretKeySpec(keyEncoded2, "AES");
             
            Cipher c = Cipher.getInstance("AES");
             
            c.init(Cipher.DECRYPT_MODE, keySpec2);
             
            FileInputStream fis = new FileInputStream("a.cif");
 
            CipherInputStream cos = new CipherInputStream(fis, c);
             
            FileOutputStream fos = new FileOutputStream("a2.docx");
             
            byte[] b = new byte[16]; 
            int i = cos.read(b);
            while (i != -1) {
                //cos.read(b, 0, i);
                fos.write(b, 0 , i);
                i = cos.read(b);
            }
            cos.close();
            fis.close();
            fos.close();
            kos.close();
            //chaveWrapped.close();
             
        } catch (FileNotFoundException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (UnrecoverableKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
         
         
    }
 
}

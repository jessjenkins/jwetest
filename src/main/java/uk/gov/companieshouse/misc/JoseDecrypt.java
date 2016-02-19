package uk.gov.companieshouse.misc;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.DirectDecrypter;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.keys.AesKey;

import java.security.Key;

/**
 * Created by jjenkins1 on 19/02/16.
 */
public class JoseDecrypt {


    public static void main(String[] args) {


        try {
            String keystring = "ATestKeyATestKeyDummyKeyDummyKey"; // A128CBC_HS256
            byte[] keybytes = keystring.getBytes("ISO-8859-1");
            String serializedJwe = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..8xFJdER78EUOXfyCW995JA.HilGHhHcSUP0rrVNK3bTRw.Z8QZAwrjMDlSaNB8DZRDpA";


            //Decode using jose4j
            Key key = new AesKey(keybytes);
            JsonWebEncryption jwe = new JsonWebEncryption();
            jwe.setKey(key);
            jwe.setCompactSerialization(serializedJwe);
            System.out.println("Payload: " + jwe.getPayload());


            //decode using nimbus
            JWEHeader header = new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A128CBC_HS256);
            JWEObject jweObject = JWEObject.parse(serializedJwe);
            jweObject.decrypt(new DirectDecrypter(keybytes));
            Payload payload = jweObject.getPayload();
            System.out.print("Numbus Decrypted payload:");
            System.out.println(payload.toString());


        } catch (Exception ex) {
            ex.printStackTrace();
        }


    }
}
package uk.gov.companieshouse.misc;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.DirectDecrypter;

import java.security.Key;

/**
 * Created by jjenkins1 on 19/02/16.
 */
public class NimbusDecrypt {


    public static void main(String[] args) {


        try {
            String keystring = "ATestKeyATestKeyDummyKeyDummyKey"; // A128CBC_HS256
            byte[] keybytes = keystring.getBytes("ISO-8859-1");
            String serializedJwe = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..8xFJdER78EUOXfyCW995JA.HilGHhHcSUP0rrVNK3bTRw.Z8QZAwrjMDlSaNB8DZRDpA";


            //decode using nimbus
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
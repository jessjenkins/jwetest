package uk.gov.companieshouse.misc;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.DirectDecrypter;

import java.security.Key;
import java.util.Base64;

/**
 * Created by jjenkins1 on 19/02/16.
 */
public class NimbusDecrypt {


    public static void main(String[] args) {


        try {
            byte[] keybytes = Base64.getDecoder().decode("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX=");
            String serializedJwe = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..jkfpHBIdEL5-LN1q4lXLTw.iLOuYYwoxEoi4ssF9JDDg7NcG4asWUhBeORyGmM78m1aKvD6mGjv7TzpLHLE2MiuuscAUIUo_BB9KuClMb7KfA.CEEerKyT8RC_CZRt7jhv2A";


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
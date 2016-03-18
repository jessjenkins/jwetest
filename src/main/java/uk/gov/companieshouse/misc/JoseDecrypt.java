package uk.gov.companieshouse.misc;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.DirectDecrypter;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.keys.AesKey;

import java.security.Key;
import java.util.Base64;

/**
 * Created by jjenkins1 on 19/02/16.
 */
public class JoseDecrypt {


    public static void main(String[] args) {


        try {
            byte[] keybytes = Base64.getDecoder().decode("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX=");
            String serializedJwe = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..jkfpHBIdEL5-LN1q4lXLTw.iLOuYYwoxEoi4ssF9JDDg7NcG4asWUhBeORyGmM78m1aKvD6mGjv7TzpLHLE2MiuuscAUIUo_BB9KuClMb7KfA.CEEerKyT8RC_CZRt7jhv2A";


            //Decode using jose4j
            Key key = new AesKey(keybytes);
            JsonWebEncryption jwe = new JsonWebEncryption();
            jwe.setKey(key);
            jwe.setCompactSerialization(serializedJwe);
            System.out.println("Payload: " + jwe.getPayload());

        } catch (Exception ex) {
            ex.printStackTrace();
        }


    }
}
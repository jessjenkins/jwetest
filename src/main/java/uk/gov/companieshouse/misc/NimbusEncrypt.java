package uk.gov.companieshouse.misc;


import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.DirectEncrypter;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.keys.AesKey;

import java.security.Key;
import java.util.Base64;

/**
 * Hello world!
 */
public class NimbusEncrypt {

    public static void main(String[] args) {

        try {
            byte[] keybytes = keybytes= Base64.getDecoder().decode("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX=");



            // Encode using Nimbus
            JWEHeader header = new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A128CBC_HS256);
            Payload payload = new Payload("{ \"moo\": \"quack\", \"stuff\": { \"a\": 1, \"b\": [ 2, 3, 4 ] }}");
            JWEObject jweObject = new JWEObject(header, payload);
            DirectEncrypter dirEnc = new DirectEncrypter(keybytes);
            jweObject.encrypt(dirEnc);
            String serializedJwe = jweObject.serialize();

            System.out.println("Serialized Encrypted JWE: " + serializedJwe);


            //Decode using jose4j
            Key key = new AesKey(keybytes);
            JsonWebEncryption jwe = new JsonWebEncryption();
            jwe.setKey(key);
            jwe.setCompactSerialization(serializedJwe);
            System.out.println("Jose decrypted Payload: " + jwe.getPayload());


            //decode using nimbus
            jweObject = JWEObject.parse(serializedJwe);
            jweObject.decrypt(new DirectDecrypter(keybytes));
            payload = jweObject.getPayload();
            System.out.println("Nimbus decrypted payload: " + payload);


        } catch (Exception ex) {
            ex.printStackTrace();
        }

    }
}

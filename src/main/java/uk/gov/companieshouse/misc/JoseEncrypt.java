package uk.gov.companieshouse.misc;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.DirectDecrypter;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.keys.AesKey;
import org.jose4j.lang.ByteUtil;

import java.security.Key;
import java.util.Base64;

/**
 * Created by jjenkins1 on 19/02/16.
 */
public class JoseEncrypt {


    public static void main(String[] args) {


        try {
            byte[] keybytes = keybytes= Base64.getDecoder().decode("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX=");

            //Encode using jose4j
            Key key = new AesKey(keybytes);
            JsonWebEncryption jwe = new JsonWebEncryption();
            jwe.setPayload("{ \"moo\": \"quack\", \"stuff\": { \"a\": 1, \"b\": [ 2, 3, 4 ] }}");
            jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.DIRECT);
            jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
//            jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_256_CBC_HMAC_SHA_512);
            jwe.setKey(key);
            String serializedJwe = jwe.getCompactSerialization();
            System.out.println("Serialized Encrypted JWE: " + serializedJwe);


            //Decode using jose4j
            jwe = new JsonWebEncryption();
            jwe.setKey(key);
            jwe.setCompactSerialization(serializedJwe);
            System.out.println("Jose decrypted Payload: " + jwe.getPayload());


            //decode using nimbus
            JWEHeader header = new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A128CBC_HS256);
            JWEObject jweObject = JWEObject.parse(serializedJwe);
            jweObject.decrypt(new DirectDecrypter(keybytes));
            Payload payload = jweObject.getPayload();
            System.out.println("Nimbus decrypted payload: " + payload);


        } catch (Exception ex) {
            ex.printStackTrace();
        }

    }

}

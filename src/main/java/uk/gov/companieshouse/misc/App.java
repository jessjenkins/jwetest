package uk.gov.companieshouse.misc;


import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;

import java.io.ByteArrayOutputStream;

/**
 * Hello world!
 */
public class App {

    public static void main(String[] args) {

        try {

            String keystring = "DummyKeyDummyKeyDummyKeyDummyKey"; // A128CBC_HS256
//            String keystring = "DummyKeyDummyKeyDummyKeyDummyKeyDummyKeyDummyKeyDummyKeyDummyKey"; // A256CBC_HS512

            byte[] keybytes = keystring.getBytes("ISO-8859-1");

            // The shared key
//        byte[] keybytes = {
//                (byte) 177, (byte) 119, (byte) 33, (byte) 13, (byte) 164, (byte) 30, (byte) 108, (byte) 121,
//                (byte) 207, (byte) 136, (byte) 107, (byte) 242, (byte) 12, (byte) 224, (byte) 19, (byte) 226};

            // Create the header
            JWEHeader header = new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A128CBC_HS256);
//            JWEHeader header = new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A256CBC_HS512);

            // Set the plain text
            Payload payload = new Payload("{\"key\": \"value\"}");

            // Create the JWE object and encrypt it
            JWEObject jweObject = new JWEObject(header, payload);

            DirectEncrypter dirEnc = new DirectEncrypter(keybytes);

            jweObject.encrypt(dirEnc);

            // Serialise to compact JOSE form...
            String jweString = jweObject.serialize();

            System.out.println("Encrypted payload...");
            System.out.println(jweString);

// Parse into JWE object again...
            jweObject = JWEObject.parse(jweString);

// Decrypt
            jweObject.decrypt(new DirectDecrypter(keybytes));

// Get the plain text
            payload = jweObject.getPayload();
            System.out.println("Decrypted payload");
            System.out.println(payload.toString());

        } catch (Exception ex) {
            ex.printStackTrace();
        }

    }
}

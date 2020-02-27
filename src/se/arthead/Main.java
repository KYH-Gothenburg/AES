package se.arthead;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class Main {

	public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeyException,
			NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException,
			InvalidKeySpecException {
		AES aes = new AES();
		IvParameterSpec iv = aes.generateIV();
		aes.saveIv("alice.iv", iv);
		// SecretKeySpec skey = aes.keyFromPassPhrase("TjohoppBlomma1");
		SecretKeySpec skey = aes.generateKey();

		aes.encrypt("Jag vill ha rast!!!", "crypto.enc", skey, iv);
		String plaintext = aes.decrypt("crypto.enc", skey, iv);
		System.out.println(plaintext);

	}
}

package br.com.tmsfasdom.assinadordesassinador;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;

public class ManipuladorCertificado {
	
	public static X509Certificate lerCertificado(File file) throws IOException, CertificateException {
		PEMParser pr = new PEMParser(new FileReader(file));
		try {
			X509CertificateHolder x509 = (X509CertificateHolder) pr.readObject();			
			return new JcaX509CertificateConverter().setProvider("BC").getCertificate(x509);
		} finally {
			pr.close();
		}
	}

	public static PrivateKey retornaPrivadaDecriptada(File arquivoChavePrivadaEncriptada, String password) throws Exception {
		PrivateKey decryptedPrivateKey;

		try {
			PEMParser keyReader = new PEMParser(new FileReader(arquivoChavePrivadaEncriptada));
			Object keyPair = keyReader.readObject();
			keyReader.close();

			if (keyPair instanceof PEMEncryptedKeyPair) {
				JcePEMDecryptorProviderBuilder builder = new JcePEMDecryptorProviderBuilder();
				PEMDecryptorProvider decryptionProvider = builder.build(password.toCharArray());
				keyPair = ((PEMEncryptedKeyPair) keyPair).decryptKeyPair(decryptionProvider);
			}

			PrivateKeyInfo keyInfo = ((PEMKeyPair) keyPair).getPrivateKeyInfo();
			decryptedPrivateKey = (new JcaPEMKeyConverter()).getPrivateKey(keyInfo);
		} catch (IOException e) {
			throw new Exception("Error parsing private key for Box Developer Edition.", e);
		}
		return decryptedPrivateKey;
	}

	public static PrivateKey retornaPrivada(File arquivoChavePrivada) throws IOException {

		PEMParser privatePem = new PEMParser(new FileReader(arquivoChavePrivada));
		PrivateKeyInfo privateKey;
		Object object = privatePem.readObject();
		if (object instanceof PrivateKeyInfo) {
			privateKey = (PrivateKeyInfo) object;
		} else {
			System.out.println("object = " + object);
			privatePem.close();
			return null;
		}
		privatePem.close();
		return (new JcaPEMKeyConverter()).getPrivateKey(privateKey);

	}
	
	public KeyStore retornaKeyStore(File arquivoKeyStore) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException
	{
		KeyStore ks = KeyStore.getInstance("pkcs12");
		ks.load(new FileInputStream(arquivoKeyStore), "fernando".toCharArray());
		return ks;
	}

}

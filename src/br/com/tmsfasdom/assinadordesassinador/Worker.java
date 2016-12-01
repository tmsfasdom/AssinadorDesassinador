package br.com.tmsfasdom.assinadordesassinador;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;

import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;

import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;

public class Worker {

	public byte[] assinar(ArrayList<Assinador> assinadores, byte[] dado)
			throws OperatorCreationException, CertificateEncodingException, CMSException, IOException {
		// Dado a ser assinado
		CMSTypedData msg = new CMSProcessableByteArray(dado);

		// Esse cara faz a magica, recebe o certificado com sua respectiva chave
		// privada
		// a cadeia de certificados e o dado a ser assinado propriamente dito
		CMSSignedDataGenerator geradorDadoAssinado = new CMSSignedDataGenerator();

		// Adiciona os certificados e a chave privada de cada assinador
		for (Assinador assinador : assinadores) {

			System.out.println("-----BEGIN PRIVATE KEY-----");
			System.out.println(Base64.encode(assinador.chavePrivada.getEncoded()));
			System.out.println("-----END PRIVATE KEY-----");
			ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC")
					.build(assinador.getChavePrivada());
			geradorDadoAssinado.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
					new JcaDigestCalculatorProviderBuilder().setProvider("BC").build()).build(sha1Signer,
							assinador.getCertificado()));
			geradorDadoAssinado.addCertificates(assinador.getCadeiaDeCertificacao());
		}
		return geradorDadoAssinado.generate(msg, true).getEncoded();
	}

	public ArrayList<Assinador> retornaAssinadores(String caminhoKeystore)
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException,
			IOException, UnrecoverableKeyException {
		ManipuladorCertificado cert = new ManipuladorCertificado();
		KeyStore ks = cert.retornaKeyStore(new File(caminhoKeystore));

		ArrayList<Assinador> assinadores = new ArrayList<Assinador>();
		Enumeration<String> e = ks.aliases();
		if (e != null) {
			while (e.hasMoreElements()) {
				String n = e.nextElement();
				X509Certificate certificado = (X509Certificate) ks.getCertificate(n);
				assinadores.add(new Assinador(certificado, (PrivateKey) ks.getKey(n, "fernando".toCharArray())));
				certificado = null;
			}
		}
		return assinadores;
	}

}

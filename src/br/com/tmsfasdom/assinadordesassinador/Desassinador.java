package br.com.tmsfasdom.assinadordesassinador;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;

public class Desassinador {

	public void VerificaAssinaturas(byte[] dadoassinado)
			throws OperatorCreationException, CertificateException, CMSException, IOException {
		CMSSignedDataParser sp = new CMSSignedDataParser(
				new JcaDigestCalculatorProviderBuilder().setProvider("BC").build(), dadoassinado);

		sp.getSignedContent().drain();

		Store certStore = sp.getCertificates();
		SignerInformationStore signers = sp.getSignerInfos();

		Collection c = signers.getSigners();
		Iterator it = c.iterator();

		while (it.hasNext()) {
			SignerInformation signer = (SignerInformation) it.next();
			Collection certCollection = certStore.getMatches(signer.getSID());

			Iterator certIt = certCollection.iterator();
			X509CertificateHolder cert = (X509CertificateHolder) certIt.next();

			System.out.println("verify returns: "
					+ signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert)));
		}

	}
	public static void ExibeCertificados(byte[] dados) throws Exception {
			

		 CMSSignedDataParser sp = new CMSSignedDataParser(
		 new JcaDigestCalculatorProviderBuilder().setProvider("BC").build(),
		 dados);
		 sp.getSignedContent().drain();	
		
		 Store certStore = sp.getCertificates();
		 SignerInformationStore signers = sp.getSignerInfos();
		
		 Collection c = signers.getSigners();
		 Iterator it = c.iterator();
		
		 while (it.hasNext()) {
		 SignerInformation signer = (SignerInformation) it.next();
		 Collection certCollection = certStore.getMatches(signer.getSID());
		 Iterator certIt = certCollection.iterator();
		
		 X509CertificateHolder cert = (X509CertificateHolder) certIt.next();
		 X509Certificate certificado = new
		 JcaX509CertificateConverter().setProvider("BC").getCertificate(cert);		
		 System.out.println(certificado.getSubjectDN());
		
		 }

	}

}

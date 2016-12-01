package br.com.tmsfasdom.assinadordesassinador;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.util.Store;

public class Assinador {

	X509Certificate certificado;
	PrivateKey chavePrivada;
	PublicKey chavePublica;
	Store cadeiaDeCertificacao;

	public Assinador(X509Certificate _certificado, PrivateKey _chavePrivada) throws CertificateEncodingException {
		super();
		this.certificado = _certificado;
		this.chavePrivada = _chavePrivada;
		this.chavePublica = _certificado.getPublicKey();
		List listcert = new ArrayList();
		listcert.add(_certificado);		
		this.cadeiaDeCertificacao = new JcaCertStore(listcert);;
	}

	public X509Certificate getCertificado() {
		return certificado;
	}

	public void setCertificado(X509Certificate certificado) {
		this.certificado = certificado;
	}

	public PrivateKey getChavePrivada() {
		return chavePrivada;
	}

	public void setChavePrivada(PrivateKey chavePrivada) {
		this.chavePrivada = chavePrivada;
	}

	public PublicKey getChavePublica() {
		return chavePublica;
	}

	public void setChavePublica(PublicKey chavePublica) {
		this.chavePublica = chavePublica;
	}

	public Store getCadeiaDeCertificacao() {
		return cadeiaDeCertificacao;
	}

	public void setCadeiaDeCertificacao(Store cadeiaDeCertificacao) {
		this.cadeiaDeCertificacao = cadeiaDeCertificacao;
	}

}

package br.com.tmsfasdom.assinadordesassinador;

import java.io.BufferedOutputStream;
import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Enumeration;
import java.util.List;
import java.util.Scanner;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

public class Utils {
	
	public static List<String> lerArquivoTxt(String caminhoArquivo) throws IOException {

		File arquivo = new File(caminhoArquivo);
		List<String> dados = Files.readAllLines(arquivo.toPath());
		return dados;
	}

	public static String retornaHashSHA1SobreOriginal(String CNAB240) throws Exception {
		MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
		sha1.update(CNAB240.getBytes());
		byte[] digest = sha1.digest();
		String hash = new String(digest);
		return hash;
	}

	public static String retornaStringDados(byte[] dados) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		CMSSignedDataParser sdp = new CMSSignedDataParser(
				new JcaDigestCalculatorProviderBuilder().setProvider("BC").build(), dados);
		String retornoCNAB240 = new String(lerInputStreamToByte(sdp.getSignedContent().getContentStream()));
		return retornoCNAB240;
	}

	public static byte[] lerInputStreamToByte(InputStream in) throws Exception {
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		int next = in.read();
		while (next > -1) {
			bos.write(next);
			next = in.read();
		}
		bos.flush();
		byte[] result = bos.toByteArray();
		return result;
	}

	public static byte[] converteBase64ParaBinario(String strBase64) {
		byte[] arrayBytes = Base64.getDecoder().decode(strBase64);
		return arrayBytes;
	}

	public static byte[] converteBinarioParaBase64(byte[] arrayBytes) {
		byte[] arrayBytesBase64 = Base64.getEncoder().encode(arrayBytes);
		return arrayBytesBase64;
	}

	
	public static byte[] lerArquivo(String caminhoArquivo) throws IOException {

		File arquivo = new File(caminhoArquivo);
		byte[] dados = Files.readAllBytes(arquivo.toPath());
		return dados;
	}

	public static void gravaArquivo(byte[] bytes, String caminho) throws Exception {

		File file = new File(caminho); // Criamos um nome para o arquivo
		BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(file, true)); // Criamos
																								// o
																								// arquivo
		bos.write(bytes); // Gravamos os bytes lá
		bos.close(); // Fechamos o stream.
	}

	public static void gravaArquivo(String dados, String caminho) throws Exception {

		BufferedWriter fr = new BufferedWriter(new FileWriter(caminho));
		fr.write(dados);
		fr.flush();
		fr.close();
	}

	public static List<String> removeInicioFimPKCS7(List<String> linhas) {

		boolean remove = true;
		List<String> linhasParaRemover = new ArrayList<String>();
		for (String str : linhas) {
			if (str.contains("-----BEGIN PKCS7-----")) {
				remove = false;
				linhasParaRemover.add(str);
			}
			if (remove) {
				linhasParaRemover.add(str);
			}
			if (str.contains("-----END PKCS7-----")) {
				remove = true;
				linhasParaRemover.add(str);
			}

		}
		linhas.removeAll(linhasParaRemover);
		return linhas;
	}

	public static String insereInicioFimPKCS7(String linhas) throws Exception {

		StringBuffer strbuff = new StringBuffer(linhas);
		strbuff.insert(0, "-----BEGIN PKCS7-----\r\n");
		strbuff.append("\r\n-----END PKCS7-----\r\n");
		linhas = strbuff.toString();
		Utils.gravaArquivo(linhas, "d:/projetos/java/AssinadorDesassinador/resources/dados1.txt");
		String[] linhaspartidas = linhas.split("\r\n");
		strbuff.delete(0, strbuff.length());
		for (String str : linhaspartidas) {
			str = String.format("%-76s", str);
			strbuff.append(str);
			strbuff.append("\r\n");
		}

		return strbuff.toString();
	}
	
	public static ArrayList<Assinador> obterCertificadoDoWindows() throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException, NoSuchProviderException, UnrecoverableKeyException {  
        
        KeyStore ks = KeyStore.getInstance("Windows-MY");  
          
        ks.load(null, null);  
          
        Enumeration<String> al = ks.aliases();  
          
        ArrayList<Assinador> assinadores = new ArrayList<Assinador>(); 
        ArrayList<Assinador> assinadoresEscolhidos = new ArrayList<Assinador>(); 
        List<String> certificados = new ArrayList<String>(); 
        while(al.hasMoreElements())  
        {  
            String alias = al.nextElement();
            if (ks.isKeyEntry(alias)){
            	 if (ks.getKey(alias, null) instanceof PrivateKey) {
            		 PrivateKey key0 = (PrivateKey)ks.getKey(alias, null);
            		 System.out.println(new String(key0.getEncoded()));
            	assinadores.add(new Assinador( (X509Certificate)ks.getCertificate(alias), (PrivateKey)ks.getKey(alias, null)) );
            	certificados.add(alias);
            	 }
            }    
           
        }  
        int count = 0;  
        for (String cert : certificados)  
        {  
            System.out.println(String.valueOf(count) + " - " + cert);  
            count++;
        }
        Scanner s = new Scanner(System.in);

        System.out.println("Digite o numero dos certificados que deseja usar separados por ';': ");
        String[] escolha = s.nextLine().split(";");
        for(String str:escolha)
        {
        	assinadoresEscolhidos.add(assinadores.get(Integer.valueOf(str)));        	
        }
		return assinadoresEscolhidos;
          
    }  

}

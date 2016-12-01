package br.com.tmsfasdom.assinadordesassinador;

import java.io.File;
import java.security.AuthProvider;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;



public class Main {

	public static void main(String[] args) throws Exception {
		//assinar();
		desassinar();
	}
	
	public static void desassinar()  throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		String caminhoPkcs7 = "d:/projetos/java/AssinadorDesassinador/resources/BMB.1.09191.rem.00243";
		String caminhoBinario = caminhoPkcs7 + ".bin";
		List<String> listaString = Utils.lerArquivoTxt(caminhoPkcs7);
		List<String> listaStringTrat = Utils.removeInicioFimPKCS7(listaString);
		for (String str : listaStringTrat) {
			Utils.gravaArquivo(Utils.converteBase64ParaBinario(str), caminhoBinario);
		}
		Desassinador desassinador = new Desassinador();
		desassinador.VerificaAssinaturas(Utils.lerArquivo(caminhoBinario));
		desassinador.ExibeCertificados(Utils.lerArquivo(caminhoBinario));
	}
	
	public static void assinar()  throws Exception
	{
		// TODO Auto-generated method stub
				//Nescessario informar à JVM qual o provedor de criptografia no caso BouncyCastle
				Security.addProvider(new BouncyCastleProvider());
				
				
				
				//Caminho onde sera localizada a keystore que conterá 
				//os certificados com respectivas chaves privadas dos assinadores
				String caminhoKeyStore = "d:/projetos/java/AssinadorDesassinador/resources/keystoreWindows.pfx";
				
				//Caminho do arquivo de saida
			    String caminhoArquivoSaida = "d:/projetos/java/AssinadorDesassinador/resources/dado.txt";
				
				//Caso nao queira usar a keystore, informar o certificado e sua respectiva chaveprivada
				
				String caminhoCertificadoN1 = "d:/projetos/java/AssinadorDesassinador/resources/certificate.crt";
				String caminhoCertificadoN2 = "";
				String caminhoPrivadaN1 = "d:/projetos/java/AssinadorDesassinador/resources/certificate.key";
				String caminhoPrivadoN2 = "";
				String senhaPrivadaN1 = "fernando";
				String senhaPrivadaN2 = "";
				
				//Caminho do arquivo txt CNAB240 e na sequencia leitura do cnab para um array de bytes
				String caminhoArquivoCNAB = "d:/projetos/java/AssinadorDesassinador/resources/teste.txt";
				byte[] dado = Utils.lerArquivo(caminhoArquivoCNAB);
				
				
				
				//Criar um ArrayList com os assinadores que serao utilizados para assinar o arquivo
				ArrayList<Assinador> assinadores = new ArrayList<Assinador>();
				
				
				Worker work = new Worker();
				
				//usando a keystore em arquivo
				//assinadores = work.retornaAssinadores(caminhoKeyStore);
				
				//Usando a keystore do windows
				assinadores = Utils.obterCertificadoDoWindows();
				
				//Usando certificados e chaves individuais
			
				//Assinador 1 com chave privada encriptada necessitando de senha para leitura
				Assinador assinador1 = new Assinador(
						ManipuladorCertificado.lerCertificado(new File(caminhoCertificadoN1)),
						ManipuladorCertificado.retornaPrivada(new File(caminhoPrivadaN1))
						);
			
				//Assinador 2 com chave privada aberta		
				//Assinador assinador2 = new Assinador(
				//		ManipuladorCertificado.lerCertificado(new File(caminhoCertificadoN2)),
				//		ManipuladorCertificado.retornaPrivada(new File(caminhoPrivadaN1))
				//		);
					
				//Adiciono os assinadores na lista
				//assinadores.add(assinador1);
				//assinadores.add(assinador2);
				//assinadores.add(assinador3);
				
				//a classe worker possui o metodo assinar que realizará a assinatura com o N assinadores
				byte[] dadoassinado = work.assinar(assinadores, dado);		
				
				//A classe Utils contem o metodo para conversão em base64
				byte[] arrayBase64 = Utils.converteBinarioParaBase64(dadoassinado);
				
				//apos convertido em base64 tranformamos em uma String
			    String dadosBase64 = new String(arrayBase64);
			    
			    //formata o arquivo em 76 colunas
			    String dadosBase64Quebrado = dadosBase64.replaceAll("(.{76})", "$1\r\n");
			    
			    //insere o inicio pkcs7 e fim pkcs7 e preenche com espacos para completar 76 colunas
			    String dadosBase64QuebradoComPKCS7 = Utils.insereInicioFimPKCS7(dadosBase64Quebrado);	    
			
				//realiza a gravacao do arquivo no disco
			    Utils.gravaArquivo(dadosBase64QuebradoComPKCS7,caminhoArquivoSaida);	    
			    
				System.out.println("Rodou com sucesso");
		
	}
}

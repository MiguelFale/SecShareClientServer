//package server;

import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.*;
import javax.net.ssl.*;
import javax.xml.bind.DatatypeConverter;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

/**
 * Aplicacao cliente.
 * 
 * @author <p>
 *         Miguel Fale, n 43556;
 *         </p>
 *         <p>
 *         Miguel Rodrigues, n 44281;
 *         </p>
 *         <p>
 *         Sergio Alves, n 44306.
 *         </p>
 * 
 */
public class SecShareClient {

	/**
	 * Nome deste utilizador.
	 */
	private static String username = null;

	/**
	 * <p>
	 * Armazena:
	 * </p>
	 * <ul>
	 * <li>Endereco IP do servidor na String da posicao 0;</li>
	 * <li>Porto do servidor na String da posicao 1.</li>
	 * </ul>
	 */
	private static String[] addr = null;

	/**
	 * Scanner global para todos os inputs do cliente.
	 */
	private static Scanner s = new Scanner(System.in);

	/**
	 * Chave publica do utilizador.
	 */
	private static PublicKey ku = null;

	/**
	 * Chave privada do utilizador.
	 */
	private static PrivateKey kr = null;

	/**
	 * Ponto de entrada responsavel por ligar o cliente ao servidor e efectuar
	 * as operacoes.
	 * 
	 * @param args
	 *            Contem as opcoes do cliente.
	 */
	@SuppressWarnings("unchecked")
	public static void main(String[] args) {

		if (!verifyArgs(args)) {
			System.out.println("Erro nas opcoes. Exemplo de uso:");
			System.out
					.println("SecShareClient -u <userId> -a <serverAddress> ( -c <filenames> | -p <userId> <filenames> | -g <filenames> | -s <filenames> ) ");
			return;
		}

		// Credenciais
		username = args[1];
		System.out.println("Bem vindo " + username + "!");
		System.out.println("cliente: main");

		Console console = System.console();
		System.out.print("Insira a password: ");
		char[] passArray = console.readPassword();
		String pass = new String(passArray);

		if (pass.contains(":") || username.contains(":")
				|| username.contains("/") || pass.contains("/")) {
			System.out
					.println("Nao pode utilizar o carater ':' ou '/' para nome de utilizador"
							+ " ou password...");
			return;
		}

		// Abrir keystore deste utilizador
		File file = new File("./keystore/");
		if (!file.exists()) {
			if (file.mkdir()) {
				System.out
						.println("Diretoria \"keystore\" criada por favor coloque o ficheiro "
								+ args[1] + ".keystore aqui!");

			} else {
				System.out.println("Erro ao criar diretoria \"keystore\"!");
			}
			return;
		}

		File file2 = new File("./keystore/" + args[1] + ".keystore");
		if (!file2.exists()) {
			System.out.println("Por favor coloque o ficheiro " + args[1]
					+ ".keystore na diretoria keystore.");
			return;
		}

		if (!openKeystore()) {
			System.out
					.println("Erro ao carregar a keystore. Por favor verifique se existe um alias \'"
							+ username
							+ "\' na sua keystore, ou se a password da keystore esta correta.");
			return;
		}

		// Separar endereco IP do porto
		addr = args[3].split(":");

		try {
			if (!checkServerCertificate()) {
				System.out
						.println("O certificado do servidor nao existe na sua truststore, ou a truststore nao existe!");
				return;
			}

			SSLSocketFactory sslSF = (SSLSocketFactory) SSLSocketFactory
					.getDefault();
			SSLSocket cSoc = (SSLSocket) sslSF.createSocket(addr[0],
					Integer.parseInt(addr[1]));

			/*
			 * Preparacao dos streams de entrada e saida que fazem a comunicacao
			 * com o servidor
			 */
			ObjectInputStream in = new ObjectInputStream(cSoc.getInputStream());
			ObjectOutputStream out = new ObjectOutputStream(
					cSoc.getOutputStream());

			// Fase de autenticacao
			Boolean fromServer = autenticationClient(in, out, args, pass);

			pass = null; // Deixa de referenciar a password

			if (fromServer)
				System.out.println("Autenticacao bem sucedida!");
			else {
				System.out.println("Autenticacao falhou!");
				cSoc.close();
				return;
			}

			int retorno;

			// Fase de operacao
			if (args[4].equals("-c")) {

				retorno = CopyClient(in, out, args);
				if (retorno > 0)
					System.out.println("Ficheiros copiados com sucesso: "
							+ retorno);
				else
					System.out.println("Nenhum ficheiro foi copiado...");

			} else if (args[4].equals("-p")) {
				retorno = ShareClient(in, out, args);
				if (retorno > 0)
					System.out.println("Ficheiros partilhados com sucesso: "
							+ retorno);
				else
					System.out.println("Nenhum ficheiro foi partilhado...");

			} else if (args[4].equals("-s")) {
				SynchClient(in, out, args);

			} else if (args[4].equals("-l")) {

				String s2 = null;
				while ((s2 = (String) in.readObject()) != null) {

					System.out.print(s2);
					ArrayList<String> partilhas = new ArrayList<String>();
					partilhas = (ArrayList<String>) in.readObject();
					System.out.print(" | Partilhas : ");
					if (partilhas.size() != 0) {
						for (String s : partilhas) {

							System.out.print(s + " ");
						}
						System.out.println();
					} else
						System.out.println(" Sem Partilhas");
				}

			} else if (args[4].equals("-g")) {
				retorno = menos_g(in, out, args);
				if (retorno > 0)
					System.out.println("Ficheiros copiados com sucesso: "
							+ retorno);
				else
					System.out.println("Nenhum ficheiro foi copiado...");

			} else {
				cSoc.close();
				return;
			}

			cSoc.close();

		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		} catch (SSLHandshakeException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private static boolean checkServerCertificate() {

		boolean res = true;

		String home = System.getProperty("user.home");
		File file = new File(home + "/.truststore");

		if (!file.exists())
			res = false;

		else {

			// verificar se alias "server" existe
			FileInputStream tfile;

			try {
				tfile = new FileInputStream(file);
				KeyStore tstore = KeyStore.getInstance("JKS");
				tstore.load(tfile, System.getenv("JKS_PASSWORD").toCharArray());
				Certificate cert = tstore.getCertificate("server");
				res = (cert == null) ? false : true;

			} catch (KeyStoreException e) {
				e.printStackTrace();
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			} catch (CertificateException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}

		}
		return res;
	}

	/**
	 * Efectua a copia dos ficheiros do cliente para o servidor.
	 * 
	 * @param in
	 *            Stream de rececao de objetos.
	 * @param out
	 *            Stream de envio de objetos.
	 * @param args
	 *            Contem os nomes dos ficheiros que o cliente quer enviar.
	 * @return O numero de ficheiros copiados com sucesso.
	 */
	private static int CopyClient(ObjectInputStream in, ObjectOutputStream out,
			String[] args) {

		// Contador de ficheiros enviados com sucesso
		int counter = 0;

		try {

			// Envia o numero de ficheiros
			out.writeObject(args.length - 5);

			FileInputStream fis;

			// Enviar um ficheiro de cada vez
			for (int i = 5; i < args.length; i++) {

				File fic = new File("./" + args[i]);

				if (fic.exists()) {

					out.writeObject(fic.getName());
					if ((Boolean) in.readObject())
						if (reader(in, out) == -1) {
							System.out.println("Ficheiro local \""
									+ fic.getName() + " inexistente!");
							continue;
						}

					// Envia a data da sua ultima modificacao
					out.writeObject(fic.lastModified());

					/*
					 * Se a data do ficheiro local for mais recente, ou se o
					 * ficheiro nao existe ainda no servidor...
					 */
					Boolean fromServer = (Boolean) in.readObject();
					if (fromServer) {

						SecretKeySpec keySpec2 = null;
						boolean reuse = (Boolean) in.readObject();
						if (reuse) {
							System.out
									.println("Chave AES vai ser reutilizada!");
							keySpec2 = getSecretKey(in);
						} else {
							System.out
									.println("Nova chave AES vai ser gerada!");
							keySpec2 = makeSecretKey();
						}

						// Enviar assinatura deste ficheiro
						sendSignature(fic, out);

						// Criar criptograma localmente
						File cipheredFile = makeCiphedFile(fic, keySpec2);

						// Enviar chave cifrada
						sendWrappedkey(keySpec2, out);

						// Enviar tamanho do criptograma, iniciar transferencia
						System.out.println("A enviar ficheiro \""
								+ fic.getName() + "\" ...");

						long t = cipheredFile.length();
						out.writeObject(t);

						// Enviar ficheiro cifrado como um ficheiro normal
						byte[] bray = new byte[1024];

						int n;
						long a = 0, r = 0, r2 = 0;

						fis = new FileInputStream(cipheredFile);
						while ((n = fis.read(bray, 0, 1024)) != -1) {
							out.write(bray, 0, n);

							// isto vai imprimir a % de dados enviados
							a = a + n;
							r = ((a * 100) / t);
							if (r != r2) // isto serve para ele nao repetir a
								// mesma percentagem
								System.out.println(r + " % completo");
							r2 = r;
						}
						out.flush();
						fis.close();

						counter++;

					} else
						System.out.println("Nao eh preciso atualizar \""
								+ fic.getName() + "\"!");
				} else {
					System.out.println("Ficheiro \"" + fic.getName()
							+ "\" nao existe!");

					// Servidor devera "saltar" para o proximo ficheiro
					out.writeObject(null);
				}
			}
		} catch (IOException e) {
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		}

		File todelete = new File("./" + "temp");
		todelete.delete();

		return counter;

	}

	private static void sendSignature(File fic, ObjectOutputStream out) {

		// Inicializar assinatura
		Signature s;

		try {
			s = Signature.getInstance("SHA256withRSA");

			s.initSign(kr);

			// Ir fazendo update consoante os conteudos
			FileInputStream fis = new FileInputStream(fic);
			BufferedInputStream bufin = new BufferedInputStream(fis);
			byte[] buffer = new byte[1024];
			int len;
			while ((len = bufin.read(buffer)) >= 0) {
				s.update(buffer, 0, len);
			}
			bufin.close();

			// Assinar
			byte[] realSig = s.sign();

			// Enviar para o servidor
			out.writeObject(DatatypeConverter.printHexBinary(realSig));

		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}

	}

	private static int menos_g(ObjectInputStream in, ObjectOutputStream out,
			String[] args) {

		int contador = 0;

		try {

			// Envia o numero de ficheiros
			out.writeObject(args.length - 5);

			for (int i = 5; i < args.length; i++) {

				File f = new File(args[i]);

				// Envia nome e escolhe o dono
				out.writeObject(args[i]);

				// true = ha varios donos, false = 1 ou 0 donos
				if ((Boolean) in.readObject())
					if (reader(in, out) == -1)
						continue;

				// Servidor responde se ficheiro remoto existe
				if ((Boolean) in.readObject()) {

					// Last modified do ficheiro do cliente
					out.writeObject(f.lastModified());

					// Se a versao no servidor for mais recente...
					if ((Boolean) in.readObject()) {
						long ret = Copy_Server_to_Client(in, f);

						if (ret == -1) {
							System.out
									.println("Transferencia do ficheiro cancelada!");
							f.delete();
							continue;
						}

						f.setLastModified(ret);
						System.out.println("\"" + f.toString()
								+ "\" recebido com sucesso!");
						contador++;
					} else {
						System.out.println("Nao eh preciso atualizar \""
								+ f.toString() + "\" local!");
					}

				} else {
					System.out.println("Ficheiro \"" + f.getName()
							+ "\" remoto nao existe!");
				}
			}
		} catch (IOException e) {
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		}

		return contador;
	}

	private static void SynchClient(ObjectInputStream in,
			ObjectOutputStream out, String[] args) {

		ArrayList<String> filenames = new ArrayList<String>();

		try {

			// Envia o numero de ficheiros
			out.writeObject(args.length - 5);

			// Enviar um ficheiro de cada vez
			for (int i = 5; i < args.length; i++) {

				// envia o nome do file
				out.writeObject(args[i]);

				int k = (Integer) in.readObject();

				if (k == 0) {
					System.out.println("Ficheiro " + args[i]
							+ " nao existe no servidor ");
				} else if (k == 1) {
					System.out.println("Existe um ficheiro");
					filenames.add(args[i]);
				} else if (k > 1) {
					System.out
							.println("Existem varios ficheiros com esse nome.");

					for (int t = 0; t < k; t++) {

						System.out.println((String) in.readObject());

					}

					System.out
							.println("Qual deles quer? (Seleccione o numero respectivo)");
					int esc = s.nextInt();
					if (esc > k || esc < 0) {
						System.out.println("Escolha errada");
						out.writeObject(-1);
						return;
					} else
						out.writeObject(esc);
					filenames.add(args[i]);
				}
			}

			Boolean k = (Boolean) in.readObject();

			if (!k) {
				System.out.println("Impossivel realizar a sincronizacao");
				return;
			}

			File novof = null;
			long l = 0;

			while (true) {
				int i = 0;
				ArrayList<Long> last2 = new ArrayList<Long>();

				for (@SuppressWarnings("unused")
				String s : filenames) {
					last2.add((Long) in.readObject());
				}

				for (String s : filenames) {

					novof = new File(s);
					l = novof.lastModified();

					if (last2.get(i) > l) {// servidor +
						out.writeObject(1);
						long ret = Copy_Server_to_Client(in, novof);

						if (ret == -1) {
							System.out
									.println("Transferencia do ficheiro cancelada!");
							novof.delete();
							continue;
						}
						novof.setLastModified(ret);

					} else if (last2.get(i) < l) {// cliente mais recente
						out.writeObject(2);
						long ret = Copy_Client_to_Server(in, out, novof);
						novof.setLastModified(ret);

					} else {
						out.writeObject(0);
						System.out.println("Nao eh preciso fazer nada para "
								+ s);// depois tiramos este print
					}
					i++;
					File todelete = new File("./" + "temp.txt");
					todelete.delete();
				}
			}
		} catch (IOException e) {
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		}

	}

	private static long Copy_Client_to_Server(ObjectInputStream in,
			ObjectOutputStream out, File novof) {

		byte[] bray = new byte[1024];
		int n;
		FileInputStream fis;
		long ret = 0;

		try {

			// Obter chave AES
			SecretKeySpec keySpec2 = getSecretKey(in);

			File cipheredFile = makeCiphedFile(novof, keySpec2);

			// Enviar tamanho do criptograma, iniciar transferencia
			System.out.println("A enviar ficheiro \"" + novof.getName()
					+ "\" ...");

			long t = cipheredFile.length();
			out.writeObject(t);

			fis = new FileInputStream(cipheredFile);

			while ((n = fis.read(bray, 0, 1024)) != -1) {
				out.write(bray, 0, n);
			}
			out.flush();
			fis.close();

			// Enviar last modified
			ret = novof.lastModified();
			out.writeObject(ret);

			System.out.println("Transferencia de " + novof.getName()
					+ " terminada!");

		} catch (IOException e) {
			e.printStackTrace();
		}

		File todelete = new File("./" + "temp");
		todelete.delete();
		return ret;
	}

	private static long Copy_Server_to_Client(ObjectInputStream in, File novof) {

		long ret = 0;
		try {

			/*
			 * Os dados veem cifrados do servidor, escrever primeiro para um
			 * temporario
			 */
			File temp = new File("./" + "temp.txt");
			FileOutputStream fos = new FileOutputStream(temp);

			byte[] bray = new byte[1024];
			int n = 0, m = 0;

			long tamf = (Long) in.readObject();

			while (m != tamf) {
				n = in.read(bray, 0, (int) ((tamf - m) >= 1024 ? 1024
						: (tamf - m)));
				fos.write(bray, 0, n);
				m += n;
			}
			fos.close();

			// Receber chave secreta
			SecretKeySpec keySpec2 = getSecretKey(in);

			// Decifrar ficheiro
			File file = makeDeciphedFile(temp, novof, keySpec2);

			// Receber assinatura
			byte[] signature = DatatypeConverter.parseHexBinary((String) in
					.readObject());

			String nomult = (String) in.readObject();

			// Inicializar verificacao
			Signature sig = Signature.getInstance("SHA256withRSA");

			// vai buscar certificado do nomult
			// NOTA: na instrucao seguinte na verdade nomult deveria ser "user". a ideia
			//era ir buscar o certificado  ah keystore
			FileInputStream kfile = new FileInputStream("./keystore/" + nomult
					+ ".keystore");
			KeyStore kstore = KeyStore.getInstance("JKS");
			kstore.load(kfile, System.getenv("JKS_PASSWORD").toCharArray());
			Certificate cert = kstore.getCertificate(nomult);

			PublicKey pu;

			// if (cert != null) {
			pu = cert.getPublicKey();
			// }

			sig.initVerify(pu);

			// Ler do ficheiro file
			FileInputStream datafis = new FileInputStream(file);
			BufferedInputStream bufin = new BufferedInputStream(datafis);

			byte[] buffer = new byte[1024];
			int len;
			while (bufin.available() != 0) {
				len = bufin.read(buffer);
				sig.update(buffer, 0, len);
			}

			bufin.close();

			// veredicto
			boolean verifies = sig.verify(signature);

			System.out.println( verifies ? "Assinatura correta!" : "Assinatura inválida!" );
			if (!verifies) {
				int continua = 2;
				System.out
						.println(novof.getName()
								+ " foi alterado nao estando asseguradas a sua autenticidade e integridade!");
				System.out.println("Continuar?");
				System.out.println("1. Sim");
				System.out.println("2. Nao");
				if (s.hasNext()) {
					continua = s.nextInt();
				}
				s.close();
				if (continua == 2)
					return -1;
			}

			// Last modified do ficheiro no servidor
			ret = (Long) in.readObject();
			file.setLastModified(ret);

			System.out.println("Atualizacao de " + novof + " local concluida!");
			temp.delete();

		} catch (IOException e) {
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			e.printStackTrace();
		} catch (KeyStoreException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		}
		return ret;

	}

	/**
	 * Efectua a partilha de ficheiros.
	 * 
	 * @param in
	 *            Stream de rececao de objetos.
	 * @param out
	 *            Stream de envio de objetos.
	 * @param args
	 *            Contem os nomes dos ficheiros que o cliente quer partilhar.
	 * @return O numero de ficheiros partilhados com sucesso.
	 */
	public static int ShareClient(ObjectInputStream in, ObjectOutputStream out,
			String[] args) {

		// Contador de ficheiros partilhados com sucesso
		int conta = 0;
		try {

			// Envia nome do utilizador com quem quer partilhar
			out.writeObject(args[5]);

			// Buscar chave publica do alvo na keystore
			PublicKey outroKey = getOtherpubkey(args[5]);

			if (outroKey == null) {
				System.out.println("Certificado de " + args[5]
						+ " nao existe nesta keystore!");
				out.writeObject(false);
				return 0;
			} else
				out.writeObject(true);

			// Se o user nao existir
			if (!((Boolean) in.readObject())) {
				System.out.println("Utilizador " + args[5] + " nao existe!");
				return 0;
			}

			// Envia o numero de ficheiros
			out.writeObject(args.length - 6);

			// Trata de um ficheiro de cada vez
			for (int i = 6; i < args.length; i++) {
				File fic = new File("./" + args[i]);

				// Escolher dono
				out.writeObject(fic.getName());

				if ((Boolean) in.readObject())
					if (reader(in, out) == -1)
						continue;

				if ((Boolean) in.readObject()) {

					// Receber chave secreta
					SecretKeySpec keySpec2 = getSecretKey(in);

					// Cifrar secreta com chave publica do alvo, enviar
					Cipher c3 = Cipher.getInstance("RSA");
					c3.init(Cipher.WRAP_MODE, outroKey);
					out.writeObject(c3.wrap(keySpec2));
					conta++;
					System.out.println("Ficheiro \"" + fic.getName()
							+ "\" partilhado com sucesso");
				} else
					System.out.println("Erro ao partilhar \"" + fic.getName()
							+ "\"");
			}
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		}

		return conta;
	}

	/**
	 * Vai ao certificado de userp buscar a chave publica.
	 * 
	 * @param userp
	 *            O user alvo.
	 * @return Chave publica de userp.
	 */
	private static PublicKey getOtherpubkey(String userp) {

		PublicKey pkey = null;

		try {
			File file = new File("./keystore/" + username + ".keystore");
			FileInputStream kfile = new FileInputStream(file);
			KeyStore kstore = KeyStore.getInstance("JKS");
			kstore.load(kfile, System.getenv("OTHERUSER_1_JKS_PASSWORD").toCharArray());
			Certificate cert = kstore.getCertificate(userp);
			pkey = (cert == null) ? null : cert.getPublicKey();

		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (KeyStoreException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}

		return pkey;
	}

	private static boolean openKeystore() {

		boolean success = true;

		try {

			FileInputStream kfile = new FileInputStream("./keystore/"
					+ username + ".keystore");
			KeyStore kstore = KeyStore.getInstance("JKS");
			kstore.load(kfile, System.getenv("JKS_PASSWORD").toCharArray());
			Certificate cert = kstore.getCertificate(username);

			if (cert != null) {
				ku = cert.getPublicKey();
				kr = (PrivateKey) kstore.getKey(username,
						System.getenv("JKS_PASSWORD").toCharArray());
				if (ku == null)
					success = false;
			} else {
				success = false;
			}

		} catch (KeyStoreException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (UnrecoverableKeyException e) {
			e.printStackTrace();
		}

		return success;
	}

	/**
	 * Gera uma chave aleatoria para usar com o AES.
	 * 
	 * @param out
	 * @return
	 */
	private static SecretKeySpec makeSecretKey() {

		KeyGenerator kg = null;
		try {

			kg = KeyGenerator.getInstance("AES");
			kg.init(128);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}

		return (SecretKeySpec) kg.generateKey();
	}

	private static SecretKeySpec getSecretKey(ObjectInputStream in) {

		byte[] wrapped;
		SecretKeySpec keySpec2 = null;

		try {

			// receber chave secreta cifrada com chave publica do cliente
			wrapped = (byte[]) in.readObject();

			// decifrar chave com a chave privada do cliente
			Cipher c2 = Cipher.getInstance("RSA");
			c2.init(Cipher.UNWRAP_MODE, kr);
			keySpec2 = (SecretKeySpec) c2.unwrap(wrapped, "AES",
					Cipher.SECRET_KEY);

		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		}

		return keySpec2;
	}

	private static void sendWrappedkey(SecretKeySpec keySpec2,
			ObjectOutputStream out) {

		Cipher c2;
		byte[] wrapped;
		try {
			c2 = Cipher.getInstance("RSA");
			c2.init(Cipher.WRAP_MODE, ku);
			wrapped = c2.wrap(keySpec2);
			out.writeObject(wrapped);

		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private static File makeDeciphedFile(File temp, File novof,
			SecretKeySpec keySpec2) {

		File decipheredFile = null;

		try {

			Cipher c = Cipher.getInstance("AES");
			c.init(Cipher.DECRYPT_MODE, keySpec2);

			// ficheiro origem
			FileInputStream fis = new FileInputStream(temp);
			CipherInputStream cos = new CipherInputStream(fis, c);

			// ficheiro destino
			decipheredFile = new File(novof.getName());
			FileOutputStream fos = new FileOutputStream(decipheredFile);

			// decifra
			byte[] b = new byte[16];
			int i = cos.read(b);
			while (i != -1) {
				fos.write(b, 0, i);
				i = cos.read(b);
			}

			// fechamento dos streams e retorno
			cos.close();
			fos.close();
			fis.close();

		} catch (IOException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		}

		return decipheredFile;
	}

	private static File makeCiphedFile(File fic, SecretKeySpec keySpec2) {

		File cipheredFile = null;

		try {

			// inicializar a cifra com a chave secreta anterior
			Cipher c = Cipher.getInstance("AES");
			c.init(Cipher.ENCRYPT_MODE, keySpec2);

			// ficheiro origem
			FileInputStream fis = new FileInputStream(fic);

			// ficheiro destino temporario
			cipheredFile = new File("./" + "temp");
			FileOutputStream fos = new FileOutputStream(cipheredFile);

			// cifra do ficheiro de origem para o de destino
			CipherOutputStream cos = new CipherOutputStream(fos, c);
			byte[] b = new byte[16];
			int k = fis.read(b);
			while (k != -1) {
				cos.write(b, 0, k);
				k = fis.read(b);
			}
			cos.flush();

			// encerramento dos streams e retorno
			cos.close();
			fos.close();
			fis.close();

		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}

		return cipheredFile;
	}

	/**
	 * Responsavel por verificar as opcoes de entrada (linha de comandos).
	 * 
	 * @param args
	 *            Contem as opcoes do cliente.
	 * @return true se as opcoes forem validas; false caso contrario.
	 */
	private static boolean verifyArgs(String[] args) {
		Boolean res = true;

		if (args.length < 5 || !(args[0].equals("-u"))
				|| !(args[2].equals("-a"))) {
			res = false;
		}

		return res;
	}

	/**
	 * Autenticacao (ou registo).
	 * 
	 * @param in
	 *            Stream de rececao de objetos.
	 * @param out
	 *            Stream de envio de objetos.
	 * @param args
	 *            Contem as opcoes do cliente.
	 * @param pass
	 *            Password a confirmar.
	 * @return true se a autenticacao/registo foi bem sucedida; false caso
	 *         contrario.
	 */
	private static boolean autenticationClient(ObjectInputStream in,
			ObjectOutputStream out, String[] args, String pass) {

		boolean fromServer = false;

		try {
			out.writeObject(args[1]);// UserID

			MessageDigest md = MessageDigest.getInstance("SHA-256");

			md.update(pass.getBytes());

			byte[] mdbytes = md.digest();

			String helloHex = DatatypeConverter.printHexBinary(mdbytes);

			out.writeObject(helloHex);// Password
			out.writeObject(args[4]);// Operacao

			fromServer = (Boolean) in.readObject(); // Resposta
		} catch (IOException e) {
			System.err.println(e.getMessage());
			System.exit(-1);
		} catch (ClassNotFoundException e) {
			System.err.println(e.getMessage());
			System.exit(-1);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return fromServer;
	}

	/**
	 * No caso de haver mais de 1 ficheiro no servidor com o mesmo nome, permite
	 * ao cliente escolher qual deles quer substituir/partilhar/obter.
	 * 
	 * @param in
	 *            Stream de rececao de objetos.
	 * @param out
	 *            Stream de envio de objetos.
	 * @return Opcao escolhida.
	 */
	private static int reader(ObjectInputStream in, ObjectOutputStream out) {

		int ret = 0;

		try {

			// Recebe o numero de ficheiros
			int k = (Integer) in.readObject();

			if (k == 1) {

				k = (Integer) in.readObject();

				System.out.print("Existem " + (k - 1)
						+ " ficheiros com o nome dado. ");
				System.out.println("Escolha uma das seguintes opcoes.");

			} else {

				System.out.print("Existem " + k
						+ " ficheiros com o nome dado. ");
				System.out.println("Qual escolhe?");
			}

			System.out
					.println("(Introduza uma opcao nao incluida para cancelar):");

			/*
			 * O servidor envia Strings que representam textualmente as
			 * hipoteses pelas quais o cliente pode optar
			 */
			int y, opcao = 0;

			for (y = 1; y <= k; y++) {
				System.out.println(" " + y + ": " + (String) in.readObject());
			}

			if (s.hasNext())
				opcao = s.nextInt();

			if (opcao > k || opcao < 1) {
				out.writeObject(-1);
				ret = -1;
			} else {
				out.writeObject(opcao - 1);
				ret = opcao;
			}

		} catch (IOException e) {
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		}

		return ret;
	}

}

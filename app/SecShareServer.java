//package server;

import java.io.*;
import java.net.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.text.*;
import java.util.*;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.*;
import javax.xml.bind.DatatypeConverter;

/**
 * Aplicacao servidor, do servico SecShareServer.
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
public class SecShareServer {
    
	/**
	 * Diretoria raiz do servico.
	 */
	private static String dir = "./Server/";
	private static Mac mac = null;
	private static PublicKey Sku = null;
	private static PrivateKey Skr = null;
    
	/**
	 * Ponto de entrada do servidor.
	 *
	 * @param args
	 *            Contem o porto TCP a utilizar.
	 */
	public static void main(String[] args) {

		System.out.println("servidor: main");
        
		if (args.length != 1) {
			System.out.println("Exemplo de uso: SecShareServer 5665");
			System.exit(-1);
		}
        
		// Abrir keystore do server
		String home = System.getProperty("user.home");
		File file = new File(home + "/.keystore");
        
		if (!file.exists()) {
			System.out
            .println("Por favor coloque o ficheiro \".keystore\" na HOME.");
			return;
		}
        
		if (!openKeystore()) {
			System.out
            .println("Erro ao carregar a keystore. Por favor verifique se existe um alias \'server\' na keystore, ou se a password da keystore esta correta.");
			return;
		}
        
		int porto = -1;
        
		try {
			porto = Integer.parseInt(args[0]);
            
		} catch (NumberFormatException e) {
            
			System.err.println(e.getMessage());
			System.exit(1);
		}
        
		// le a pass para calculo do MAC
		Console console = System.console();
		System.out.print("Insira a password para calculo do MAC: ");
		char[] passArray = console.readPassword();
		String passMac = new String(passArray);
		mac = getMac(passMac);
		passMac = null;
        
		SecShareServer server = new SecShareServer();
		server.startServer(porto);
	}
    
	private static Mac getMac(String passMAC) {
        
		Mac m = null;
		byte[] marray = null;
        
		try {
            
			SecretKey key = new SecretKeySpec(passMAC.getBytes(), "HmacSHA256");
			m = Mac.getInstance("HmacSHA256");
			m.init(key);
			marray = m.doFinal();
		} catch (NoSuchAlgorithmException e){
			e.printStackTrace();
		}
        catch (InvalidKeyException e) {
			e.printStackTrace();
		}
        
		return m;
	}
    
	private static boolean openKeystore() {
        
		boolean success = true;
        
		String home = System.getProperty("user.home");
		File file = new File(home + "/.keystore");
        
		if (!file.exists())
			success = false;
		else {
            
			try {
                
				FileInputStream kfile = new FileInputStream(file);
				KeyStore kstore = KeyStore.getInstance("JKS");
				kstore.load(kfile, System.getenv("SERVER_JKS_PASSWORD").toCharArray());
				Certificate cert = kstore.getCertificate("server");
                
				if (cert != null) {
					Sku = cert.getPublicKey();
					Skr = (PrivateKey) kstore.getKey("server",
                                                     System.getenv("SERVER_JKS_PASSWORD").toCharArray());
					if (Sku == null)
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
		}
        
		return success;
	}
    
	/**
	 * Inicializacao do servidor.
	 *
	 * @param porto
	 *            O porto que vai aceitar as ligacoes dos clientes.
	 */
	private void startServer(int porto) {
        
		// Socket de escuta
		SSLServerSocket sSoc = null;
        
		try {
			SSLServerSocketFactory sslservSF = (SSLServerSocketFactory) SSLServerSocketFactory
            .getDefault();
			sSoc = (SSLServerSocket) sslservSF.createServerSocket(porto);
            
			// Criacao do diretorio do servico (se ainda nao existir)
			File file = new File(dir);
			if (!file.exists()) {
				if (file.mkdir()) {
					System.out.println("Diretoria \"Server\" criada!");
				} else {
					System.out.println("Erro ao criar diretoria \"Server\"!");
					System.exit(-1);
				}
			}
            
			/*
			 * Criacao do ficheiro que armazena os IDs e as respetivas passwords
			 * (se ainda nao existir)
			 */
			File ftxt = new File(dir + "bd.txt");
			if (!ftxt.exists()) {
				if (ftxt.createNewFile()) {
					System.out.println("Ficheiro de base de dados criado!");
					createMAC(ftxt);
					System.out.println("MAC de " + ftxt.getName() + " criado!");
                    
				} else {
					System.out
                    .println("Erro ao criar ficheiro de base de dados!");
					System.exit(-1);
				}
			} else {
                
				macChecker(ftxt);
			}
            
		} catch (IOException e) {
			System.err.println(e.getMessage());
			System.exit(-1);
		} catch (IllegalArgumentException e) {
			System.err.println(e.getMessage());
			System.exit(-1);
		}
        
		/*
		 * Este bloco vai recebendo os pedidos dos clientes. Cada pedido eh
		 * isolado numa thread.
		 */
		System.out.println("Aceitando ligacoes no porto " + porto);
		while (true) {
			try {
				SSLSocket inSoc = (SSLSocket) sSoc.accept();
				System.out.println("\nRecebida ligacao de "
                                   + inSoc.getInetAddress() + ':' + inSoc.getPort());
                
				ServerThread newServerThread = new ServerThread(inSoc);
				newServerThread.start();
				System.out.println(newServerThread);
                
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		// sSoc.close();
	}
    
	private void macChecker(File file) {
		File fileMAC = new File(file.getAbsolutePath() + ".mac");
        
		if (!fileMAC.exists()) {
            
			int opcao = -1;
			System.out.println("Nao existe nenhum mac para " + file.getName());
			System.out.println("O que pretende?");
			System.out.println("1. Terminar");
			System.out.println("2. Recalcular o MAC");
			Scanner s = new Scanner(System.in);
            
			if (s.hasNext())
				opcao = s.nextInt();
			s.close();
            
			if (opcao == 1) {
				System.out.println("Servidor vai terminar...");
				System.exit(-1);
			}
			if (opcao == 2) {
				createMAC(file);
				System.out.println("MAC de " + file.getName() + " criado!");
			} else {
				System.out.println("Opcao errada!");
				System.out.println("Servidor vai terminar...");
				System.exit(-1);
			}
            
		} else {
            
			// Verifica integridade de bd.txt
			if (!verificaMAC(file)) {
				System.err.println("MAC de " + file.getName() + " errado!");
				System.exit(-1);
			} else {
				System.err.println("MAC de " + file.getName() + " correto!");
			}
		}
	}
    
	private static void createMAC(File file) {
        
		try {
			// Criar ficheiro .mac
			File dest = new File(file.getAbsolutePath() + ".mac");
			FileOutputStream fos = new FileOutputStream(dest);
			ObjectOutputStream oos = new ObjectOutputStream(fos);
            
			// Ler do ficheiro file
			FileInputStream fis = new FileInputStream(file);
            
			byte[] bray = new byte[1024];
			int n;
            
			// Processar os conteudos ATUAIS de file usando o mac "geral"
			while ((n = fis.read(bray, 0, 1024)) != -1) {
                
				// processar os dados
				mac.update(bray);
			}
			fis.close();
            
			// Escrever resultado da operacao
			oos.writeObject(mac.doFinal());
			fos.close();
            
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
    
	private static boolean verificaMAC(File toCheck) {
        
		boolean res = true;
        
		try {
            
			// FASE 1 - ESCREVER MAC DO FICHEIRO ATUAL
            
			// Criar ficheiro .mac2
			File dest = new File(toCheck.getAbsolutePath() + ".mac2");
			FileOutputStream fos = new FileOutputStream(dest);
			ObjectOutputStream oos = new ObjectOutputStream(fos);
            
			// Ler do ficheiro toCheck
			FileInputStream fis = new FileInputStream(toCheck);
            
			byte[] bray = new byte[1024];
			int n;
            
			// Processar os conteudos ATUAIS de toCheck usando o mac "geral"
			while ((n = fis.read(bray, 0, 1024)) != -1) {
                
				// processar os dados
				mac.update(bray);
			}
			fis.close();
            
			// escrever resultado da operacao
			oos.writeObject(mac.doFinal());
			fos.close();
            
			// FASE 2 - COMPARAR
            
			File currentMAC = new File(toCheck.getAbsolutePath() + ".mac");
			res = compareF(dest, currentMAC);
			dest.delete();
            
		} catch (IOException e) {
			e.printStackTrace();
		}
        
		return res;
	}
    
	private static boolean compareF(File f1, File f2) {
        
		boolean res = true;
		try {
			// Ler de 1
			FileInputStream fis = new FileInputStream(f1);
            
			// Ler de 2
			FileInputStream fis2 = new FileInputStream(f2);
            
			byte[] bray = new byte[1024];
			byte[] bray2 = new byte[1024];
			int n1, n2;
            
			while (true) {
				n1 = fis.read(bray, 0, 1024);
				n2 = fis2.read(bray2, 0, 1024);
                
				if (n1 == n2 && n1 == -1)
					break;
                
				// Comparar conteudos dos arrays
				if (!Arrays.equals(bray, bray2)) {
					res = false;
					break;
				}
			}
            
		} catch (IOException e) {
			e.printStackTrace();
		}
        
		return res;
	}
    
	/**
	 * Threads utilizadas para comunicacao com os clientes.
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
	private class ServerThread extends Thread {
        
		/**
		 * Nome de utilizador.
		 */
		private String user;
        
		/**
		 * Password de utilizador.
		 */
		private String pass;
        
		/**
		 * Operacao que o cliente pretende efectuar.
		 */
		private String op;
        
		/**
		 * Socket de ligacao.
		 */
		private Socket socket = null;
        
		/**
		 * Recebe o socket de ligacao para o qual se vai ler e/ou escrever.
		 *
		 * @param inSoc
		 *            O socket de ligacao de um cliente.
		 */
		ServerThread(Socket inSoc) {
			socket = inSoc;
		}
        
		/**
		 * Efectua as operacoes no servidor.
		 */
		public void run() {
            
			try {
				/*
				 * Preparacao dos streams de entrada e saida, associados ao
				 * socket de ligacao recebido anteriormente.
				 */
				ObjectOutputStream outStream = new ObjectOutputStream(
                                                                      socket.getOutputStream());
                
				ObjectInputStream inStream = new ObjectInputStream(
                                                                   socket.getInputStream());
                
				user = (String) inStream.readObject();
				pass = (String) inStream.readObject();
				op = (String) inStream.readObject();
                
				// Fase de autenticacao
				if (!autentication()) {
					outStream.writeObject(false);
					socket.close();
					return; // Fechar esta thread
				} else {
					outStream.writeObject(true);
				}
                
				pass = null; // Deixa de referenciar a password
                
				System.out
                .println("======== Utilizador: " + user + " ========");
                
				
				if (op.equals("-c")) {
					copyFile(inStream, outStream);
				} else if (op.equals("-p")) {
					shareFile(inStream, outStream);
				} else if (op.equals("-s")) {
					SynchFile(inStream, outStream);
				} else if (op.equals("-l")) {
					ListFiles(inStream, outStream);
				} else if (op.equals("-g")) {
					Menos_G(inStream, outStream);
				} else
					return;
                
			} catch (IOException e) {
				e.printStackTrace();
			} catch (ClassNotFoundException e) {
				e.printStackTrace();
			}
		}
        
		/**
		 * Efectua a copia dos ficheiros no servidor.
		 *
		 * @param inStream
		 *            Stream de rececao de objetos
		 * @param outStream
		 *            Stream de envio de objetos
		 */
		public void copyFile(ObjectInputStream inStream,
                             ObjectOutputStream outStream) {
            
			int numf;
            
			try {
				numf = (Integer) inStream.readObject();
                
				boolean reuse;
                
				// Para cada ficheiro...
				for (int j = 0; j < numf; j++) {
                    
					/*
					 * necessario pedir chave AES nova para cada ficheiro
					 * EXCEPTO no caso de atualizacao de um ficheiro ja
					 * existente!
					 */
					reuse = false;
                    
					String nomef = null;
                    
					// Decide se o userFiles.txt do user deve ser atualizado.
					boolean replaceUFtxt = false;
					boolean replaceUFtxt2 = false;
					nomef = (String) inStream.readObject();
					if (nomef == null)
						continue; // saltar para o proximo
                    
					// Fase de escolha do dono
					String dono = null;
					int numDonos = 0;
					ArrayList<String> donos = ficheiroExiste(nomef);
					numDonos = donos.size();
                    
					if (numDonos > 1 && donos.contains(user)) {
						outStream.writeObject(true);
                        
						// Envio das opcoes ao cliente
						outStream.writeObject(numDonos);
						for (String elem : donos) {
							outStream.writeObject("\"" + nomef
                                                  + "\" criado por " + elem);
						}
                        
						// Resposta do cliente
						int opcao = (Integer) inStream.readObject();
                        
						if (opcao == -1)
							continue; // cliente cancelou...
                        
						dono = donos.get(opcao);
						System.out.println("Dono escolhido para copia eh "
                                           + dono);
                        
						// Neste caso o ficheiro ja existe (no dono)
						replaceUFtxt = false;
                        
						/*
						 * este caso eh sempre relativo a uma atualizacao, como
						 * tal a chave AES (que user vai buscar a area remota do
						 * proprio, e consoante o dono) vai ser reusada.
						 */
						reuse = true;
                        
					} else if (numDonos >= 1 && !donos.contains(user)) {
                        
						/*
						 * user pode querer substituir um ficheiro partilhado ou
						 * introduzir um novo ficheiro no seu proprio diretorio.
						 */
						donos.add(user);
						outStream.writeObject(true);
						outStream.writeObject(1);
						outStream.writeObject(numDonos + 1);
						for (int i = 0; i < numDonos; i++)
							outStream.writeObject("\"" + nomef
                                                  + "\" criado por " + donos.get(i));
                        
						outStream.writeObject("Ou quer copiar para a sua area"
                                              + " particular?");
                        
						// Resposta do cliente
						int opcao = (Integer) inStream.readObject();
                        
						if (opcao == -1)
                            
							continue;
                        
						dono = donos.get(opcao);
						System.out.println("Dono escolhido para copia eh "
                                           + dono);
                        
						// novo ficheiro => pode atualizar userfiles.txt
						if (dono.equals(user)){
							replaceUFtxt = true;
						}
						else
							reuse = true; // ficheiro existente => reusar chave
                        
					} else {
                        
						/*
						 * Neste caso o utilizador pode substituir um ficheiro
						 * seu (com o mesmo nome) ou meter um novo.
						 */
						outStream.writeObject(false);
						dono = user;
                        
						// Se meteu um novo ficheiro...
                        
						if (numDonos == 0){
                            
							replaceUFtxt = true;
							replaceUFtxt2 = true;
						}
						else
							reuse = true; // ficheiro existente => reusar chave
                        
					}
                    
					/*
					 * Nesta fase o ficheiro a criar/substituir ja esta
					 * decidido!
					 */
					File novof = new File(dir + dono + "/" + nomef);
                    
					long LastMod;
                    
					// Verifica se data + recente
					if ((LastMod = (Long) inStream.readObject()) > new File(
                                                                            novof.getPath()).lastModified()) {
                        
						// Dizer ao cliente para iniciar a transferencia
						outStream.writeObject(true);
                        
						// Enviar reuse para o cliente se preparar
						outStream.writeObject(reuse);
                        
						if (reuse) {
							System.out
                            .println("Chave AES vai ser reutilizada!");
							File keyinFile = new File(dir + user + "/" + nomef
                                                      + "." + dono + ".key");
							sendWrappedkey(keyinFile, outStream);
						} else {
							System.out
                            .println("Nova chave AES vai ser gerada!");
						}
                        
						// Receber a assinatura deste ficheiro e colocar na
						// pasta do dono
						byte[] signature = DatatypeConverter
                        .parseHexBinary((String) inStream.readObject());
						File signFile = new File(dir + dono + "/" + nomef
                                                 + ".sig");
						FileOutputStream sigfos = new FileOutputStream(signFile);
						sigfos.write(signature);
						sigfos.close();
                        
						// Receber a chave (cifrada) deste ficheiro
						byte[] keyEncoded = (byte[]) inStream.readObject();
                        
						FileOutputStream kos = new FileOutputStream(dir + user
                                                                    + "/" + nomef + "." + dono + ".key");
						kos.write(keyEncoded);
						kos.close();
                        
						FileOutputStream fos = new FileOutputStream(novof);
                        
						byte[] bray = new byte[1024];
						int n = 0, m = 0;
						long tamf = (Long) inStream.readObject();
                        
						// Receber criptograma e atribuir data de ultima
						// modificacao
						while (m != tamf) {
                            
							// checkar para valores < 1024
							n = inStream.read(bray, 0,
                                              (int) ((tamf - m) >= 1024 ? 1024
                                                     : (tamf - m)));
                            
							fos.write(bray, 0, n);
							m += n;
						}
						novof.setLastModified(LastMod);
						fos.close();
                        
						/*
						 * dono = user && ficheiro copiado nao tiver existido
						 * anteriormente no diretorio * de user => atualizar
						 * userFiles
						 */
                        
						if (replaceUFtxt == true) {
                            
							File filet = new File(dir + user + "/userFiles.txt");
                            
							macChecker(filet);
                            
							FileOutputStream reg = new FileOutputStream(filet,
                                                                        true);
							reg.write((nomef + " " + dono + " : " + dono + "\r\n")
                                      .getBytes());
							reg.close();
							createMAC(filet);
							System.out.println("MAC de " + filet.getName()
                                               + " atualizado!");
                            
						} else {
                            
							// Apenas atualizar nome de quem fez ultima
							// modificacao ( este user )
							updtLastUser(dono, novof.getName());
						}
                        
						System.out.println("Escrita de " + novof.getName()
                                           + " concluida");
                        
					} else {
						//o que esta dentro deste if nao existia porque o de cima n era executado uma vez que a comparaçao das datas dava sempre /////falso
						if (replaceUFtxt2 == true) {
                            // Dizer ao cliente para iniciar a transferencia
                            outStream.writeObject(true);
                            System.out.println("iuiuiuiu");
                            // Enviar reuse para o cliente se preparar
                            outStream.writeObject(reuse);
                            
                            if (reuse) {
                                System.out
                                .println("Chave AES vai ser reutilizada!");
                                File keyinFile = new File(dir + user + "/" + nomef
                                                          + "." + dono + ".key");
                                sendWrappedkey(keyinFile, outStream);
                            } else {
                                System.out
                                .println("Nova chave AES vai ser gerada!");
                            }
                            
                            // Receber a assinatura deste ficheiro e colocar na
                            // pasta do dono
                            byte[] signature = DatatypeConverter
                            .parseHexBinary((String) inStream.readObject());
                            File signFile = new File(dir + dono + "/" + nomef
                                                     + ".sig");
                            FileOutputStream sigfos = new FileOutputStream(signFile);
                            sigfos.write(signature);
                            sigfos.close();
                            
                            // Receber a chave (cifrada) deste ficheiro
                            byte[] keyEncoded = (byte[]) inStream.readObject();
                            
                            FileOutputStream kos = new FileOutputStream(dir + user
                                                                        + "/" + nomef + "." + dono + ".key");
                            kos.write(keyEncoded);
                            kos.close();
                            
                            FileOutputStream fos = new FileOutputStream(novof);
                            
                            byte[] bray = new byte[1024];
                            int n = 0, m = 0;
                            long tamf = (Long) inStream.readObject();
                            
                            // Receber criptograma e atribuir data de ultima
                            // modificacao
                            while (m != tamf) {
                                
                                // checkar para valores < 1024
                                n = inStream.read(bray, 0,
                                                  (int) ((tamf - m) >= 1024 ? 1024
                                                         : (tamf - m)));
                                
                                fos.write(bray, 0, n);
                                m += n;
                            }
                            novof.setLastModified(LastMod);
                            fos.close();
                            
                            
							File filet = new File(dir + user + "/userFiles.txt");
                            
							macChecker(filet);
                            
							FileOutputStream reg = new FileOutputStream(filet,
                                                                        true);
							reg.write((nomef + " " + dono + " : " + dono + "\r\n")
                                      .getBytes());
							reg.close();
							createMAC(filet);
							System.out.println("MAC de " + filet.getName()
                                               + " atualizado!");
                            
                            
						}
						else{
							System.out.println("Nao eh preciso atualizar \""
                                               + novof.getName() + "\"");
							outStream.writeObject(false);
						}
					}
                    
				}
                
			} catch (ClassNotFoundException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}
            
		}
        
		private void updtLastUser(String dono, String filename) {
            
			File fdono = new File(dir + dono + "/userFiles.txt");
			macChecker(fdono);
			File temp4 = new File(dir + dono + "/temp2");
			try {
				// temp4.createNewFile();
                
				FileOutputStream reg2 = new FileOutputStream(temp4, true);
				Scanner scan = new Scanner(fdono);
                
				while (scan.hasNext()) {
                    
					String linha = scan.nextLine();
                    
					String[] line = linha.split(" ");
                    
					if (line[0].equals(filename) && line[1].equals(dono)) {
                        
						String[] l = linha.split(" : ");
						reg2.write((l[0] + " : " + user + "\r\n").getBytes());
					} else {
						reg2.write((linha + "\r\n").getBytes());
					}
                    
				}
				scan.close();
				reg2.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
            
			temp4.renameTo(fdono);
			createMAC(fdono);
			System.out.println("MAC de " + fdono.getName() + " atualizado!");
            
		}
        
		private void Menos_G(ObjectInputStream inStream,
                             ObjectOutputStream outStream) {
            
			int numf;
            
			try {
                
				numf = (Integer) inStream.readObject();
				for (int j = 0; j < numf; j++) {
                    
					// Recepcao de nome do ficheiro
					String nomef = (String) inStream.readObject();
					if (nomef == null)
						continue;
                    
					// Fase de escolha de dono
					String dono = null;
                    
					int numDonos = 0;
					ArrayList<String> donos = ficheiroExiste(nomef);
					numDonos = donos.size();
                    
					if (numDonos > 1) {
                        
						outStream.writeObject(true);
						outStream.writeObject(numDonos);
                        
						// Agora o cliente tera de escolher o dono
						for (String elem : donos) {
							outStream.writeObject("\"" + nomef
                                                  + "\" criado por " + elem);
						}
                        
						// Resposta do cliente
						int opcao = (Integer) inStream.readObject();
                        
						if (opcao == -1) {
							System.out.println("Cancelou partilha de");
							continue;
						}
                        
						dono = donos.get(opcao);
					} else if (numDonos == 1) {
						outStream.writeObject(false);
						dono = donos.get(0);
					} else {
						System.out.println("\"" + nomef + "\" nao existe!");
						outStream.writeObject(false);
						outStream.writeObject(false);
						continue;
					}
					outStream.writeObject(true);
                    
					// Fase de operacao
					File f = new File(dir + dono + "/" + nomef);
                    
					// Last modified do cliente
					long lastModC = (Long) inStream.readObject();
                    
					System.out.println(" user " + lastModC);
					System.out.println("server " + f.lastModified());
                    
					// Se a versao no servidor for mais recente...
					if (f.lastModified() > lastModC) {
						outStream.writeObject(true);
						copy_S_to_C(outStream, f, dono);
					} else {
						outStream.writeObject(false);
						System.out.println("Nao eh preciso enviar \""
                                           + f.getName() + "\" para " + user);
					}
				}
                
			} catch (ClassNotFoundException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
        
		private void SynchFile(ObjectInputStream inStream,
                               ObjectOutputStream outStream) {
            
			ArrayList<String> files = new ArrayList<String>();
			ArrayList<String> donos1 = new ArrayList<String>();
			Scanner scan;
			int h = 0, esc = 0;
			String s = null;
			try {
                
				for (int numf = (Integer) inStream.readObject(); numf > 0; numf--) {
                    
					h = 0;
					esc = 0;
					// le o nome do file
					s = (String) inStream.readObject();
					File fic = new File(dir + user + "/userFiles.txt");
                    
					macChecker(fic);
                    
					scan = new Scanner(fic);
					ArrayList<String> donos = new ArrayList<String>();
					String[] args = null;
                    
					// Procura o nome do ficheiro
					while (scan.hasNextLine()) {
                        
						args = scan.nextLine().split(" ");
                        
						if (args[0].equals((s))) {
							// files.add(s);
							donos.add(args[1]);
							h++;
							System.out.println("Fichero " + s + " existe em "
                                               + args[1]);
						}
					}
                    
					if (h == 0) {
						System.out.println("Fichero " + s + " nao existe!");
						outStream.writeObject(h);
						continue;
					}
                    
					if (h > 1) {
                        
						outStream.writeObject(h);
                        
						for (int u = 0; u < donos.size(); u++) {
                            
							String msg = " - " + (u + 1) + " " + s + " Dono: "
                            + donos.get(u);
                            
							outStream.writeObject(msg);
                            
						}
                        
						esc = (Integer) inStream.readObject();
						if ((esc) == -1) {
							scan.close();
							return;
						}
                        
						donos1.add(donos.get(esc - 1));
						files.add(s);
					}
					if (h == 1) {
						files.add(s);
						donos1.add(donos.get(0));
						outStream.writeObject(h);
					}
				}
                
				if (files.size() > 0) {
					outStream.writeObject(true);
					new Sync(inStream, outStream, files, donos1);
				} else {
					System.out
                    .println("Nao existe nenhum ficheiro para sincronizar");
					outStream.writeObject(false);
					return;
				}
                
			} catch (ClassNotFoundException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
        
		public class Sync {
			Timer timer;
			ObjectInputStream in;
			ObjectOutputStream out;
            
			public Sync(ObjectInputStream in, ObjectOutputStream out,
                        ArrayList<String> files, ArrayList<String> donos) {
                
				timer = new Timer();
				this.in = in;
				this.out = out;
				timer.schedule(new ola(files, donos), 0, 6000);
			}
            
			class ola extends TimerTask {
                
				ArrayList<String> files = new ArrayList<String>();
				ArrayList<Long> last = new ArrayList<Long>();
				ArrayList<String> donos = new ArrayList<String>();
                
				public ola(ArrayList<String> files, ArrayList<String> donos) {
					this.files = files;
					this.donos = donos;
				}
                
				public void run() {
                    
					try {
						File f = null;
						int i = 0;
						for (String s : files) {
							f = new File(dir + donos.get(i) + "/" + s);
							last.add(f.lastModified());
							out.writeObject(f.lastModified());
							out.flush();
							i++;
						}
                        
						int escolha = 0;
                        
						for (int g = 0; g < files.size(); g++) {
                            
							escolha = (Integer) in.readObject();
							File f1 = new File(dir + donos.get(g) + '/'
                                               + files.get(g));
							if (escolha == 1) {
								copy_S_to_C(out, f1, donos.get(g));
							} else if (escolha == 2) {
                                
								File keyinFile = new File(dir + user + "/"
                                                          + f1.getName() + "." + donos.get(g)
                                                          + ".key");
								sendWrappedkey(keyinFile, out);
								long ret = copy_C_to_S(in, f1);
								f1.setLastModified(ret);
                                
								// atualizar nome de quem fez ultima modificacao
								// ( este user )
								updtLastUser(donos.get(g), f1.getName());
                                
							} else {
								System.out
                                .println("Preciso de fazer nada para "
                                         + f1.getName());
								continue;
							}
						}
						last.clear();
					} catch (EOFException e) {
						return;
					} catch (SocketException e) {
						return;
					} catch (ClassNotFoundException e) {
						e.printStackTrace();
					} catch (IOException e) {
						e.printStackTrace();
					}
				}
			}
		}
        
		/**
		 * Autenticacao. Tambem eh responsavel pelo registo de um utilizador no
		 * sistema se necessario.
		 *
		 * @return true se a autenticacao foi bem sucedida; false caso contrario
		 */
		private boolean autentication() {
            
			Boolean res = true;
            
			// Consultar o ficheiro "base de dados"
			File bdf = new File(dir + "bd.txt");
            
			macChecker(bdf);
            
			try {
				Scanner scan = new Scanner(bdf);
                
				boolean registered = false;
                
				while (scan.hasNext()) {
                    
					String[] upass = scan.nextLine().split(":");
                    
					/*
					 * Procurar nome do utilizador. De cada vez que falha volta
					 * a procurar na proxima linha, ate nao haver mais nomes a
					 * percorrer.
					 */
					if (upass[0].equals(user)) {
						registered = true;
                        
						/*
						 * Testar se a password fornecida eh a correta para este
						 * utilizador.
						 */
						if (!upass[1].equals(pass)) {
							res = false;
						}
						break;
					}
				}
                
				scan.close();
                
				/*
				 * Se registered eh false, entao o utilizador nao consta na base
				 * de dados. Eh necessario regista-lo no sistema.
				 */
				if (!registered)
					res = registration();
                
			} catch (FileNotFoundException e) {
				System.err.print(e.getMessage());
				System.exit(-1);
			}
            
			return res;
		}
        
		/**
		 * Efectua o registo de um utilizador.
		 *
		 * @return true se o registo foi bem sucedido; false caso contrario
		 */
		private boolean registration() {
            
			Boolean res = true;
            
			try {
                
				/*
				 * Atualizar o ficheiro "base de dados" e criar a diretoria do
				 * cliente
				 */
				File bdf = new File(dir + "bd.txt");
                
				macChecker(bdf);
                
				FileOutputStream reg = new FileOutputStream(bdf, true);
				File file = new File(dir + user);
                
				if (!file.exists()) {
					if (file.mkdir()) {
                        
						System.out
                        .println("Diretorio \"" + user + "\" criado!");
                        
						File userFiles = new File(dir + user + "/userFiles.txt");
						userFiles.createNewFile();
						createMAC(userFiles);
						System.out.println("userFiles para " + user
                                           + " criado!");
						System.out.println("MAC de " + userFiles.getName()
                                           + " criado!");
                        
						/*
						 * Atualizar no ficheiro "base de dados" os dados do
						 * cliente. O formato vai ter de ser user:password
						 */
						reg.write((user + ":" + pass + "\r\n").getBytes());
						createMAC(bdf);
						System.out.println("MAC de " + bdf.getName()
                                           + " atualizado!");
                        
					} else {
						System.out.println("Erro ao criar diretorio \""
                                           + file.getPath() + "\"");
						res = false;
					}
				} else {
					reg.write((user + ":" + pass + "\r\n").getBytes());
					createMAC(bdf);
					System.out.println("MAC de " + bdf.getName()
                                       + " atualizado!");
				}
                
				reg.close();
                
			} catch (IOException e) {
				e.printStackTrace();
			}
            
			return res;
		}
        
		private File getCiphedFile(File fic, SecretKeySpec skey) {
            
			File cipheredFile = null;
            
			try {
                
				// inicializar cifra
				Cipher c = Cipher.getInstance("AES");
				c.init(Cipher.ENCRYPT_MODE, skey);
                
				// ficheiro origem
				FileInputStream fis = new FileInputStream(fic);
                
				// ficheiro destino temporario
				cipheredFile = new File("./Server/" + "temp"); // tinha temp.txt
				FileOutputStream fos = new FileOutputStream(cipheredFile);
                
				// cifra do ficheiro de origem para o de destino
				CipherOutputStream cos = new CipherOutputStream(fos, c);
				byte[] b = new byte[16];
				int k = fis.read(b);
				while (k != -1) {
					cos.write(b, 0, k);
					k = fis.read(b);
				}
                
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
		 * Faz a decifra do ficheiro temp,
		 *
		 * @param temp
		 *            Ficheiro a decifrar.
		 * @param novof
		 *            Ficheiro para o qual se vai escrever.
		 * @param skey
		 *            Chave AES para decifrar.
		 * @return Ficheiro decifrado (mesmo que novof)
		 */
		private File getDeciphedFile(File temp, File novof, SecretKeySpec skey) {
            
			File decipheredFile = null;
            
			try {
                
				// inicializar decifra
				Cipher c = Cipher.getInstance("AES");
				c.init(Cipher.DECRYPT_MODE, skey);
                
				// ficheiro origem
				FileInputStream fis = new FileInputStream(temp);
				CipherInputStream cos = new CipherInputStream(fis, c);
                
				// ficheiro destino
				decipheredFile = new File(novof.getAbsolutePath());
				FileOutputStream fos = new FileOutputStream(decipheredFile);
                
				// decifra
				byte[] b = new byte[16];
				int i = cos.read(b);
				while (i != -1) {
					fos.write(b, 0, i);
					i = cos.read(b);
				}
                
				// fechamento dos streams e retorno
				fis.close();
				fos.close();
				cos.close();
                
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
        
		/**
		 * Efectua a partilha dos ficheiros no servidor.
		 *
		 * @param inStream
		 *            Stream de rececao de objetos
		 * @param outStream
		 *            Stream de envio de objetos
		 */
		private void shareFile(ObjectInputStream inStream,
                               ObjectOutputStream outStream) {
            
			int numf;
            
			try {
                
				String userp = (String) inStream.readObject();
                
				if (!(Boolean) inStream.readObject()) {
					System.out.println(user + " nao possui certificado de "
                                       + userp);
					return;
				}
                
				// Verifica se user com quem quer partilhar existe
				if (userExists(userp))
					outStream.writeObject(true);
				else {
					System.out.println(userp + " nao existe!");
					outStream.writeObject(false);
					socket.close();
					return;
				}
                
				numf = (Integer) inStream.readObject();
                
				// Para cada ficheiro...
				for (int j = 0; j < numf; j++) {
                    
					// Le nome do ficheiro
					String nomef = (String) inStream.readObject();
                    
					// Fase de escolha do dono
					// escolha do dono em -p*
					int numDonos = 0;
					String dono = null;
					ArrayList<String> donos = ficheiroExiste(nomef);
					numDonos = donos.size();
                    
					if (numDonos > 1) {
                        
						outStream.writeObject(true);
						outStream.writeObject(numDonos);
                        
						// Agora o cliente tera de escolher o dono
						for (String elem : donos) {
							outStream.writeObject("\"" + nomef
                                                  + "\" criado por " + elem);
						}
                        
						// Resposta do cliente
						int opcao = (Integer) inStream.readObject();
                        
						if (opcao == -1)
							continue;
                        
						dono = donos.get(opcao);
					} else if (numDonos == 1) {
						outStream.writeObject(false);
						dono = donos.get(0);
					} else {
						System.out.println("\"" + nomef + "\" nao existe!");
						outStream.writeObject(false);
						outStream.writeObject(false);
						continue;
					}
					System.out.println("Dono escolhido para a partilha: "
                                       + dono);
                    
					// Verificar se partilha ja existe
					boolean shared = false;
                    
					File f1 = new File(dir + dono + "/userFiles.txt");
                    
					macChecker(f1);
                    
					Scanner scan = new Scanner(f1);
                    
					String[] sargs = null;
					while (scan.hasNextLine()) {
                        
						sargs = scan.nextLine().split(" ");
						// System.out.println(sargs.toString());
						if (sargs[0].equals(nomef) && sargs[1].equals(dono)) {
                            
							System.out.println(dono + " tem ficheiro!");
							for (String elem : sargs) {
                                
								// Se os dois tiverem o ficheiro
								if (elem.contains(userp)) {
									System.out
                                    .println(userp + " tem ficheiro!");
									// ... entao a partilha ja existe!
									shared = true;
									break;
								}
							}
                            
						}
						if (shared)
							break;
					}
					scan.close();
                    
					if (shared) {
						System.out.println("Partilha de \"" + nomef
                                           + "\" entre " + dono + " e " + userp
                                           + " ja existe!");
						outStream.writeObject(false);
						continue;
                        
					} else {
                        
						outStream.writeObject(true);
                        
						// Atualizar userFiles do alvo
						File fuserp = new File(dir + userp + "/userFiles.txt");
						macChecker(fuserp);
						FileOutputStream reg = new FileOutputStream(fuserp,
                                                                    true);
                        
						reg.write((nomef + " " + dono + "\r\n").getBytes());
						reg.close();
                        
						createMAC(fuserp);
						System.out.println("MAC de " + fuserp.getName()
                                           + " atualizado!");
                        
						// Actualizar userFiles do dono
						File fdono = new File(dir + dono + "/userFiles.txt");
						macChecker(fdono);
						File temp4 = new File(dir + dono + "/temp2");
						FileOutputStream reg2 = new FileOutputStream(temp4,
                                                                     true);
                        
						scan = new Scanner(fdono);
						while (scan.hasNext()) {
                            
							String linha = scan.nextLine();
                            
							String[] line = linha.split(" ");
                            
							if (line[0].equals(nomef) && line[1].equals(dono)) {
                                
								String[] l = linha.split(" : ");
								reg2.write((l[0] + " " + userp + " : " + l[1] + "\r\n")
                                           .getBytes());
							} else {
								reg2.write((linha + "\r\n").getBytes());
							}
                            
						}
						scan.close();
						reg2.close();
                        
						temp4.renameTo(fdono);
						createMAC(fdono);
						System.out.println("MAC de " + fdono.getName()
                                           + " atualizado!");
                        
						// Substituir
						/*
						 * if (!temp.renameTo(f1)) { System.out
						 * .println("Nao foi possivel alterar o userFiles" +
						 * " do dono!"); outStream.writeObject(false); continue;
						 * }
						 */
                        
						// Enviar chave secreta cifrada ao user
						// NOTA: Isto so funciona se dono = user..? testar
						File keyinFile = new File(dir + user + "/" + nomef
                                                  + "." + dono + ".key");
						sendWrappedkey(keyinFile, outStream);
                        
						System.out.println("Partilha de \"" + nomef
                                           + "\" feita!");
                        
						// receber chave secreta (cifrada com publica de userp)
						byte[] key = (byte[]) inStream.readObject();
						File n = new File(dir + "/" + userp + "/" + nomef + "."
                                          + dono + ".key");
						reg = new FileOutputStream(n, true);
						reg.write(key);
						reg.close();
					}
                    
				}
                
			} catch (ClassNotFoundException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
        
		/**
		 * Efetua a copia de um ficheiro do cliente para o servidor.
		 * 
		 * @param in
		 * @param novof
		 * @param user
		 * @return Last modified do ficheiro vindo do cliente.
		 */
		public long copy_C_to_S(ObjectInputStream in, File novof) {
            
			long ret = 0;
            
			try {
                
				FileOutputStream fos = new FileOutputStream(novof);
                
				byte[] bray = new byte[1024];
				int n, m = 0;
				long tamf;
                
				tamf = (Long) in.readObject();
                
				while (m != tamf) {
					n = in.read(bray, 0, (int) ((tamf - m) >= 1024 ? 1024
                                                : (tamf - m)));
					fos.write(bray, 0, n);
					m += n;
				}
                
				ret = (Long) in.readObject();
                
				fos.close();
				System.out.println("Atualizacao de " + novof
                                   + " no server concluida");
			} catch (ClassNotFoundException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}
            
			return ret;
		}
        
		/**
		 * Efetua a copia do ficheiro fic do servidor para o cliente. User
		 * possui a chave cifrada a enviar.
		 * 
		 * @param outStream
		 *            Stream de envio de objetos.
		 * @param fic
		 *            Ficheiro a enviar.
		 * @param dono
		 *            User que possui o ficheiro cifrado (fic).
		 */
		private void copy_S_to_C(ObjectOutputStream outStream, File fic,
                                 String dono) {
            
			byte[] bray = new byte[1024];
			int n;
			FileInputStream fis;
            
			try {
                
				System.out.println("A enviar ficheiro " + fic.getName()
                                   + " para " + user + " ...");
                
				// Enviar tamanho do ficheiro, iniciar transferencia
				long t = fic.length();
				outStream.writeObject(t);
                
                
				fis = new FileInputStream(fic);
				while ((n = fis.read(bray, 0, 1024)) != -1) {
					outStream.write(bray, 0, n);
				}
				outStream.flush();
				fis.close();
                
				// Enviar chave secreta (cifrada) deste ficheiro
				File keyinFile = new File(dir + user + "/" + fic.getName()
                                          + "." + dono + ".key");
				sendWrappedkey(keyinFile, outStream);
                
				// Enviar assinatura
				File signFile = new File(dir + dono + "/" + fic.getName()
                                         + ".sig");
                
				// bytes da assinatura (signFile) vao para o sigToVerify
				FileInputStream sigfis = new FileInputStream(signFile);
				byte[] sigToVerify = new byte[sigfis.available()];
				sigfis.read(sigToVerify);
				sigfis.close();
				String helloHex = DatatypeConverter.printHexBinary(sigToVerify);
                
				outStream.writeObject(helloHex);
				
				//manda também nome do ultimo user a alterar
				File ultFile = new File(dir + dono + "/userFiles.txt");
				System.out.println(ultFile.getName());
				Scanner scan = new Scanner(ultFile);
				
				while (scan.hasNext()) {
                    
					String linha = scan.nextLine();
					String[] line = linha.split(" ");
					
                    
					if (line[0].equals(fic.getName()) && line[1].equals(dono)) {
						outStream.writeObject(line[line.length - 1]);
						
					} 
				}
                
				// Enviar last modified do server
				long l = fic.lastModified();
				outStream.writeObject(l);
                
				System.out.println("Envio de ficheiro \"" + fic.getName()
                                   + "\" concluido");
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
        
		/**
		 * Verifica se userp existe no ficheiro de "base de dados".
		 * 
		 * @param userp
		 *            O user a encontrar.
		 * @return true se userp foi encontrado; false caso contrario.
		 */
		private boolean userExists(String userp) {
            
			boolean exists = false;
			Scanner scan = null;
			File bdf = new File(dir + "bd.txt");
            
			macChecker(bdf);
            
			try {
				scan = new Scanner(bdf);
                
			} catch (FileNotFoundException e) {
				e.printStackTrace();
				System.exit(-1);
			}
            
			while (scan.hasNext()) {
                
				String[] upass = scan.nextLine().split(":");
                
				if (upass[0].equals(userp)) {
					exists = true;
					break;
				}
                
			}
            
			scan.close();
			return exists;
		}
        
		/**
		 * Procura os ficheiros com o mesmo nome que nomef, e adiciona os
		 * respetivos donos numa lista.
		 * 
		 * @param nomef
		 *            O nome do ficheiro a procurar.
		 * @return Uma lista de donos de ficheiros com o nome especificado.
		 */
		private ArrayList<String> ficheiroExiste(String nomef) {
            
			// Abrir userfiles do utilizador atual
			Scanner scan;
			try {
				File userfiles = new File(dir + user + "/userFiles.txt");
                
				macChecker(userfiles);
                
				scan = new Scanner(userfiles);
                
			} catch (IOException e) {
				e.printStackTrace();
				return null;
			}
            
			/*
			 * Lista de donos. O cliente vai poder escolher qual o ficheiro que
			 * pretende substituir/partilhar.
			 */
			ArrayList<String> donos = new ArrayList<String>();
            
			// Procura o nome do ficheiro
			while (scan.hasNextLine()) {
                
				String[] args = scan.nextLine().split(" ");
                
				if (args[0].equals((nomef))) {
					// Armazenar o nome do dono no arraylist
					donos.add(args[1]);
				}
			}
            
			scan.close();
            
			return donos;
		}
        
		/**
		 * Envia ao cliente uma chave cifrada.
		 * 
		 * @param keyinFile
		 *            Ficheiro com a chave cifrada.
		 * @param outStream
		 *            Stream de envio de objetos.
		 */
		private void sendWrappedkey(File keyinFile, ObjectOutputStream outStream) {
            
			try {
				byte[] keyEncoded2 = new byte[(int) keyinFile.length()];
                
				FileInputStream kos = new FileInputStream(keyinFile);
				kos.read(keyEncoded2);
				outStream.writeObject(keyEncoded2);
				kos.close();
                
			} catch (FileNotFoundException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
        
		/**
		 * Gera uma chave aleatoria para usar com o AES.
		 * 
		 * @return Nova chave secreta AES.
		 */
		private SecretKeySpec makeSecretKey() {
            
			KeyGenerator kg = null;
			try {
                
				kg = KeyGenerator.getInstance("AES");
				kg.init(128);
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			}
            
			return (SecretKeySpec) kg.generateKey();
		}
        
		private void ListFiles(ObjectInputStream inStream,
                               ObjectOutputStream outStream) {
            
			try {
				File fic = new File(dir + user + "/userFiles.txt");
                
				macChecker(fic);
                
				Scanner scan = new Scanner(fic);
				String dono = user;
                
				// Procura o nome do ficheiro
				while (scan.hasNextLine()) {
                    
					String[] args = scan.nextLine().split(" ");
					ArrayList<String> partilha = new ArrayList<String>();
                    
					dono = args[1];
					System.out.println(args[0]);
					File f = new File(dir + dono + "/" + args[0]);
                    
					// imprime a data
					DateFormat formatData = new SimpleDateFormat("dd/MM/yyyy");
					String data = formatData.format(new Date(f.lastModified()));
                    
					// imprime a data
					SimpleDateFormat formatHora = new SimpleDateFormat(
                                                                       "HH:mm:ss");
					String hora = formatHora.format(new Date(f.lastModified()));
                    
					outStream.writeObject("Nome Ficheiro: " + args[0]
                                          + " | Data: " + data + " " + hora + " | Dono:  "
                                          + dono);
					if (dono.equals(user)) {
						for (int i = 2; i < args.length; i++) {
							// if( args[i] )
							partilha.add(args[i]);
						}
					} else {
						File fic2 = new File(dir + dono + "/userFiles.txt");
                        
						macChecker(fic2);
                        
						Scanner scan2 = new Scanner(fic2);
						while (scan2.hasNextLine()) {
							String[] args2 = scan2.nextLine().split(" ");
							if (args2[0].equals(f.getName())
                                && args2[1].equals(dono)) {
								for (int i = 2; i < args2.length; i++) {
									partilha.add(args2[i]);
									System.out.println("part " + args2[i]);
									System.out.println("dono " + dono);
								}
							}
                            
						}
						scan2.close();
					}
					outStream.writeObject(partilha);
                    
				}
				outStream.writeObject(null); // para ciclo no cliente parar
				scan.close();
                
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}
    
}

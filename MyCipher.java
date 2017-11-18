import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.Console;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

/**
 *  This is a simple program to protect the users password.
    Copyright (C) 2017  Gil Vilela Correia

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

public class MyCipher {

    private final static String folderName = ".myCipher";
    private final static String macsFolder = ".macs";
    private final static String userFile = ".user";
    private static String pwd, salt, salt2;
    private static Console console = System.console();



    public static void main (String [] args) throws IOException, NoSuchAlgorithmException{
	boolean ver;
	boolean firstTime = false;
	Scanner sc = new Scanner (System.in);
	String [] x;
	String aux, action, pwd2;
	StringBuilder sb;
	BufferedReader brUFile;
	BufferedWriter bwuFile;
	byte [] buff, hash, compare;

	File dir = new File (new File(".").getAbsolutePath() + File.separator + folderName);
	File macDir = new File (new File(".").getAbsolutePath() + File.separator + folderName + File.separator + macsFolder);
	File uFile = new File (new File(".").getAbsolutePath() + File.separator + folderName + File.separator + userFile);
	if (!uFile.exists()){
	    dir.mkdirs();
	    macDir.mkdirs();
	    firstTime = true;
	}

	MessageDigest md = MessageDigest.getInstance("SHA-256");

	if (firstTime){
	    ver = false;
	    while (!ver){
		pwd = new String(console.readPassword("This is your First Time, so write a secure password for this application:"));
		pwd2 = new String(console.readPassword("Confirm the password:"));
		if (!pwd.equals(pwd2)){
		    System.err.println("The passwords didn't match, try again!");
		}
		else
		    ver = true;
	    }

	    ver = false;
	    while (!ver){
		System.out.println("For great security write 6 numbers randomly:");
		salt = sc.nextLine();
		if (salt.length() != 6)
		    System.err.println("I said 6 numbers!");
		else
		    ver = true;
	    }
	    ver = false;
	    while (!ver){
		System.out.println("For greatest security write 6 numbers randomly:");
		salt2 = sc.nextLine();
		if (salt2.length() != 6)
		    System.err.println("I said 6 numbers!");
		else
		    ver = true;
	    }
	    sb = new StringBuilder();
	    sb.append(pwd+":"+salt);
	    aux = sb.toString();
	    buff = DatatypeConverter.parseBase64Binary(aux);
	    hash = md.digest(buff);
	    bwuFile = new BufferedWriter (new FileWriter (uFile));
	    aux = DatatypeConverter.printBase64Binary(hash);
	    bwuFile.write(aux + ":" + salt + ":" + salt2);
	    bwuFile.close();
	}

	ver = true;
	while (ver){
	    do{
		System.out.println("");
		System.out.println("   -l (list) | -v (view) | -a (add) | -r (remove) | -c (confirm) "
			       + "\n-u (update) | -q (quit) | -about | -uninstall (uninstall myCipher)");
		action = sc.nextLine();
		if (!action.equals("-l") && !action.equals("-a") && !action.equals("-r") &&
		    !action.equals("-c") && !action.equals("-q") && !action.equals("-v") &&
		    !action.equals("-u") && !action.equals("-about") && !action.equals("-uninstall")){
		    ver = false;
		    System.err.println("Wrong Input!");
		}
		else
		    ver = true;
	    }
	    while (!ver);

	    boolean exists;
	    switch (action){
	    case "-l":
		System.out.println("Your list of passwords:");
		for (File f: dir.listFiles()){
		    if (!f.getName().equals(macsFolder) && !f.getName().equals(userFile) && !f.getName().startsWith("."))
			System.out.println("-> " + f.getName());
		}
		System.out.println("");
		break;

	    case "-a":
		if (!register(sc,uFile,md)){
		    System.err.println("You have no permissions here!");
		    break;
		}
		System.out.println("");
		System.out.println("Insert name of the aplication (without spaces):");
		aux = sc.nextLine();
		String [] appA = aux.split(" ");
		exists = false;
		for (File f: dir.listFiles()){
		    if (appA[0].equals(f.getName())){
			exists = true;
			break;
		    }
		}
		if (exists){
		    System.out.print("This account already exists: ");
		    System.err.println(appA[0]);
		    break;
		}
		File novo = new File (new File(".").getAbsolutePath() + File.separator + folderName + File.separator + appA[0]);
		File sig = new File (new File(".").getAbsolutePath() + File.separator + folderName + File.separator + "." + appA[0] + ".sig");
		System.out.println("Insert the username or first parameter:");
		aux = sc.nextLine();

		byte [] encrypted;
		String e1, e2, af;

		encrypted = encrypt (aux.getBytes(),pwd,salt2);

		BufferedWriter bw = new BufferedWriter (new FileWriter(novo));

		bw.write(DatatypeConverter.printBase64Binary(encrypted));
		bw.newLine();

		System.out.println("Insert the password or second parameter:");
		aux = sc.nextLine();

		encrypted = encrypt (aux.getBytes(),pwd,salt2);

		bw.write(DatatypeConverter.printBase64Binary(encrypted));
		bw.flush();
		bw.close();

		BufferedReader brsig = new BufferedReader (new FileReader (novo));
		e1 = brsig.readLine();
		e2 = brsig.readLine();
		brsig.close();
		af = e1.concat(e2);
		bw = new BufferedWriter (new FileWriter (sig));
		hash = md.digest(DatatypeConverter.parseBase64Binary(af));
		bw.write(DatatypeConverter.printBase64Binary(hash));
		bw.close();

		System.out.println("Account saved with success!");
		break;

	    case "-v":
		if (!register(sc,uFile,md)){
		    System.err.println("You have no permissions here!");
		    break;
		}
		System.out.println("");
		System.out.println("Insert name of the aplication (without spaces):");
		aux = sc.nextLine();
		String [] appV = aux.split(" ");
		exists = false;
		for (File f: dir.listFiles()){
		    if (appV[0].equals(f.getName())){
			exists = true;
			break;
		    }
		}
		if (!exists){
		    System.out.print("This account doesn't exist: ");
		    System.err.println(appV[0]);
		    break;
		}
		File toread = new File (new File(".").getAbsolutePath() + File.separator + folderName + File.separator + appV[0]);

		byte [] ciphertext;
		BufferedReader br = new BufferedReader (new FileReader(toread));
		String userb = br.readLine();
		ciphertext = DatatypeConverter.parseBase64Binary(userb);
		byte [] decrypted;

		decrypted = decrypt (ciphertext,pwd,salt2);

		System.out.println("The username or first parameter is:");
		System.out.println(new String (decrypted));

		String pwdb = br.readLine();
		ciphertext = DatatypeConverter.parseBase64Binary(pwdb);
		decrypted = decrypt (ciphertext,pwd,salt2);

		System.out.println("The password or second parameter is:");
		System.out.println(new String (decrypted));

		br.close();
		break;

	    case "-r":
		if (!register(sc,uFile,md)){
		    System.err.println("You have no permissions here!");
		    break;
		}
		System.out.println("");
		System.out.println("Insert name of the application/s to remove:");
		String [] apps;
		boolean noerase = true;
		aux = sc.nextLine();
		apps = aux.split(" ");
		while (true){
		    System.out.println("Are you sure that you want to remove these applications? (y/n)");
		    aux = sc.nextLine();
		    if (aux.equals("y"))
			break;
		    else if (aux.equals("n")){
			noerase = false;
			break;
		    }
		    else
			System.err.println("Incorrect Input!");
		}
		if (!noerase)
		    break;
		for (int i = 0; i < apps.length; i++){
		    exists = false;
		    for (File f: dir.listFiles()){
			if (apps[i].equals(macsFolder) || apps[i].equals(userFile)){
			    System.out.println ("Better not erase this files");
			    exists = true;
			    break;
			}
			else if (apps[i].equals(f.getName())){
			    exists = true;
			    File apagar = new File (new File(".").getAbsolutePath() + File.separator + folderName + File.separator + apps[i]);
			    apagar.delete();
			    apagar = new File (new File(".").getAbsolutePath() + File.separator + folderName + File.separator + "." + apps[i] + ".sig");
			    apagar.delete();
			    System.out.println("[" + apps[i] + "] Removed with Sucess!");
			    break;
			}
		    }
		    if (!exists){
			System.out.print("This account doesn't exist: ");
			System.err.println(apps[i]);
		    }
		}
		break;

	    case "-c":
		/*
		if (!register(sc,uFile,md)){
		    System.err.println("You have no permissions here!");
		    break;
		}
		*/
		File signature;
		BufferedReader brc, brs;
		String par1, par2, par, compS;

		for (File f : dir.listFiles()){
		    if (!f.getName().equals(macsFolder) && !f.getName().equals(userFile) && !f.getName().startsWith(".")){
			if (!new File (new File(".").getAbsolutePath() + File.separator + folderName + File.separator + "." + f.getName() + ".sig").exists()){
			    String r;
			    do {
				System.err.println("Your file " + f.getName() + " doesn't have a signature, do you want to generate it?(y/n)");
				r = sc.nextLine();
			    }
			    while (!r.equals("y") && !r.equals("n"));
			    if (r.equals("y")){
				signature = new File (new File(".").getAbsolutePath() + File.separator + folderName + File.separator + "." + f.getName() + ".sig");
				brc = new BufferedReader (new FileReader (f));
				bw = new BufferedWriter(new FileWriter(signature));
				par1 = brc.readLine();
				par2 = brc.readLine();
				brc.close();
				par = par1.concat(par2);
				hash = DatatypeConverter.parseBase64Binary(par);
				hash = md.digest(hash);
				bw.write(DatatypeConverter.printBase64Binary(hash));
				bw.close();
				System.out.println("Signature generated with success!");
			    }
			    else{
				System.out.println("Signature not generated.");
			    }
			    continue;
			}
			signature = new File (new File(".").getAbsolutePath() + File.separator + folderName + File.separator + "." + f.getName() + ".sig");
			brc = new BufferedReader (new FileReader (f));
			brs = new BufferedReader (new FileReader (signature));
			par1 = brc.readLine();
			par2 = brc.readLine();
			brc.close();
			par = par1.concat(par2);
			hash = DatatypeConverter.parseBase64Binary(par);
			hash = md.digest(hash);
			compS = brs.readLine();
			brs.close();
			compare = DatatypeConverter.parseBase64Binary(compS);
			if (Arrays.equals(hash, compare)){
			    System.out.println("[V] : " + f.getName());
			}
			else{
			    System.out.print("[");
			    System.err.print("X");
			    System.out.println("] : " + f.getName());
			}
		    }
		}
		break;

		case "-u":
		if (!register(sc,uFile,md)){
		    System.err.println("You have no permissions here!");
		    break;
		}
		System.out.println("");
		System.out.println("Insert name of the aplication (without spaces):");
		aux = sc.nextLine();
		appA = aux.split(" ");
		exists = false;
		for (File f: dir.listFiles()){
		    if (appA[0].equals(f.getName())){
			exists = true;
			break;
		    }
		}
		if (!exists){
		    System.out.print("This account doesn't exist: ");
		    System.err.println(appA[0]);
		    break;
		}
		novo = new File (new File(".").getAbsolutePath() + File.separator + folderName + File.separator + appA[0]);
		sig = new File (new File(".").getAbsolutePath() + File.separator + folderName + File.separator + "." + appA[0] + ".sig");
		System.out.println("Insert the username or first parameter:");
		aux = sc.nextLine();

		encrypted = encrypt (aux.getBytes(),pwd,salt2);

	        bw = new BufferedWriter (new FileWriter(novo));

		bw.write(DatatypeConverter.printBase64Binary(encrypted));
		bw.newLine();

		System.out.println("Insert the password or second parameter:");
		aux = sc.nextLine();

		encrypted = encrypt (aux.getBytes(),pwd,salt2);

		bw.write(DatatypeConverter.printBase64Binary(encrypted));
		bw.flush();
		bw.close();

		brsig = new BufferedReader (new FileReader (novo));
		e1 = brsig.readLine();
		e2 = brsig.readLine();
		brsig.close();
		af = e1.concat(e2);
		bw = new BufferedWriter (new FileWriter (sig));
		hash = md.digest(DatatypeConverter.parseBase64Binary(af));
		bw.write(DatatypeConverter.printBase64Binary(hash));
		bw.close();

		System.out.println("Account updated with success!");
		break;

	    case "-about":
		System.out.println("MyCypher  Copyright (C) 2017  Gil Vilela Correia\nThis program comes with ABSOLUTELY NO WARRANTY; for details type `w'.\nThis is free software, and you are welcome to redistribute it\nunder certain conditions; type `c' for details.\ntype `q' to return to menu.");
		while (true){
		    aux = sc.nextLine();
		    if (aux.equals("w")){
			System.out.println("\nTHERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW. EXCEPT WHEN OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES PROVIDE THE PROGRAM “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE PROGRAM IS WITH YOU. SHOULD THE PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL NECESSARY SERVICING, REPAIR OR CORRECTION.\ntype `q' to return to menu.");
		    }
		    else if (aux.equals("c")){
			System.out.println("IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MODIFIES AND/OR CONVEYS THE PROGRAM AS PERMITTED ABOVE, BE LIABLE TO YOU FOR DAMAGES, INCLUDING ANY GENERAL, SPECIAL, INCIDENTAL OR CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OR INABILITY TO USE THE PROGRAM (INCLUDING BUT NOT LIMITED TO LOSS OF DATA OR DATA BEING RENDERED INACCURATE OR LOSSES SUSTAINED BY YOU OR THIRD PARTIES OR A FAILURE OF THE PROGRAM TO OPERATE WITH ANY OTHER PROGRAMS), EVEN IF SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.\ntype `q' to return to menu.");
		    }
		    else if(aux.equals("q")){
			break;
		    }
		    else
			System.err.println("Incorrect input!");
		}
		break;

	    case "-uninstall":
		if (!register(sc,uFile,md)){
		    System.err.println("You have no permissions here!");
		    break;
		}
		System.out.println("");
		System.out.println("Are you sure that you want to uninstall myCipher?\nAll your passwords will be LOST! (y/n)");
		noerase = false;
		while (true){
		    aux = sc.nextLine();
		    if (aux.equals("y"))
			break;
		    else if (aux.equals("n")){
			noerase = true;
			break;
		    }
		    else
			System.err.println("Incorrect input!");
		}
		if (noerase)
		    break;
		deleteDir(dir);
		System.out.println("Uninstall successful!");
	    case "-q":
		System.out.println("Bye Bye :)");
		ver = false;
		sc.close();
		break;
	    }
	}
    }
    private static void deleteDir(File file) {
	File[] contents = file.listFiles();
	if (contents != null) {
	    for (File f : contents) {
		deleteDir(f);
	    }
	}
	file.delete();
    }
    private static byte [] encrypt(byte [] plaintext,String pwd, String salt) throws NoSuchAlgorithmException{
	byte[] ciphertext = null;
	StringBuilder sb = new StringBuilder();
	String x = sb.append(salt+":"+pwd).toString();
	byte[]key = DatatypeConverter.parseBase64Binary(x);
	MessageDigest sha = MessageDigest.getInstance("SHA-1");
	key = sha.digest(key);
	key = Arrays.copyOf(key, 16);
	SecretKeySpec secret = new SecretKeySpec (key,"AES");
	try {
	    Cipher cipherE = Cipher.getInstance("AES/ECB/PKCS5Padding");
	    cipherE.init(Cipher.ENCRYPT_MODE, secret);
	    ciphertext = cipherE.doFinal(plaintext);
	} catch (IllegalBlockSizeException | BadPaddingException | InvalidKeyException 
		 | NoSuchPaddingException e) {
	    e.printStackTrace();
	}
	return ciphertext;
    }

    private static byte [] decrypt (byte [] ciphertext, String pwd, String salt) throws NoSuchAlgorithmException {
	byte [] plainbytes = null;
	StringBuilder sb = new StringBuilder();
	String x = sb.append(salt+":"+pwd).toString();
	byte[]key = DatatypeConverter.parseBase64Binary(x);
	MessageDigest sha = MessageDigest.getInstance("SHA-1");
	key = sha.digest(key);
	key = Arrays.copyOf(key, 16);
	SecretKeySpec secret = new SecretKeySpec (key,"AES");
	try{
	    Cipher cipherD = Cipher.getInstance("AES/ECB/PKCS5Padding");
	    cipherD.init(Cipher.DECRYPT_MODE, secret);
	    plainbytes = cipherD.doFinal(ciphertext);
	} catch (InvalidKeyException | NoSuchAlgorithmException 
		 | NoSuchPaddingException 
		 | IllegalBlockSizeException | BadPaddingException e) {
	    e.printStackTrace();
	}
	return plainbytes;
    }

    private static boolean register (Scanner sc, File uFile, MessageDigest md) throws IOException{
	int i = 3;
	String aux;
	String [] x;
	byte [] compare, buff, hash;
	StringBuilder sb;
	BufferedReader brUFile;
	do{
	    if (i < 3){
		System.err.println("Not that password");
		if (i == 0){
		    return false;
		}
	    }
	    pwd = new String(console.readPassword("Password required:"));
	    brUFile = new BufferedReader (new FileReader (uFile));
	    x = brUFile.readLine().split(":");
	    aux = x[0];
	    salt = x[1];
	    salt2 = x[2];
	    compare = DatatypeConverter.parseBase64Binary(aux);
	    sb = new StringBuilder();
	    sb.append(pwd+":"+salt);
	    aux = sb.toString();
	    buff = DatatypeConverter.parseBase64Binary(aux);
	    hash = md.digest(buff);
	    brUFile.close();
	    i--;
	}
	while (!Arrays.equals(hash, compare));
	return true;
    }
}

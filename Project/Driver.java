
  import java.io.FileNotFoundException;
  import java.io.FileReader;

  // This import statement imports BigInteger
  //BigInteger converts the String representation of a BigInteger in the specified radix into a BigInteger
  import java.math.BigInteger;
  import java.util.Scanner;


  /**
  *
  *  Authors:  Gopi.Para, Sudheer.Mandava
  *  Date: 05/02/2016
  *  Course  name:  :  MSCS  630
  *  Project: AES 128,192,256 bit encryption and decryption
  *  Due  date: 05/02/2016
  */

  public class Driver {

  /**
   *
   * @param Array of arguments are taken into the String which is a BigInteger
   */
  public static void main(String[] args){


  // Scanner function is used to read the input from the textCase file as arguments
  Scanner scr = new Scanner(System.in);

  // key is given as string
  String key = scr.nextLine();
  byte[] keyHex = new BigInteger(key,16).toByteArray();

  String text = scr.nextLine();
  byte[] pTextHex = new BigInteger(text,16).toByteArray();

  // pTextHex, keyHex are plaintext and key of 4*4
  byte[] enc = AEScipher.encrypt(pTextHex, keyHex);

  System.out.print("ENC: ");
  for(int i=0;i<enc.length;i++)
  System.out.printf("%02X",enc[i]);


  byte[] dec = AEScipher.decrypt(enc, keyHex);
  System.out.println("");
  System.out.println("dec len-"+dec.length);
  System.out.print("dec: ");
  for(int i=0;i<dec.length;i++)
  System.out.printf("%02X",dec[i]);



  }
  }



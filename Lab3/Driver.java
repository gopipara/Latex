  import java.io.FileNotFoundException;
  import java.io.FileReader;

  // This import statement imports BigInteger  
  //BigInteger converts the String representation of a BigInteger in the specified radix into a BigInteger
  import java.math.BigInteger;
  import java.util.Scanner;


  /**
   * File name: AES Basic Functions
   * Author: Gopi
   * Date: 31-March-2016
   * Course: : MSCS 630
   * Assignment: Lab3  
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
  

  byte[] out = AEScipher.encrypt(pTextHex, keyHex);
  
  for(int i=0;i<out.length;i++)
  System.out.printf("%02X",out[i]);

  
  }

  }

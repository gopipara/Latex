


// This import statement imports BigInteger

//BigInteger converts the String representation of a BigInteger in the specified radix into a BigInteger
import java.math.BigInteger;


/**
 * File name: driver.java
 * Author: Gopi
 * Date: Feb-23-2016
 * Course: : MSCS 630
 * Assignment: Lab 2 (AES Round Keys Generation)
 * Due date: Feb-23-2016
 */




public class driver {

/**
 *
 * @param Array of arguments are taken into the String which is a BigInteger
 */
public static void main(String[] args){

            String str = args[0];
 byte[] key = new BigInteger(str,16).toByteArray();
 byte[][] w = aescipher.aesRoundKeyHexs(key);
 int cnt=0;
 for(int i=0;i<44;i++){
 	for(int j=0;j<4;j++){

  // Displays the hexa decimal values
  System.out.printf("%02X",w[i][j]);

  // if the count is equal to 15, the below loop breaks and print the rest in another line.
  if(cnt==15){
  System.out.println("");
  cnt =0;
  }else{
  cnt++;
  }


 	}
 }

	}

}

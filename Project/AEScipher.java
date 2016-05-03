

  import java.util.Arrays;

   /**
   *
   *  Authors:  Gopi.Para, Sudheer.Mandava
   *  Date: 05/02/2016
   *  Course  name:  :  MSCS  630
   *  Project: AES 128,192,256 bit encryption and decryption
   *  Due  date: 05/02/2016
   *  */


  //  References:  http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf


  public  class  AEScipher  {

  private  static  int  Nb,  Nk,  Nr;
  private  static  byte[][]  w;

  /**
  *  S-box  values  are  taken  into  2-D  array  and  is  displayed  in  hexadecimal.
  *
  *  S-box:  Non-linear  substitution  table  used  in  several  byte  substitution
  *  transformations  and  in  the  Key  Expansion  routine  to  perform  a  one  for  one
  *  substitution  of  a  byte  value
  */

  private  static  int[]  sbox  =  {
  0x63,  0x7C,  0x77,  0x7B,  0xF2,  0x6B,  0x6F,
  0xC5,  0x30,  0x01,  0x67,  0x2B,  0xFE,  0xD7,  0xAB,  0x76,  0xCA,  0x82,
  0xC9,  0x7D,  0xFA,  0x59,  0x47,  0xF0,  0xAD,  0xD4,  0xA2,  0xAF,  0x9C,
  0xA4,  0x72,  0xC0,  0xB7,  0xFD,  0x93,  0x26,  0x36,  0x3F,  0xF7,  0xCC,
  0x34,  0xA5,  0xE5,  0xF1,  0x71,  0xD8,  0x31,  0x15,  0x04,  0xC7,  0x23,
  0xC3,  0x18,  0x96,  0x05,  0x9A,  0x07,  0x12,  0x80,  0xE2,  0xEB,  0x27,
  0xB2,  0x75,  0x09,  0x83,  0x2C,  0x1A,  0x1B,  0x6E,  0x5A,  0xA0,  0x52,
  0x3B,  0xD6,  0xB3,  0x29,  0xE3,  0x2F,  0x84,  0x53,  0xD1,  0x00,  0xED,
  0x20,  0xFC,  0xB1,  0x5B,  0x6A,  0xCB,  0xBE,  0x39,  0x4A,  0x4C,  0x58,
  0xCF,  0xD0,  0xEF,  0xAA,  0xFB,  0x43,  0x4D,  0x33,  0x85,  0x45,  0xF9,
  0x02,  0x7F,  0x50,  0x3C,  0x9F,  0xA8,  0x51,  0xA3,  0x40,  0x8F,  0x92,
  0x9D,  0x38,  0xF5,  0xBC,  0xB6,  0xDA,  0x21,  0x10,  0xFF,  0xF3,  0xD2,
  0xCD,  0x0C,  0x13,  0xEC,  0x5F,  0x97,  0x44,  0x17,  0xC4,  0xA7,  0x7E,
  0x3D,  0x64,  0x5D,  0x19,  0x73,  0x60,  0x81,  0x4F,  0xDC,  0x22,  0x2A,
  0x90,  0x88,  0x46,  0xEE,  0xB8,  0x14,  0xDE,  0x5E,  0x0B,  0xDB,  0xE0,
  0x32,  0x3A,  0x0A,  0x49,  0x06,  0x24,  0x5C,  0xC2,  0xD3,  0xAC,  0x62,
  0x91,  0x95,  0xE4,  0x79,  0xE7,  0xC8,  0x37,  0x6D,  0x8D,  0xD5,  0x4E,
  0xA9,  0x6C,  0x56,  0xF4,  0xEA,  0x65,  0x7A,  0xAE,  0x08,  0xBA,  0x78,
  0x25,  0x2E,  0x1C,  0xA6,  0xB4,  0xC6,  0xE8,  0xDD,  0x74,  0x1F,  0x4B,
  0xBD,  0x8B,  0x8A,  0x70,  0x3E,  0xB5,  0x66,  0x48,  0x03,  0xF6,  0x0E,
  0x61,  0x35,  0x57,  0xB9,  0x86,  0xC1,  0x1D,  0x9E,  0xE1,  0xF8,  0x98,
  0x11,  0x69,  0xD9,  0x8E,  0x94,  0x9B,  0x1E,  0x87,  0xE9,  0xCE,  0x55,
  0x28,  0xDF,  0x8C,  0xA1,  0x89,  0x0D,  0xBF,  0xE6,  0x42,  0x68,  0x41,
  0x99,  0x2D,  0x0F,  0xB0,  0x54,  0xBB,  0x16  };

  private static int[] inv_sbox = { 0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5,
  0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB, 0x7C, 0xE3,
  0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4,
  0xDE, 0xE9, 0xCB, 0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D,
  0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E, 0x08, 0x2E, 0xA1,
  0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B,
  0xD1, 0x25, 0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4,
  0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92, 0x6C, 0x70, 0x48, 0x50,
  0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D,
  0x84, 0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4,
  0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06, 0xD0, 0x2C, 0x1E, 0x8F, 0xCA,
  0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
  0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF,
  0xCE, 0xF0, 0xB4, 0xE6, 0x73, 0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD,
  0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E, 0x47,
  0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E,
  0xAA, 0x18, 0xBE, 0x1B, 0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79,
  0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4, 0x1F, 0xDD,
  0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27,
  0x80, 0xEC, 0x5F, 0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D,
  0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF, 0xA0, 0xE0, 0x3B,
  0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53,
  0x99, 0x61, 0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1,
  0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D };

  /**
  *  Rcon[]:The  round  constant  word  array.
  *This  method  is  used  to  produce  round  constant  which  is  hexadecimal
  */
  private  static  int  Rcon[]  =  {
  0x8d,  0x01,  0x02,  0x04,  0x08,  0x10,  0x20,  0x40,  0x80,  0x1b,  0x36,  0x6c,  0xd8,  0xab,  0x4d,  0x9a,
  0x2f,  0x5e,  0xbc,  0x63,  0xc6,  0x97,  0x35,  0x6a,  0xd4,  0xb3,  0x7d,  0xfa,  0xef,  0xc5,  0x91,  0x39,
  0x72,  0xe4,  0xd3,  0xbd,  0x61,  0xc2,  0x9f,  0x25,  0x4a,  0x94,  0x33,  0x66,  0xcc,  0x83,  0x1d,  0x3a,
  0x74,  0xe8,  0xcb,  0x8d,  0x01,  0x02,  0x04,  0x08,  0x10,  0x20,  0x40,  0x80,  0x1b,  0x36,  0x6c,  0xd8,
  0xab,  0x4d,  0x9a,  0x2f,  0x5e,  0xbc,  0x63,  0xc6,  0x97,  0x35,  0x6a,  0xd4,  0xb3,  0x7d,  0xfa,  0xef,
  0xc5,  0x91,  0x39,  0x72,  0xe4,  0xd3,  0xbd,  0x61,  0xc2,  0x9f,  0x25,  0x4a,  0x94,  0x33,  0x66,  0xcc,
  0x83,  0x1d,  0x3a,  0x74,  0xe8,  0xcb,  0x8d,  0x01,  0x02,  0x04,  0x08,  0x10,  0x20,  0x40,  0x80,  0x1b,
  0x36,  0x6c,  0xd8,  0xab,  0x4d,  0x9a,  0x2f,  0x5e,  0xbc,  0x63,  0xc6,  0x97,  0x35,  0x6a,  0xd4,  0xb3,
  0x7d,  0xfa,  0xef,  0xc5,  0x91,  0x39,  0x72,  0xe4,  0xd3,  0xbd,  0x61,  0xc2,  0x9f,  0x25,  0x4a,  0x94,
  0x33,  0x66,  0xcc,  0x83,  0x1d,  0x3a,  0x74,  0xe8,  0xcb,  0x8d,  0x01,  0x02,  0x04,  0x08,  0x10,  0x20,
  0x40,  0x80,  0x1b,  0x36,  0x6c,  0xd8,  0xab,  0x4d,  0x9a,  0x2f,  0x5e,  0xbc,  0x63,  0xc6,  0x97,  0x35,
  0x6a,  0xd4,  0xb3,  0x7d,  0xfa,  0xef,  0xc5,  0x91,  0x39,  0x72,  0xe4,  0xd3,  0xbd,  0x61,  0xc2,  0x9f,
  0x25,  0x4a,  0x94,  0x33,  0x66,  0xcc,  0x83,  0x1d,  0x3a,  0x74,  0xe8,  0xcb,  0x8d,  0x01,  0x02,  0x04,
  0x08,  0x10,  0x20,  0x40,  0x80,  0x1b,  0x36,  0x6c,  0xd8,  0xab,  0x4d,  0x9a,  0x2f,  0x5e,  0xbc,  0x63,
  0xc6,  0x97,  0x35,  0x6a,  0xd4,  0xb3,  0x7d,  0xfa,  0xef,  0xc5,  0x91,  0x39,  0x72,  0xe4,  0xd3,  0xbd,
  0x61,  0xc2,  0x9f,  0x25,  0x4a,  0x94,  0x33,  0x66,  0xcc,  0x83,  0x1d,  0x3a,  0x74,  0xe8,  0xcb  };


  /**
  *  RoundKey:Round  keys  are  values  derived  from  the  Cipher  Key  using  the  Key
  Expansion  routine;  they  are  applied  to  the  State  in  the  Cipher  and
  Inverse  Cipher.
  *  @param  "KeyHex"  is  the  hexadecimal  key.
  *
  */
  public  static  byte[][]  aesRoundKeyHexs(byte[]  KeyHex)  {

  //  "Nb"  is  Number  of  columns  (32-bit  words)  comprising  the  State.  For  this  standard,  Nb  =  4
  //Nb  =  4;

  //  "Nk"is  Number  of  32-bit  words  comprising  the  Cipher  Key.  For  this  standard,  Nk  =  4,  6,  or  8.
  //Nk  =  KeyHex.length/4;

  //"Nr"  is  Number  of  rounds,  which  is  a  function  of  Nk  and  Nb  (which  are  fixed).
  // For  this  standard,  Nr  =  10,  12,  or  14.

  //Nr  =  Nk  +  6;


  byte[][]  w  =  new  byte[Nb  *  (Nr  +  1)][4];

  int  i  =  0;
  while  (i  <  Nk)  {

  w[i][0]  =  KeyHex[i  *  4];
  w[i][1]  =  KeyHex[i  *  4  +  1];
  w[i][2]  =  KeyHex[i  *  4  +  2];
  w[i][3]  =  KeyHex[i  *  4  +  3];
  i++;
  }
  i  =  Nk;
  while  (i  <  Nb  *  (Nr  +  1))  {
  byte[]  innerWord  =  new  byte[4];
  for(int  k  =  0;k<4;k++)
  innerWord[k]  =  w[i-1][k];
  if  (i  %  Nk  ==  0)  {
  innerWord  =  SubWord(RotWord(innerWord));
  innerWord[0]  =  (byte)  (innerWord[0]  ^  (Rcon[i  /  Nk]  &  0xff));
  }  else  if  (Nk  >  6  &&  i  %  Nk  ==  4)  {
  innerWord  =  SubWord(innerWord);
  }
  w[i]  =  XOR(w[i  -  Nk],  innerWord);
  i++;
  }

  return  w;
  }

  /**
  *  SubWord:  Function  used  in  the  Key  Expansion  routine  that  takes  a  four-byte
   input  word  and  applies  an  S-box  to  each  of  the  four  bytes  to
   produce  an  output  word
  *  @param  "a"  is  an  input  byte  that  is  taken  in  to  SubWord.
  *  @return  "Word"  which  is  converted  into  the  values  based  on  s-box  in  hexa  decimal.
  */
  private  static  byte[]  SubWord(byte[]  a)  {
  byte[]  word  =  new  byte[a.length];
  for  (int  i  =  0;  i  <  word.length;  i++)
  word[i]  =  (byte)  (sbox[a[i]  &  0x000000ff]  &  0xff);
  return  word;
  }


  /**
  *  RotWord():  Function  used  in  the  Key  Expansion  routine  that  takes  a  four-byte
   word  and  performs  a  cyclic  permutation.
  *  @param  "word"  is  a  length  of  four  bytes
  *  @return  "word"
  */
  private  static  byte[]  RotWord(byte[]  word)  {
  byte[]  rotation  =  new  byte[word.length];
  rotation[0]  =  word[1];
  rotation[1]  =  word[2];
  rotation[2]  =  word[3];
  rotation[3]  =  word[0];

  return  rotation;
  }



  /**
  *  XOR:  Exclusive-OR  operation.
  *  @param  a
  *  @param  b
  *  @return
  */
  private  static  byte[]  XOR(byte[]  a,  byte[]  b)  {
  byte[]  value  =  new  byte[a.length];
  for  (int  i  =  0;  i  <  a.length;  i++)  {
  value[i]  =  (byte)  (a[i]  ^  b[i]);
  }
  return  value;
  }

  /**
  *  @param  block plaintext as input message
  *  @return returns cipher text
  */
  private  static  byte[]  encryptBloc(byte[]  block)  {
  byte[]  tmp  =  new  byte[block.length];
  byte[][]  state  =  new  byte[4][4];
  for  (int  i  =  0;  i  <  block.length;  i++)
  state[i  /  4][i  %  4]  =  block[i%4*4+i/4];

  state  =  aesStateXOR(state,  w,  0);

  for  (int  round  =  1;  round  <  Nr;  round++)  {

  // all the methods are performed one by one for different rounds.
  state  =  aesNibbleSub(state);
  state  =  aesShiftRow(state);
  state  =  aesMixColumn(state);
  state  =  aesStateXOR(state,  w,  round);
  }
  state  =  aesNibbleSub(state);
  state  =  aesShiftRow(state);
  state  =  aesStateXOR(state,  w,  Nr);
  for  (int  i  =  0;  i  <  tmp.length;  i++)
  tmp[i%4*4+i/4]  =  state[i  /  4][i%4];
  return  tmp;
  }


  /**
  *  @param  text plaintext given as input to arguments.
  *  @param  key  key given along with the plaintext to arguments
  *  @return returns cipher text
  */
  public  static  byte[]  encrypt(byte[]  text,byte[]  key){

  Nb  =  4;
  Nk  =  key.length/4;
  Nr  =  Nk  +  6;

  //padding
  byte[] padding = new byte[1];
  int j;
  int padLen = 16 - text.length % 16;
  System.out.println("padLen-----"+padLen);
  padding = new byte[padLen];
  padding[0] = (byte) 0x80;

  for (j = 1; j < padLen; j++)
  padding[j] = (byte) 0;

  byte[]  tmp  =  new  byte[text.length];
  byte[]  bloc  =  new  byte[16];
  w  =  aesRoundKeyHexs(key);

  int  i,count = 0;;
  for  (  i  =  0;  i  <  text.length;  i++)  {
  if  (i  >  0  &&  i  %  16  ==  0)  {
  bloc  =  encryptBloc(bloc);
  System.arraycopy(bloc,  0,  tmp,  i  -  16,  bloc.length);
    }

  if  (i  <  text.length)
  bloc[i  %  16]  =  text[i];
  else{
  bloc[i  %  16]  = padding[count % 16];
    }
  count++;
      }

  if(bloc.length  ==  16){
  bloc  =  encryptBloc(bloc);
  System.arraycopy(bloc,  0,  tmp,  i  -  16,  bloc.length);
  }

  return  tmp;
  }


  /**
  *  @param  sHex plaintext is given in hex decimal format with data type string
  *  @param  keyHex- key is given in hex decimal format with data type byte array.
  *  @param  round round number in every round
  *  @return plaintext is XORed with key to produces the output for different rounds
  *          produces the output.
  */
  public  static  byte[][]  aesStateXOR(byte[][]  sHex,  byte[][]  keyHex,int  round)  {
  byte[][]  output  =  new  byte[sHex.length][sHex[0].length];
  for  (int  i  =  0;  i  <  Nb;  i++)  {
  for  (int  j  =  0;  j  <  4;  j++)
  output[j][i]  =  (byte)  (sHex[j][i]  ^  keyHex[round  *Nb+  i][j]);
  }
  return  output;
  }


  /**
  *  @param  inStateHex  inputs and out are 4 by 4 matrices of pairs of hex digits,
  *           and that will perform the “Substitution” operation
  *          , .
  *  @return  outputs the corresponding input matrix entries through the AES S-Box
  */
  public  static  byte[][]  aesNibbleSub(byte[][]  inStateHex){
  /*
  byte[]  step1  =  toSingleDimention(inStateHex);
  byte[]  step2  =  SubWord(step1);
  return  toBiDimention(step2,4,4);*/
  byte[][] tmp = new byte[inStateHex.length][inStateHex[0].length];
  for (int row = 0; row < 4; row++)
  for (int col = 0; col < Nb; col++)
  tmp[row][col] = (byte) (sbox[(inStateHex[row][col] & 0x000000ff)] & 0xff);

  return tmp;
  }


  /**
   *
   * @param state
   * @return
   */

  private static byte[][] InvNibbleSub(byte[][] state) {
  for (int row = 0; row < 4; row++)
  for (int col = 0; col < Nb; col++)
  state[row][col] = (byte)(inv_sbox[(state[row][col] & 0x000000ff)]&0xff);
  return state;
  }

  /**
  *  @param  inStateHex  will perform the Shift Row operation of the AES to transform
  *          the hexadecimal input state matrix
  *          into output state
  *  @return  outputs 4 by 4 matrices of pairs
  */
  public  static  byte[][]  aesShiftRow(byte[][]  inStateHex){
  byte[]  local  =  new  byte[4];
  for  (int  i  =  1;  i  <  4;  i++)  {
  for  (int  j  =  0;  j  <  Nb;  j++)
  local[j]  =  inStateHex[i][(j  +  i)  %  Nb];
  for  (int  k  =  0;  k  <  Nb;  k++)
  inStateHex[i][k]  =  local[k];
  }

  return  inStateHex;

  }
  /**
   *
   * @param state current state matrix which is cyclically left shifted
   * is considered. The bytes in the last three rows of the State are
   * cyclically shifted over different numbers of bytes (offsets).
   * @return gives the matrix in which bytes are substituted with s-box bytes.
   */
  private static byte[][] InvShiftRows(byte[][] state) {
  byte[] t = new byte[4];
  for (int r = 1; r < 4; r++) {
  for (int c = 0; c < Nb; c++)
  t[(c + r)%Nb] = state[r][c];
  for (int c = 0; c < Nb; c++)
  state[r][c] = t[c];
  }
  return state;
  }


  /**
  *  @param  input - output from shift rows is taken as input i.e. instatehex.
  *  @return
  */
  public  static  byte[][]  aesMixColumn(byte[][]  input){
  int[]  local  =  new  int[4];
  byte  b2  =  (byte)0x02;
  byte  b3  =  (byte)0x03;
  for  (int  c  =  0;  c  <  4;  c++)  {
  local[0]  =  multiplier(b2,input[0][c])^multiplier(b3,input[1][c])^input[2][c]^input[3][c];
  local[1]  =  input[0][c]^multiplier(b2,input[1][c])^multiplier(b3,input[2][c])^input[3][c];
  local[2]  =  input[0][c]^input[1][c]^multiplier(b2,input[2][c])^multiplier(b3,input[3][c]);
  local[3]  =  multiplier(b3,input[0][c])^input[1][c]^input[2][c]^multiplier(b2,input[3][c]);
  for  (int  i  =  0;  i  <  4;  i++)
  input[i][c]  =  (byte)(local[i]);
  }
  return  input;
  }

  /**
   *
   * @param s takes the state matrix which is obtained by XORing with fixed matrix
   * and outputs the original matrix which is obtained after the shift rows operation.
   * @return state matrix obtained after the shift rows operation.
   */
  private static byte[][] InvMixColumns(byte[][] s){
  int[] sp= new int[4];
  byte b2 = (byte)0x0e;
  byte b3 = (byte)0x0b;
  byte b4 = (byte)0x0d;
  byte b5 = (byte)0x09;
  for (int c = 0; c < 4; c++) {
  sp[0] = multiplier(b2, s[0][c]) ^ multiplier(b3, s[1][c]) ^ multiplier(b4,s[2][c])  ^ multiplier(b5,s[3][c]);
  sp[1] = multiplier(b5, s[0][c]) ^ multiplier(b2, s[1][c]) ^ multiplier(b3,s[2][c])  ^ multiplier(b4,s[3][c]);
  sp[2] = multiplier(b4, s[0][c]) ^ multiplier(b5, s[1][c]) ^ multiplier(b2,s[2][c])  ^ multiplier(b3,s[3][c]);
  sp[3] = multiplier(b3, s[0][c]) ^ multiplier(b4, s[1][c]) ^ multiplier(b5,s[2][c])  ^ multiplier(b2,s[3][c]);
  for (int i = 0; i < 4; i++) s[i][c] = (byte)(sp[i]);
  }
  return s;
  }


  /**
  *  @param  first
  *  @param  second
  *  @return
  */
  public  static  byte  multiplier(byte  first,  byte  second)  {
  byte  value  =  0,  local;
  while  (first  !=  0)  {
  if  ((first  &  1)  !=  0)
  value  =  (byte)  (value  ^  second);
  local  =  (byte)  (second  &  0x80);
  second  =  (byte)  (second  <<  1);
  if  (local  !=  0)
  second  =  (byte)  (second  ^  0x1b);
  first  =  (byte)  ((first  &  0xff)  >>  1);
  }
  return  value;
  }


  // Since the returned value is Single dimension from the above input,
  //we are converting it to the Bi-dimension
  private static byte[][] toBiDimention(final byte[] input,final int rows,final int cols  ){
  if  (input.length  !=  (rows*cols))
  throw  new  IllegalArgumentException("Invalid  array  length");
  byte[][]  convert  =  new  byte[rows][cols];
  for  (  int  i  =  0;  i  <  rows;  i++  )
  System.arraycopy(input,  (i*cols),  convert[i],  0,  cols);
  return  convert;
  }

  private  static  byte[]  toSingleDimention(  final  byte[][]  input  )  {
  int  rows  =  input.length,  cols  =  input[0].length;
  byte[]  convert  =  new  byte[(rows*cols)];
  for  (  int  i  =  0;  i  <  rows;  i++  )
  System.arraycopy(input[i],  0,  convert,  (i*cols),  cols);
  return  convert;
  }

  public  static  String[][]  genMatrix(String  hexString)  {
  String[][]  matrix=  new  String[4][4];
  int  col  =  0;
  for  (int  i  =  0;  i  <  (hexString.length()  -  1);  i  =  i  +  8)  {
  int  row  =  0;
  for  (int  j  =  i;  j  <  (i  +  8);  j  =  j  +  2)  {
  matrix[row][col]  =  hexString.substring(j,  (j  +  2));
  ++row;
  }
  ++col;
  }
  return  matrix;
  }



  /**
   *
   * @param in takes the cipher text as the input and performs inverse operations
   * @return plain text.
   */
  public static byte[] decryptBloc(byte[] in) {
  byte[] tmp = new byte[in.length];
  byte[][] state = new byte[4][Nb];
  for (int i = 0; i < in.length; i++)
  state[i / 4][i % 4] = in[i%4*4+i/4];
  state = aesStateXOR(state, w, Nr);

  // Reduces the number of rounds based on the value of Nr
  for (int round = Nr-1; round >=1; round--) {

  //inverse the state matrix that is obtained by substituting
  //the corresponding bytes with bytes in the s-box
  state = InvNibbleSub(state);

  //current state matrix which is cyclically left shifted
  //is considered. The bytes in the last three rows of the State are
  //cyclically shifted over different numbers of bytes (offsets)
  state = InvShiftRows(state);
  state = aesStateXOR(state, w, round);
  state = InvMixColumns(state);
  }
  state = InvNibbleSub(state);
  state = InvShiftRows(state);
  state = aesStateXOR(state, w, 0);
  for (int i = 0; i < tmp.length; i++)
  tmp[i%4*4+i/4] = state[i / 4][i%4];
  return tmp;
  }

  /**
   *
   * @param in takes the cypher text as the input and performs
   * all the inverse operations to generate the original plain text.
   * @param key the key provided with the plain text
   * @return the original plain text.
   */
  public static byte[] decrypt(byte[] in,byte[] key){
  int i;
  byte[] tmp = new byte[in.length];
  byte[] bloc = new byte[16];
  Nb = 4;
  Nk = key.length/4;
  Nr = Nk + 6;
  w = aesRoundKeyHexs(key);
  for (i = 0; i < in.length; i++) {
  if (i > 0 && i % 16 == 0) {
  bloc = decryptBloc(bloc);
  System.arraycopy(bloc, 0, tmp, i - 16, bloc.length);
  }
  if (i < in.length)
  bloc[i % 16] = in[i];
  }
  bloc = decryptBloc(bloc);
  System.arraycopy(bloc, 0, tmp, i - 16, bloc.length);
  tmp = deletePadding(tmp);
  return tmp;
  }
  /**
   *
   * @param input
   * @return
   */
  private static byte[] deletePadding(byte[] input) {
  int count = 0;
  byte checkFor = (byte) 0x80;  //-128
  boolean isPadded = false;
  int i = input.length-1;
  while (true) {
  count++;
  //System.out.println("i"+i);
  if(input[i]==checkFor){
  isPadded = true;
  break;
  }
  i--;
  if(i<0)
  break;
  }
  if(isPadded){
  byte[] tmp = new byte[input.length - count - 1];
  System.arraycopy(input, 0, tmp, 0, tmp.length);
  return tmp;
  }else{
  return input;
  }
  }
  }

/*
 * Attack.java
 * Date: 07-25-2014
 * v1.0
 * Author: Shreyas Jayanna
 */

// Import statements
import edu.rit.util.Hex;
import edu.rit.util.Packing;
import java.io.*;
import java.util.*;

/**
 * Class Attack
 * This class defines an attack on reduced-round SPECK32/64 for three rounds.
 */
public class Attack {

    // Datastructures to store keys, hits and the input plaintext-ciphertext pairs
    Hashtable<String, Integer> keys;
    ArrayList<String> subkeysOne;
    Hashtable<String, String> plainCipher;

    /**
     * Attack
     * Constructor
     */
    Attack() {
        keys = new Hashtable<String, Integer>();
        subkeysOne = new ArrayList<String>();
        plainCipher = new Hashtable<String, String>();
    }


    /**
     * generateRoundOneSubkeys method.
     * This method generates the round keys for the first round. This is a brute-force method. So, all possible keys
     * (2^16 - 1) are produced and stored in the respective datastructure.
     */
    public void generateRoundOneSubkeys() {
        for(int i = 0; i <= 65535; ++i) {
            this.subkeysOne.add(Integer.toHexString(i));
        }
    }

    /**
     * attack method.
     * This method attacks the reduced three-round SPECK32/64.
     */
    public void attack() {

        ArrayList<String> plaintext = new ArrayList<String>(plainCipher.keySet());

        for(String plain : plaintext) {

            String cipher = plainCipher.get(plain);

            byte[] plainText = Hex.toByteArray(plain);
            byte[] cipherText = Hex.toByteArray(cipher);

            short p1 = Packing.packShortBigEndian(plainText, 0);
            short p2 = Packing.packShortBigEndian(plainText, 2);

            short c1 = Packing.packShortBigEndian(cipherText, 0);
            short c2 = Packing.packShortBigEndian(cipherText, 2);

            short x1, y1;
            short x2, y2;

            int temp1 = c1 & 65535;
            int temp2 = c2 & 65535;

            int temp4 = (temp1 ^ temp2) & 65535;
            temp4 = ((temp4 >>> 2) | (temp4 << (16 - 2))) & 65535;
            y2 = (short) temp4;

            for (int keyIndex = 0; keyIndex <= 65535; ++keyIndex) {

                int key = Integer.parseInt(this.subkeysOne.get(keyIndex),16) & 65535;
                int temp3 = key;

                temp1 = p1 & 65535;
                temp2 = p2 & 65535;

                x1 = (short) ((((((temp1 >>> 7) | (temp1 << (16 - 7))) & 65535) + temp2) & 65535) ^ temp3);
                temp1 = x1 & 65535;
                y1 = (short) ((((temp2 << 2) | (temp2 >>> (16 - 2))) & 65535) ^ temp1);

                temp2 = y1 & 65535;
                temp1 = y2 & 65535;
                temp2 = ((temp2 << 2) | (temp2 >>> (16 - 2))) & 65535;
                temp3 = temp1 ^ temp2;

                x2 = (short) temp3;

                short key1 = (short) key;
                short key2, key3;

                temp4 = x1 & 65535;
                temp4 = ((temp4 >>> 7) | (temp4 << (16 - 7))) & 65535;
                temp2 = y1 & 65535;
                temp2 = (temp2 + temp4) & 65535;
                temp3 = (temp3 ^ temp2) & 65535;

                key2 = (short) temp3;

                temp3 = c1 & 65535;
                temp4 = x2 & 65535;
                temp4 = (temp4 >>> 7) | (temp4 << (16 - 7));
                temp2 = y2 & 65535;
                temp2 = (temp2 + temp4) & 65535;
                temp3 = (temp3 ^ temp2) & 65535;

                key3 = (short) temp3;

                String keysFound = "" + Hex.toString(key1) + ';' + Hex.toString(key2) + ';' + Hex.toString(key3);

                if (this.keys.containsKey(keysFound)) {
                    int count = this.keys.get(keysFound);
                    ++count;
                    this.keys.put(keysFound, count);
                } else {
                    this.keys.put(keysFound, 1);
                }
            }

        }

        ArrayList<String> foundKeys = new ArrayList<String>(this.keys.keySet());
        ArrayList<Integer> foundHits = new ArrayList<Integer>(this.keys.values());

        int max = Collections.max(foundHits);
        int index = foundHits.indexOf(max);

        Collections.sort(foundHits);

        String theKey = foundKeys.get(index);

        String[] keys = theKey.split(";");
        int[] keyInt = new int[3];
        keyInt[0] = Integer.parseInt(keys[0],16);
        keyInt[1] = Integer.parseInt(keys[1],16);
        keyInt[2] = Integer.parseInt(keys[2],16);

        for(int key : keyInt) {
            String printKey = Hex.toString(key);
            System.out.println(printKey.substring(4));
        }
    }

    /**
     * main
     * The main method
     * @param args Command line arguments
     */
    public static void main(String[] args) throws IOException {

        if(args.length != 1) {
            System.out.println("Argument must be a valid file.");
            System.exit(1);
        } else {
            try {
                Attack a = new Attack();

                File inFile = new File(args[0]);

                BufferedReader br = new BufferedReader(new FileReader(inFile));

                String fileText;
                while ((fileText = br.readLine()) != null) {
                    String[] input = fileText.split("\\s+");
                    a.plainCipher.put(input[0], input[1]);
                }
                a.generateRoundOneSubkeys();
                a.attack();
            } catch(FileNotFoundException e) {
                System.out.println("Not a valid file");
            } catch(Exception e) {
                System.out.println("Please check for valid arguments");
            }
        }
    }
}

package test;

import util.KeyUtils;
import util.MD5Utils;
import util.SignUtils;

public class SecTest {
	private static String info;
	private static String KEY_FILE="d:/test/A/AKey.dat";
	private static String SIGN_FILE="d:/test/A/sign.dat";
	private static String FILE = "d:/test/A/test.txt";
	public static void main(String[] args) throws Exception {
		info = MD5Utils.md5(FILE);
		KeyUtils.createPairKey(KEY_FILE);
		SignUtils.signInfo(KEY_FILE, info, SIGN_FILE);
		boolean b =SignUtils.validateSign(SIGN_FILE);
		System.out.println(b);
		/*RSAPublicKey pubKey = (RSAPublicKey) FileUtils.getObjFromFile("D:/test/B/BKey.dat",1);
		//System.out.println(pubKey);
		RSAUtils.encryptToFile(pubKey, "d:/test/A/sign.dat", "d:/test/A/rsasign.dat");
		RSAUtils.encryptToFile(pubKey, "d:/test/A/test.txt", "d:/test/A/rsatest.dat");
		RSAPrivateKey priKey = (RSAPrivateKey) FileUtils.getObjFromFile("D:/test/B/BKey.dat",2);
		RSAUtils.decryptToFile(priKey, "d:/test/A/rsasign.dat", "d:/test/B/sign.dat");
		RSAUtils.decryptToFile(priKey, "d:/test/A/rsatest.dat", "d:/test/B/test.txt");	*/
	}
	
}

package net;

import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import util.FileUtils;
import util.KeyUtils;
import util.MD5Utils;
import util.RSAUtils;
import util.SignUtils;



public class B {
	
	private String KEY_FILE="d:/test/B/BKey.dat";
	private static String A_RSA_SIGN_FILE="d:/test/B/aRsaSign.dat";
	private static String A_RSA_FILE="d:/test/B/aRsaTest.dat";
	private static String SIGN_FILE="d:/test/B/sign.dat";
	private static String FILE="d:/test/B/testResult.txt";
	private static RSAPublicKey pubKey;
	private static RSAPrivateKey priKey;


	public   void init(){
		//创建目录
		File f = new File("d:/test/B");
		f.mkdirs();
		KeyUtils.createPairKey(KEY_FILE);
		pubKey = (RSAPublicKey) FileUtils.getObjFromFile(KEY_FILE, 1);
		priKey = (RSAPrivateKey) FileUtils.getObjFromFile(KEY_FILE, 2);
	}
	
	public void start() throws Exception {
		
		Socket socket = new Socket("127.0.0.1", 520);

		InputStream is = socket.getInputStream();
		DataInputStream dis = new DataInputStream(is);
		BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
		OutputStream os = socket.getOutputStream();
		DataOutputStream dos = new DataOutputStream(os);
		ObjectOutputStream oos = new ObjectOutputStream(os);
		String str1 = dis.readUTF();
		System.out.println(str1);
		String str2 = dis.readUTF();
		System.out.println(str2);
		String str3 = br.readLine();//输入y
		System.out.println("【B】B的输入:"+str3);
		dos.writeUTF(str3);
		dos.flush();
		System.out.println("【B】AB通话开始......");
		System.out.println("【B】B传送公钥开始...");
		oos.writeObject(pubKey);
		System.out.println("【B】B传送公钥完毕...");
		System.out.println("【B】B开始接收密文........");
		BufferedOutputStream bos = new BufferedOutputStream(
				new FileOutputStream(A_RSA_SIGN_FILE));
		BufferedOutputStream bos2 = new BufferedOutputStream(
				new FileOutputStream(A_RSA_FILE));
		long length=dis.readLong();
		int a=0;
		int len=0;
		while (len<length) {
			a=dis.read();
			bos.write(a);
			len++;
		}
		bos.close();
		int b;
		while ((b = dis.read()) != -1) {
			bos2.write(b);
		}
		bos2.close();
		System.out.println("【B】B接收密文完毕........");
		System.out.println("【B】AB通话结束......");
		socket.close();
	}
	public static void main(String[] args) throws Exception {
		System.out.println("B:");
		B b= new B();
		b.init();
		b.start();
		System.out.println("【B】B开始解密密文...");
		RSAUtils.decryptToFile(priKey, A_RSA_SIGN_FILE, SIGN_FILE);
		System.out.println("【B】B开始验证数字签名...");
		boolean flag =SignUtils.validateSign(SIGN_FILE);
		if(flag){
			System.out.println("【B】B数字签名验证通过...");
			String info = (String) FileUtils.getObjFromFile(SIGN_FILE, 3);
			System.out.println("【B】从签名中得到明文的MD5值是：");
			System.out.println("【B】"+info);
			System.out.println("【B】开始计算接收到明文的MD5值...");
			RSAUtils.decryptToFile(priKey, A_RSA_FILE, FILE);	
			String md5 = MD5Utils.md5(FILE);
			System.out.println("【B】得出明文的MD5值是：");
			System.out.println("【B】"+md5);
			System.out.println("【B】比较MD5值，结果是："+info.equals(md5)+"  (相同)");
		}
		System.out.println("【B】操作完毕..........");
	}
}
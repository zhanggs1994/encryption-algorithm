package util;

import java.io.FileInputStream;
import java.security.DigestInputStream;
import java.security.MessageDigest;

public class MD5Utils {
	//用MD5获得文件的信息摘要
	public static String md5(String file) {
		try {
			//生成MessageDigest对象，得到md5的消息摘要
			MessageDigest md = MessageDigest.getInstance("MD5");
			//得到需要计算的输入流
			FileInputStream fis = new FileInputStream(file);
			//生成DigestInputStream对象
			DigestInputStream dis = new DigestInputStream(fis,md);
			//从DigestInputStream流中读取数据，不需要循环体
			while(dis.read()!=-1);	
			//得到摘要
			byte[] bytes= md.digest(); 
			//将摘要转换成字符串返回
			String result = "";
			for (int i=0; i<bytes.length; i++){
	            result+=Integer.toHexString((0x000000ff & bytes[i]) | 
					0xffffff00).substring(6);
	        }
			return result;
		
		} catch (Exception e) {
			return null;
		}	
	}
}

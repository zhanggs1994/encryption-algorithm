package util;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

public class KeyUtils {
	//加密块大小
	 public static final int KEY_SIZE = 1024;
	/**
	 * 创建密钥组,并存储到文件中
	 */
	public static void createPairKey(String file) {	
		try {
			//创建RSA密钥生成器,BouncyCastleProvider第三方RSA算法提供商
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA",new org.bouncycastle.jce.provider.BouncyCastleProvider());
			//使用给定参数集合和随机源初始化密钥对生成器。
			keyGen.initialize(KEY_SIZE, new SecureRandom());
			//通过KeyPairGenerator产生密钥对
			KeyPair keyPair = keyGen.generateKeyPair();  
			// 得到公匙  
	        PublicKey pubKey = (PublicKey) keyPair.getPublic();  
	        // 得到私匙  
	        PrivateKey priKey = (PrivateKey) keyPair.getPrivate();  
	        // 将公匙私匙写入到文件当中  
            FileUtils.doObjToFile(file, new Object[] { pubKey, priKey });  
		} catch (Exception e) {
		}  
	}
	
 
}

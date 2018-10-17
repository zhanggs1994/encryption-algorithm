package util;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;


public class SignUtils {
	/**
	 * 从文件中获得公钥、私钥，并对信息摘要进行签名，保存到文件中
	 * @param file
	 * 				存放私钥的文件
	 * @param info
	 * 				信息摘要
	 * @param signFile
	 * 				保存文件
	 */
    public static void signInfo(String file,String info, String signFile) {  
    	// 从文件中读取公匙  
        PublicKey myPubKey = (PublicKey) FileUtils.getObjFromFile(file, 1);  
        // 从文件中读取私匙  
    	 PrivateKey myPriKey = (PrivateKey) FileUtils.getObjFromFile(file, 2);  
        try {  
            // 获取Signature ,Signature对象可用来生成和验证数字签名  
            Signature signet = Signature.getInstance("MD5WithRSA");  
            // 用私钥初始化Signature
            signet.initSign(myPriKey);  
            // 传入签名的信息摘要 
            signet.update(info.getBytes());  
            // 执行签名
            byte[] signed = signet.sign();  
            // 将数字签名,公匙,信息摘要放入文件中  
            FileUtils.doObjToFile(signFile, new Object[] { signed, myPubKey, info });  
        } catch (Exception e) {  
            e.printStackTrace();  
        }  
    }  
    
    /** 
     * 读取数字签名文件 根据公匙，签名，信息验证信息的合法性 
     *  
     * @return true 验证成功 false 验证失败 
     */  
    public static boolean validateSign(String signFile) {  
        // 读取签名  
        byte[] signed = (byte[]) FileUtils.getObjFromFile(signFile, 1);  
        // 读取公匙  
        PublicKey myPubKey = (PublicKey) FileUtils.getObjFromFile(signFile, 2);  
        // 读取信息  
        String info = (String) FileUtils.getObjFromFile(signFile, 3);  
        try {  
            // 初始一个Signature对象,并用公钥和签名进行验证  
            Signature signet = Signature.getInstance("MD5WithRSA");  
            // 初始化验证签名的公钥  
            signet.initVerify(myPubKey);  
            // 传入验证的信息摘要 
            signet.update(info.getBytes());  
           // System.out.println(info);  
            // 验证传入的签名  
            return signet.verify(signed);  
        } catch (Exception e) {  
            e.printStackTrace();  
            return false;  
        }  
    }  
}

/**
 * 
 */
package com.doubleca.sample.pki.pkcs;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.Enumeration;

import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;

public class Test
{
	String priPass = "DoubleCA";
	String dcksPass = "DoubleCA";
	String dcksFilePath = "resources/test01.dcks";
	String p7bFilepath = "resources/test01.p7b";
	String cerFilepath = "resources/sm2rootca.cer";
	
	void createPkcs10()
	{
		FileOutputStream os = null;
		try
		{
			SM2Keystore ks1 = new SM2Keystore();
			String pkcs10 = ks1.createPKCS10(null, priPass.toCharArray());
			os = new FileOutputStream(dcksFilePath);
			ks1.store(os, dcksPass.toCharArray());
			System.out.println(pkcs10);
		}
		catch(Exception ex)
		{
			ex.printStackTrace();
		}
		finally
		{
			try
			{
				os.close();
			}
			catch(Exception ex)
			{
			}
		}
	}
	
	void installCertificate()
	{
		FileInputStream is = null;
		FileOutputStream os = null;
		try
		{
			is = new FileInputStream(dcksFilePath);
			SM2Keystore ks2 = new SM2Keystore();
			ks2.load(is, dcksPass.toCharArray());
			ks2.installCertificate(p7bFilepath, priPass.toCharArray());
			os = new FileOutputStream(dcksFilePath);
			ks2.store(os, dcksPass.toCharArray());
		}
		catch(Exception ex)
		{
			ex.printStackTrace();
		}
		finally
		{
			try
			{
				is.close();
			}
			catch(Exception ex)
			{
			}
			try
			{
				os.close();
			}
			catch(Exception ex)
			{
			}
		}
	}
	
	void listDCKeystore()
	{
		FileInputStream is = null;
		try
		{
			is = new FileInputStream(dcksFilePath);
			SM2Keystore ks2 = new SM2Keystore();
			ks2.load(is, dcksPass.toCharArray());
			Enumeration e = ks2.aliases();
			while(e.hasMoreElements())
			{
				String alias = (String)e.nextElement();
				System.out.println("alias : " + alias);
				if (ks2.isCertificate(alias))
				{
					System.out.println(ks2.getCertificate(alias));
				}
				else
				{
					if (ks2.isKey(alias))
					{
						System.out.println("PrivateKey:");
						System.out.println(ks2.getPrivateKey(alias, priPass.toCharArray()));
						Certificate[] chain = ks2.getCertificateChain(alias);
						if (chain == null)
						{
							continue;
						}
						for (int i = 0; i < chain.length; i++)
						{
							System.out.println(chain[i]);
						}
					}
					else
					{
						System.out.println("Unknown type...");
					}
				}
			}
		}
		catch(Exception ex)
		{
			ex.printStackTrace();
		}
		finally
		{
			try
			{
				is.close();
			}
			catch(Exception ex)
			{
			}
		}		
	}
	
	void signAndVerify()
	{
		FileInputStream is = null;
		PrivateKey privKey = null;
		PublicKey pubKey = null;
		String alias = "cn=selfcert,e=contact@doubleca.com,o=www.doubleca.com,st=beijing,c=cn";
		try
		{
			is = new FileInputStream(dcksFilePath);
			SM2Keystore ks2 = new SM2Keystore();
			ks2.load(is, dcksPass.toCharArray());
			
			privKey = ks2.getPrivateKey(alias, priPass.toCharArray());
			Certificate cert = ks2.getCertificate(alias);
			pubKey = cert.getPublicKey();
		}
		catch(Exception ex)
		{
			ex.printStackTrace();
		}
		finally
		{
			try
			{
				is.close();
			}
			catch(Exception ex)
			{
			}
		}
		String content = "偶像：握奇数据王幼君总裁！";
		byte[] signValue = null;
		boolean result = false;
		try
		{
			java.security.Signature signature = java.security.Signature.getInstance("SM3withSM2");
			signature.initSign(privKey);
			signature.update(content.getBytes());
			signValue = signature.sign();
			signature.initVerify(pubKey);
			signature.update(content.getBytes());
			result = signature.verify(signValue);
		}
		catch(Exception ex)
		{
			ex.printStackTrace();
		}
		System.out.println("原文 ：" + content);
		System.out.println("SM3withSM2 签名值 ：" + Base64.encode(signValue));
		System.out.println("签名验证结果 ：" + result);
	}
	
	void installOtherCertificate()
	{
		FileInputStream is = null;
		FileOutputStream os = null;
		try
		{
			is = new FileInputStream(dcksFilePath);
			SM2Keystore ks2 = new SM2Keystore();
			ks2.load(is, dcksPass.toCharArray());
			ks2.installCertificate(cerFilepath);
			os = new FileOutputStream(dcksFilePath);
			ks2.store(os, dcksPass.toCharArray());
			System.out.println("安装完成");
		}
		catch(Exception ex)
		{
			ex.printStackTrace();
			return;
		}
		finally
		{
			try
			{
				is.close();
			}
			catch(Exception ex)
			{
			}
			try
			{
				os.close();
			}
			catch(Exception ex)
			{
			}
		}
	}
	
	/**
	 * @param args
	 */
	public static void main(String[] args)
	{
		// TODO Auto-generated method stub
		/**
		 * 说明：JDK7版本及以上，JDK需要使用无限制的策略文件 UnlimitedJCEPolicy
		 * 否则，SM2密钥长度为256位，JCE无法调用成功
		 */
		Test obj = new Test();
		// 1. 创建SM2算法PKCS10数据
//		obj.createPkcs10();
		// 2. 用PKCS10数据去 http://www.DoubleCA.com 免费申请证书，然后安装进DCKS
//		obj.installCertificate();
		// 3. 列出DCKS内容
		obj.listDCKeystore();
		// 4. 测试SM2签名与验签
		obj.signAndVerify();
		// 5. 安装其它根证书等
		obj.installOtherCertificate();
	}
}

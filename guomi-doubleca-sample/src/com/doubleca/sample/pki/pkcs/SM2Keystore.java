/**
 * 
 */
package com.doubleca.sample.pki.pkcs;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import com.doubleca.pki.crypto.DCToken;
import com.doubleca.pki.crypto.params.KeyPairParams;
import com.doubleca.pki.pkcs.SM2PKCS10;
import com.doubleca.pki.pkcs.SM2PKCS7;
import com.doubleca.pki.util.DnComponents;
import com.doubleca.pki.x509.cert.SM2X509Cert;

import doubleca.security.provider.DoubleCA;

public final class SM2Keystore
{
	static
	{
		Security.addProvider(new DoubleCA());
	}

	private final static String CERT_DEFAULT_SUBJECTDN = "CN=SelfCert, E=contact@doubleca.com, O=www.DoubleCA.com, ST=BEIJING, C=CN";
	
	private final static String DEFAULT_ALIAS = "c=cn,st=beijing,o=www.doubleca.com,e=contact@doubleca.com,cn=selfcert";
	
	private final static String SIGN_ALG = "SM3WithSM2";
	
	private final static int CERT_DEFAULT_VALIDITY = 365;
	
	private final static String KEYSTORE_TYPE = "DCKS";
	
	private KeyStore keyStore = null;
	
	public SM2Keystore() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException
	{
		keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
		keyStore.load(null, null);
	}
	
	public void load(InputStream stream, char[] password) throws NoSuchAlgorithmException, CertificateException, IOException
	{
		keyStore.load(stream, password);
	}
	
	public void store(OutputStream stream, char[] password) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException
	{
		keyStore.store(stream, password);
	}
	
	public String createPKCS10(String subjectDN, char[] priKeyPassword) throws Exception
	{
		return createPKCS10(subjectDN, priKeyPassword, null);
	}
	
	public String createPKCS10(String subjectDN, char[] priKeyPassword, String alias) throws Exception
	{
		return createPKCS10(subjectDN, priKeyPassword, alias, null);
	}
	
	public String createPKCS10(String subjectDN, char[] priKeyPassword, String alias, String csrFilepath) throws Exception
	{
		DCToken token = new DCToken();
		KeyPair keyPair = null;
		if (subjectDN == null || subjectDN.length() <= 0)
		{
			subjectDN = CERT_DEFAULT_SUBJECTDN;
		}
		keyPair = token.generatorKeyPair(KeyPairParams.getInstance(KeyPairParams.SM2_KEY, 256));
		SM2PKCS10 sm2PKCS10 = new SM2PKCS10(token, SIGN_ALG, subjectDN, null, keyPair);
		X509Certificate[] chain = new X509Certificate[1];
		chain[0] = token.signSelfCertificate(subjectDN, CERT_DEFAULT_VALIDITY, SIGN_ALG, keyPair);
		if (alias == null || alias.length() <= 0)
		{
			alias = DnComponents.stringToBCDNString(chain[0].getSubjectDN().getName());
		}
		keyStore.setKeyEntry(alias, keyPair.getPrivate(), priKeyPassword, chain);
		if (csrFilepath != null && csrFilepath.length() > 0)
		{
			FileOutputStream fos = new FileOutputStream(csrFilepath);
			fos.write(sm2PKCS10.getPKCS10Base64(true).getBytes("UTF-8"));
			fos.close();
		}
		return sm2PKCS10.getPKCS10Base64(true);
	}

	public Certificate getCertificate(String alias) throws KeyStoreException
	{
		return this.keyStore.getCertificate(alias);
	}
	
	public Certificate[] getCertificateChain(String alias) throws KeyStoreException
	{
		return this.keyStore.getCertificateChain(alias);
	}
	
	public void installCertificate(final byte[] pkcs7Data, char[] priKeyPassword) throws KeyStoreException, NoSuchAlgorithmException, Exception
	{
		SM2PKCS7 p7b = new SM2PKCS7(pkcs7Data);
		SM2X509Cert[] chain = p7b.getCerts();
		X509Certificate temp[] = new X509Certificate[chain.length];
		for (int i = 0; i < chain.length; i++)
		{
			temp[i] = chain[i].getX509Certificate();
		}
		this.installCertificate(temp, priKeyPassword);
	}
	
	public void installCertificate(final String cerFilepath) throws FileNotFoundException, CertificateException, NoSuchProviderException
	{
		InputStream bis = null;
		Certificate cert = null;
		String alias = null;
		try
		{
			bis = new FileInputStream(new File(cerFilepath));
			CertificateFactory cf = CertificateFactory.getInstance("X509", DoubleCA.PROVIDER_NAME);
			cert = cf.generateCertificate(bis);
			alias = DnComponents.stringToBCDNString(((X509Certificate)cert).getSubjectDN().getName());
		}
		finally
		{
			try
			{
				bis.close();
			}
			catch(Exception ex)
			{
			}
		}
		if (alias == null)
		{
			return;
		}
		installCertificate(alias, cerFilepath);
	}
	
	public void installCertificate(final String alias, final String cerFilepath) throws FileNotFoundException, CertificateException, NoSuchProviderException
	{
		InputStream bis = null;
		Certificate cert = null;
		try
		{
			bis = new FileInputStream(new File(cerFilepath));
			CertificateFactory cf = CertificateFactory.getInstance("X509", DoubleCA.PROVIDER_NAME);
			cert = cf.generateCertificate(bis);
		}
		finally
		{
			try
			{
				bis.close();
			}
			catch(Exception ex)
			{
			}
		}
		try
		{
			keyStore.setCertificateEntry(alias, cert);
		}
		catch(Exception ex)
		{
			ex.printStackTrace();
		}
	}
	
	public void installCertificate(final String p7bFilepath, char[] priKeyPassword) throws KeyStoreException, NoSuchAlgorithmException, Exception
	{
		BufferedInputStream bis = null;
		ByteArrayOutputStream bos = null;
		byte[] pkcs7Data = null;
		try
		{
			bis = new BufferedInputStream(new FileInputStream(new File(p7bFilepath)));
			bos = new ByteArrayOutputStream();
			byte[] readDate = new byte[1024];
			while (bis.read(readDate) >= 0)
			{
				bos.write(readDate);
			}
			pkcs7Data = bos.toByteArray();
		}
		finally
		{
			if (bis != null)
			{
				try
				{
					bis.close();
				}
				catch(Exception ex)
				{
				}
			}
			if (bos != null)
			{
				try
				{
					bos.close();
				}
				catch(Exception ex)
				{
				}
			}
		}
		installCertificate(pkcs7Data, priKeyPassword);
	}
	
	public void installCertificate(final X509Certificate chain[], char[] priKeyPassword) throws KeyStoreException, NoSuchAlgorithmException
	{
		final Enumeration<String> eAlias = this.keyStore.aliases();
		boolean notFound = true;
		String alias = "";
	
		if (null != eAlias && eAlias.hasMoreElements())
		{
			while (eAlias.hasMoreElements() && notFound)
			{
				alias = eAlias.nextElement();
				final PublicKey hsmPublicKey = getCertificate(alias).getPublicKey();
				final PublicKey importPublicKey = chain[0].getPublicKey();
				if (hsmPublicKey.equals(importPublicKey))
				{
					this.keyStore.setKeyEntry(alias, getPrivateKey(alias, priKeyPassword), priKeyPassword, chain);
					notFound = false;
				}
			}
			if (notFound)
			{
				throw new KeyStoreException("Not found a matching public key.");
			}
		}
		else
		{
			alias = DEFAULT_ALIAS;
		}
		for (X509Certificate cert : chain)
		{
			String alias1 = DnComponents.stringToBCDNString(cert.getSubjectDN().getName());
			if (!alias1.equalsIgnoreCase(alias))
			{
				this.keyStore.setCertificateEntry(alias1, cert);
			}
		}
	}

	public PrivateKey getPrivateKey(String alias, char[] priKeyPassword) throws KeyStoreException, NoSuchAlgorithmException
	{
		try
		{
			return (PrivateKey)keyStore.getKey(alias, priKeyPassword);
		}
		catch (UnrecoverableKeyException e1)
		{
			e1.printStackTrace();
			return null;
		}
	}
	
	public void installTrustedCertificate(X509Certificate cert) throws Exception
	{
		if (!this.keyStore.containsAlias(DnComponents.stringToBCDNString(cert.getSubjectDN().getName())))
		{
			this.keyStore.setCertificateEntry(DnComponents.stringToBCDNString(cert.getSubjectDN().getName()), cert);
		}
	}
	
	public void deleteAlias(String alias) throws KeyStoreException
	{
		this.keyStore.deleteEntry(alias);
	}
	
	public Enumeration<String> aliases() throws KeyStoreException
	{
		return keyStore.aliases();
	}
	
	public boolean isCertificate(String alias) throws KeyStoreException
	{
		return keyStore.isCertificateEntry(alias);
	}
	
	public boolean isKey(String alias) throws KeyStoreException
	{
		return keyStore.isKeyEntry(alias);
	}
}

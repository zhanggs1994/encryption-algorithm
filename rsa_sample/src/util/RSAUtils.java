package util;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.Cipher;

public class RSAUtils {
	/**
	 * 用RSA算法给字节数组加密返回字节数组
	 * @param pk
	 * 			加密需要的公钥
	 * @param data
	 * 			需要加密的字节数组
	 * @return
	 * 			返回加密后的字节数组
	 * @throws Exception
	 */
	private static byte[] encrypt(PublicKey pk, byte[] data) throws Exception {

		Cipher cipher = Cipher.getInstance("RSA",
				new org.bouncycastle.jce.provider.BouncyCastleProvider());
		cipher.init(Cipher.ENCRYPT_MODE, pk);
		int blockSize = cipher.getBlockSize();// 获得加密块大小
		int outputSize = cipher.getOutputSize(data.length);// 获得加密块加密后块大小
		int leavedSize = data.length % blockSize;//取膜
		int blocksSize = leavedSize != 0 ? data.length / blockSize + 1
				: data.length / blockSize;
		byte[] raw = new byte[outputSize * blocksSize];
		int i = 0;
		while (data.length - i * blockSize > 0) {
			if (data.length - i * blockSize > blockSize)
				cipher.doFinal(data, i * blockSize, blockSize, raw, i
						* outputSize);
			else
				cipher.doFinal(data, i * blockSize,
						data.length - i * blockSize, raw, i * outputSize);
			i++;
		}
		return raw;

	}

	/**
	 * 
	 * @param pk
	 * 			加密公钥
	 * @param file
	 * 			加密文件
	 * @param destFile
	 * 			目标文件
	 * @throws Exception
	 */
	public static void encryptToFile(RSAPublicKey pk, String file,
			String destFile) throws Exception {
		//将加密文件读取后放到内存中
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		InputStream is = new FileInputStream(file);
		byte[] b = new byte[1024];
		int r;
		while ((r = is.read(b)) > 0) {
			baos.write(b, 0, r);
		}
		byte[] data = baos.toByteArray();
		byte[] bytes = encrypt(pk, data);
		OutputStream os = new FileOutputStream(destFile);
		os.write(bytes);
		baos.close();
		os.close();
	}

	/**
	 * 
	 * @param pk
	 * 			解密私钥
	 * @param data
	 * 			解密字节数组
	 * @return
	 * 			返回字节数组
	 * @throws Exception
	 */
	private static byte[] decrypt(RSAPrivateKey pk, byte[] data)
			throws Exception {

		Cipher cipher = Cipher.getInstance("RSA",
				new org.bouncycastle.jce.provider.BouncyCastleProvider());
		cipher.init(Cipher.DECRYPT_MODE, pk);
		int blockSize = cipher.getBlockSize();
		ByteArrayOutputStream bout = new ByteArrayOutputStream(64);
		int j = 0;

		while (data.length - j * blockSize > 0) {
			bout.write(cipher.doFinal(data, j * blockSize, blockSize));
			j++;
		}
		return bout.toByteArray();

	}
/**
 * 
 * @param pk
 * 			解密私钥
 * @param file
 * 			解密文件
 * @param destFile
 * 			目标文件
 * @throws Exception
 */
	public static void decryptToFile(RSAPrivateKey pk, String file,
			String destFile) throws Exception {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		InputStream is = new FileInputStream(file);
		byte[] b = new byte[1024];
		int r;
		while ((r = is.read(b)) > 0) {
			baos.write(b, 0, r);
		}
		byte[] data = baos.toByteArray();
		byte[] bytes = decrypt(pk, data);
		OutputStream os = new FileOutputStream(destFile);
		os.write(bytes);
		baos.close();
		os.close();
	}

}

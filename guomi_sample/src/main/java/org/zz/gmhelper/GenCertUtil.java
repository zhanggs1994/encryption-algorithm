package org.zz.gmhelper;


import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ECPoint;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.cert.bc.BcX509v3CertificateBuilder;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.bc.BcECContentSignerBuilder;
import org.bouncycastle.x509.X509V3CertificateGenerator;

import javax.security.auth.x500.X500Principal;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Random;

public class GenCertUtil {
    public static void genSM2CertBySelf() throws Exception {

        String dn = "CN=dfg, OU=aert, O=45y, L=sdfg, ST=fg, C=CN";

        long year = 360 * 24 * 60 * 60 * 1000;

        Date notBefore = new Date();

        Date notAfter = new Date(notBefore.getTime() + year);

        //证书的名称

        String fileName = "self" + new Date().getTime() / 1000;

        String path = "/testGenCer/";

        String rootCertPath = path + fileName + ".der";

        AsymmetricCipherKeyPair kp = Sm2Util.generateAsymmetricCipherKeyPair();

        ECPrivateKeyParameters bcecPrivateKey = (ECPrivateKeyParameters) kp.getPrivate();
        ECPublicKeyParameters bcecPublicKey = (ECPublicKeyParameters) kp.getPublic();
        BigInteger privateKey = bcecPrivateKey.getD();
        ECPoint publicKey = bcecPublicKey.getQ();

        System.out.println("公钥: " + TypeHandleUtil.byteToHex(publicKey.getEncoded()));
        System.out.println("私钥: " + TypeHandleUtil.byteToHex(privateKey.toByteArray()));

        BcX509v3CertificateBuilder build = new BcX509v3CertificateBuilder(

                new X500Name(dn),

                BigInteger.probablePrime(64, new Random()),

                notBefore,

                notAfter,

                new X500Name(dn),

                bcecPublicKey);

        AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find("SM3withSM2");//即"1.2.156.10197.1.501"

        AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find("SHA256");

        ContentSigner sigGen = new BcECContentSignerBuilder(sigAlgId, digAlgId).build(bcecPrivateKey);
        build.addExtension(Extension.basicConstraints,true,"aaa".getBytes());
        X509CertificateHolder x509certHolder = build.build(sigGen);

        FileOutputStream outputStream = new FileOutputStream(rootCertPath);

        outputStream.write(x509certHolder.getEncoded());
        outputStream.close();

    }

    /**
     * 转换为夹带公钥参数对象
     *
     * @param pub
     * @return
     */
    public static SubjectPublicKeyInfo createSubjectECPublicKeyInfo(ECPublicKeyParameters pub) {
        ASN1OctetString p = (ASN1OctetString) new X9ECPoint(pub.getQ()).toASN1Primitive();

        return new SubjectPublicKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, GMObjectIdentifiers.sm2p256v1), p.getOctets());

    }

//
//    /**
//     * 国密证书签名算法标识
//     */
//    private static String SignAlgor = "1.2.156.10197.1.501";
//    /**
//     * 生成国密ROOT证书方法
//     *
//     * @param
//     * @throws Exception
//     */
//    public static void genSM2CertByRoot() throws Exception {
//        SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
//        long year = 360 * 24 * 60 * 60 * 1000;
//        Date notBefore = new Date();
//        Date notAfter = new Date(notBefore.getTime() + year);
//        org.bouncycastle.jce.provider.BouncyCastleProvider bouncyCastleProvider = new org.bouncycastle.jce.provider.BouncyCastleProvider();
//        Security.addProvider(bouncyCastleProvider);
//        //证书的名称
//        String fileName = "root" + new Date().getTime() / 1000;
//        String path = "/testGenCer/";
//        String rootCertPath = path + fileName + ".cer";
//        try {
//            KeyPair kp = Sm2Util.generateKeyPair();
//          //这块就是生成SM2公私钥对  非免费提供的代码 有需要加QQ:783021975 具体价格:https://pan.baidu.com/s/1OhC2G944fzkWAzU5RyEM6A
//            System.out.println("=====公钥算法====="+kp.getPublic().getAlgorithm());
//            BCECPrivateKey bcecPrivateKey = (BCECPrivateKey) kp.getPrivate();
//            BCECPublicKey bcecPublicKey = (BCECPublicKey) kp.getPublic();
//
//
//            //这块就是生成SM2公私钥对
//            System.out.println("=====公钥算法=====" + kp.getPublic().getClass());
//
//            //申请服务器证书信息  我是通过网页得到传递的参数 。如果测试 写死即可。这一步没有什么的。
//            X500Principal principal = new X500Principal("CN=小帅丶博客,O=小帅丶博客");
//            //X500Principal principal = new X500Principal("CN="+pageCert.getCn()+",O="+pageCert.getO());
//            X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
//            certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
//            certGen.setIssuerDN(principal);
//            certGen.setNotBefore(new Date());
//            certGen.setNotAfter(notAfter);
//            certGen.setSubjectDN(principal);
//            certGen.setSignatureAlgorithm(SignAlgor);
//            certGen.setPublicKey(bcecPublicKey);
////             //添加CRL分布点 QQ:783021975
////            certGen.addExtension(Extension.cRLDistributionPoints, true, XSCertExtension.getCRLDIstPoint());
////             //添加证书策略 QQ:783021975
////            certGen.addExtension(Extension.certificatePolicies, true, new DERSequence(XSCertExtension.getPolicyInfo()));
////            //颁发者密钥标识
////            DigestCalculator calculator = new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1));
////            X509ExtensionUtils extensionUtils = new X509ExtensionUtils(calculator);
////            certGen.addExtension(Extension.authorityKeyIdentifier, false, extensionUtils.createAuthorityKeyIdentifier(publicKeyInfo));
////            //使用者密钥标识
////            certGen.addExtension(Extension.subjectKeyIdentifier, false, extensionUtils.createSubjectKeyIdentifier(publicKeyInfo));
////            //密钥用法 QQ:783021975
////            certGen.addExtension(Extension.keyUsage, true, XSCertExtension.getKeyUsage());
////            //增强密钥用法 QQ:783021975
////            certGen.addExtension(Extension.extendedKeyUsage, true, XSCertExtension.getExtendKeyUsage());
//            //基本约束
////            BasicConstraints basicConstraints = new BasicConstraints(0);
////            certGen.addExtension(Extension.basicConstraints, true, basicConstraints);
//            certGen.addExtension("userInfo",true,"aaa".getBytes());
//            X509Certificate rootCert = certGen.generateX509Certificate(bcecPrivateKey, "BC");
//            FileOutputStream outputStream = new FileOutputStream(rootCertPath);
//            outputStream.write(rootCert.getEncoded());
//            outputStream.close();
//        } catch (Exception e) {
//            System.out.println("======根证书申请失败" + e.getMessage());
//        }
//    }


}

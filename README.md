##RSA非对称加密和数字签名代码示例
`
	import java.io.ByteArrayInputStream;
	import java.io.ByteArrayOutputStream;
	import java.io.InputStream;
	import java.security.Key;
	import java.security.KeyFactory;
	import java.security.KeyPair;
	import java.security.KeyPairGenerator;
	import java.security.NoSuchAlgorithmException;
	import java.security.PrivateKey;
	import java.security.PublicKey;
	import java.security.Signature;
	import java.security.interfaces.RSAPrivateKey;
	import java.security.interfaces.RSAPublicKey;
	import java.security.spec.PKCS8EncodedKeySpec;
	import java.security.spec.X509EncodedKeySpec;
	
	import javax.crypto.Cipher;
	
	import org.apache.commons.codec.CharEncoding;
	import org.apache.commons.codec.binary.Base64;

	public class RSAEncode {
		private static final String PRIVATEKEY = "MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBANQC"
				+ "oC6334MPhQWnfTDUZ7N1P2clRTfoDp/uMCClSMY1Ptf57nMYa87QbzSui61/9xtNKr1MJ2vCff2La5Dp0vGcWyTOKe"
				+ "bva1QgPs/G8Vm7wG2QtB4vlkEj0Mfga2IEbTrz8Drk4wSO8gKNjI9E8EnoBKKcUTAjJsgDiPoUP6YRAgMBAAECgYEAlI2W"
				+ "ccXTLoFUYwbd+LYMR7mzCHIcEzVd8gAy5t0JpiCu/SSaSTlmaQ6xrUdUheixXAbxGJzgzmgEYgEsCOleLTkg5+cUp0MJ7Sfo"
				+ "Edrz/dtjp9+M2CQMpCUVRVoHlJLbRB3AEwo+PEnefu/gkx6k2E/sEuzDbiopQpO1ZcWsnvECQQDuax56efeAiijve2cmtDbk"
				+ "ICuEX6db1we/+cwUawp0E5grADI7VGA//z2RUl/wBn+okeVZdNrx2ls5WvXhS7UNAkEA46T4m3+lAA6nAIBHRCksgFPWWP2"
				+ "Per22WyblUr6Sp3sYjtBUx10znQexV9t2sBP4Gg++NbUv3yKIKBZWa9X8FQJBAKZ8Xrgf21kDITq57Xn1di8u17SEJxX"
				+ "Wvi6sfHn1lUMhO60rYehULzIBRjjoUN4Ha7WGy6UAGLOySuluPyyn9TECQGzW5V5DazpZxxMAQhKetP4uF1+46669ocB3G"
				+ "lGzeB7HRfiSNtaTAyhjEzF0ZozNH2QmfsTi+h5vPjYcZ/lq9/kCQQCwDYpT2Pz2bmmESyJIj"
				+ "jgLLvyoa1irG0sNvFtNczayj25IzTSTQttBdByi5zteoO2sDvHOAxaE/pdL9HM64bNE";
		private static final String PUBLICKEY = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDUAqAut9+DD"
				+ "4UFp30w1GezdT9nJUU36A6f7jAgpUjGNT7X+e5zGGvO0G80routf/cbTSq9TCdrwn39i2uQ6d"
				+ "LxnFskzinm72tUID7PxvFZu8BtkLQeL5ZBI9DH4GtiBG068/A65OMEjvICjYyPRPBJ6ASinFEwIybIA4j6FD+mEQIDAQAB";
		
		private static final String AlGORITHM = "RSA";
		/**
		 * RSA
		 * 
		 * 初始化方法
		 * 长度为1024
		 * @throws NoSuchAlgorithmException
		 */
		public static final void init() throws NoSuchAlgorithmException{
			KeyPairGenerator kpg = KeyPairGenerator.getInstance(AlGORITHM);
			kpg.initialize(1024);
			kpg.generateKeyPair().getPrivate();
			KeyPair keyPair = kpg.generateKeyPair();
			
			System.out.println("#############################公钥#################################");
			RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
			System.out.println(Base64.encodeBase64String(publicKey.getEncoded()));
			
			System.out.println("#############################私钥#################################");
			RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
			System.out.println(Base64.encodeBase64String(privateKey.getEncoded()));
			
		}
		/**
		 * 用私钥加密
		 * 
		 * @param input
		 * @param privateKey
		 * @return
		 * @throws Exception
		 */
		public static byte[] encryptByPrivateKey(byte[] input,String privateKey) throws Exception{
			//解密私钥，生成PKCS8EncodedKeySpec对象
			PKCS8EncodedKeySpec pKeySpec = new PKCS8EncodedKeySpec(Base64.decodeBase64(privateKey));
			//生成RSA 加密工厂类
			KeyFactory keyFactory = KeyFactory.getInstance(AlGORITHM);
			//生成加密的key
			Key key = keyFactory.generatePrivate(pKeySpec);
			//创建Cipher对象（此类为加密和解密提供密码功能。它构成了 Java Cryptographic Extension (JCE) 框架的核心。）
			Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
			//初始化Cipher，设置模式为加密模式
			cipher.init(Cipher.ENCRYPT_MODE, key);
			
			byte[] returnBytes = cipher.doFinal(input);
			
			return returnBytes;
		}
		/**
		 * 用公钥解密
		 * 
		 * @param data
		 * @param publicKey
		 * @return
		 * @throws Exception
		 */
		public static byte[] decryptByPublicKey(byte[] data,String publicKey) throws Exception{
			//解密公钥，生成X509EncodedKeySpec对象
			X509EncodedKeySpec xKeySpec = new X509EncodedKeySpec(Base64.decodeBase64(publicKey));
			//生成RSA 加密工厂类
			KeyFactory keyFactory = KeyFactory.getInstance(AlGORITHM);
			//生成加密的key
			Key key = keyFactory.generatePublic(xKeySpec);
			//创建Cipher对象（此类为加密和解密提供密码功能。它构成了 Java Cryptographic Extension (JCE) 框架的核心。）
			Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
			cipher.init(Cipher.DECRYPT_MODE, key);
			
			InputStream is = new ByteArrayInputStream(data);
			
			ByteArrayOutputStream write = new ByteArrayOutputStream();
			byte[] buf = new byte[128];
			int flag;
			
			while((flag = is.read(buf)) != -1){
				byte[] block = null;
				if (flag == buf.length) {
					block = buf;
				}else{
					block = new byte[flag];
					for (int i = 0; i < flag; i++) {
						block[i] = buf[i];
					}
				}
				write.write(cipher.doFinal(block));
			}
			
			return write.toByteArray();
		}
		/**
		 * 用公钥解密
		 * 
		 * @param input
		 * @param publicKey
		 * @return
		 * @throws Exception
		 */
		public static byte[] encryptByPublicKey(byte[] input,String publicKey) throws Exception{
			//解密公钥，生成KeySpec对象
			X509EncodedKeySpec xKeySpec = new X509EncodedKeySpec(Base64.decodeBase64(publicKey));
			//生成RSA加密工厂类
			KeyFactory keyFactory = KeyFactory.getInstance(AlGORITHM);
			//生成加密的key
			Key key = keyFactory.generatePublic(xKeySpec);
			//创建Cipher对象（此类为加密和解密提供密码功能。它构成了 Java Cryptographic Extension (JCE) 框架的核心。）
			Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
			cipher.init(Cipher.ENCRYPT_MODE, key);
			return cipher.doFinal(input);
		}
		/**
		 * 用私钥解密
		 * @param data
		 * @param privateKey
		 * @return
		 * @throws Exception
		 */
		public static byte[] decryptByPrivateKey(byte[] data,String privateKey) throws Exception{
			//解密公钥，生成KeySpec对象
			PKCS8EncodedKeySpec pKeySpec = new PKCS8EncodedKeySpec(Base64.decodeBase64(privateKey));
			//生成RSA加密工厂类
			KeyFactory keyFactory = KeyFactory.getInstance(AlGORITHM);
			//生成加密的key
			Key key = keyFactory.generatePrivate(pKeySpec);
			//创建Cipher对象（此类为加密和解密提供密码功能。它构成了 Java Cryptographic Extension (JCE) 框架的核心。）
			Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
			cipher.init(Cipher.DECRYPT_MODE, key);
			
			InputStream is = new ByteArrayInputStream(data);
			ByteArrayOutputStream write = new ByteArrayOutputStream();
			byte[] buf = new byte[128];
			int flag;
			while((flag = is.read(buf)) != -1){
				byte[] block = null;
				if (flag == buf.length) {
					block = buf;
				}else{
					block = new byte[flag];
					for (int i = 0; i < flag; i++) {
						block[i] = buf[i];
					}
					
				}
				write.write(cipher.doFinal(block));
				
			}
			
			return write.toByteArray();
		}
		
		/**
		 * 算法签名 也可以是MD5withRSA或者其他
		 *
		 */
		
		static final String SIGN_ALGORITHM = "SHA1WithRSA";
		/**
		 * 对数据进行数字签名
		 * 
		 * @param content
		 * @param privateKey
		 * @param charset
		 * @return
		 * @throws Exception
		 */
		public static String sign(String content,String privateKey,String charset) throws Exception{
			PKCS8EncodedKeySpec pKeySpec = new PKCS8EncodedKeySpec(Base64.decodeBase64(privateKey));
			KeyFactory keyFactory = KeyFactory.getInstance(AlGORITHM);
			PrivateKey key = keyFactory.generatePrivate(pKeySpec);
			//生成签名对象
			Signature signature = Signature.getInstance(SIGN_ALGORITHM);
			//通过私钥初始化
			signature.initSign(key);
			//写入要签名的数据
			signature.update(content.getBytes(charset));
			//获取签名后的数据
			byte[] data = signature.sign();
			
			return Base64.encodeBase64String(data);
		}
		/**
		 * 校验签名数据是否正确
		 * @param content
		 * @param signStr
		 * @param publicKey
		 * @param charset
		 * @return
		 * @throws Exception
		 */
		public static boolean verify(String content,String signStr,String publicKey,String charset) throws Exception{
			X509EncodedKeySpec xKeySpec = new X509EncodedKeySpec(Base64.decodeBase64(publicKey));
			KeyFactory keyFactory = KeyFactory.getInstance(AlGORITHM);
			PublicKey key = keyFactory.generatePublic(xKeySpec);
			Signature signature = Signature.getInstance(SIGN_ALGORITHM);
			signature.initVerify(key);
			signature.update(content.getBytes(charset));
			
			return signature.verify(Base64.decodeBase64(signStr));
		}
		
		public static void main(String[] args) throws Exception {
			//		初始化key
			//		initKey();
					String content = "123";
					System.out.println("------------------下面是公钥加密和私钥解密------------------");
					//对数据进行加密
					byte[] encryptedData = encryptByPublicKey(content.getBytes(), PUBLICKEY);
					String encryptedStr = Base64.encodeBase64String(encryptedData);
					System.out.println("加密后的字符串："+encryptedStr);
					//解密
					byte[] s = decryptByPrivateKey(Base64.decodeBase64(encryptedStr), PRIVATEKEY);
			//		byte[] s = decryptByPrivateKey(encryptedData, PRIVATEKEY);//直接使用加密后的byte数组就行
					System.out.println("解密后："+new String(s));
					
					System.out.println("------------------下面是私钥加密和公钥解密------------------");
					//对数据进行加密
					byte[] encryptedData2 = encryptByPrivateKey(content.getBytes(), PRIVATEKEY);
					//解密
					byte[] s2 = decryptByPublicKey(encryptedData2, PUBLICKEY);//直接使用加密后的byte数组就行
					System.out.println("解密后："+new String(s2));
					
					System.out.println("------------------下面是签名和签名验证------------------");
					String signStr = sign(content, PRIVATEKEY, CharEncoding.UTF_8);
					System.out.println("签名数据："+signStr);
					System.out.println("签名验证结果:"+verify("223", signStr, PUBLICKEY, CharEncoding.UTF_8));
					System.out.println("签名验证结果:"+verify("123", signStr, PUBLICKEY, CharEncoding.UTF_8));
				}
	
		
	}
`

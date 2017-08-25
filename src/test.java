
public class test {

	public static void main(String[] args) throws Exception {
		RSACoder.KeyInit();

		String entest=RSACoder.PrivateEncrypt("hello", RSACoder.getPrivateKey());
		String detest=RSACoder.PublicDecrypt(entest, RSACoder.getPublicKey(3));
		
		System.out.println(detest);

	}

}

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;

public abstract class RSACoder {
	public static  String Certificate = null;
	public static int Header=1;
	public static Boolean flag=false;
	public static int AllNum=4;
    private static PrivateKey privateKey;
    public static String[] publicKeyString={"MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAJY4OqNN0kSr79WojHwSVVvch+oaazv4QJfQ+A9HNSgxOPXUfiXB7USat7PFkMN5UHdSXyZlIt0xlAtROPcZGk0CAwEAAQ==","MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAI01Ce6LrNb8kdmjk9NJ7EgWwGLn51mf3XE4hFnNyq2WOiKK83sZjDVjIkYAFf+SpKIGohm54Jtfx54OypOtONUCAwEAAQ==","",""};  
    public static String privateKeyString="MIIBUwIBADANBgkqhkiG9w0BAQEFAASCAT0wggE5AgEAAkEAjTUJ7ous1vyR2aOT00nsSBbAYufnWZ/dcTiEWc3KrZY6IorzexmMNWMiRgAV/5KkogaiGbngm1/Hng7Kk6041QIDAQABAkBZzfGTFKHH2LmpgK7zIYB0GIQiYvpvtYxQBXGm64qK+pauioT/CR4TrGA7di3CbTBhsXKe1cGMJQdgBuKAI6gBAiEA8yGeHNg2bE41foAZ29rc+vsGPLtW7O+q+rb28abxSrUCIQCUrl5rdePUjDZDhB2YoPUIADjHJe04DocuKVbsPcVpoQIgLn3bMkDWB1fdOtdcGoJ7hzLBOpPIR358/3xFNGhr85ECIG/lErY5EO+jXitNwKBfcklFMXXfOzpW5LF+9yXwDyRBAiA4BJ9kVaajbBAxMNS/YD3fxX1kv/D7cFu6WK4SgqlYqA==";
    public static PublicKey[] publicKey=new PublicKey[4];
    public static Map<Integer, String> NameTable=new HashMap<Integer,String>()
    		{{
    			put(0,"CA");
    			put(1, "ZhouYi");
    			put(2, "WangShiSheng");
    			put(3, "TangXie");
    		}};

      public static void KeyInit() throws Exception//閸掓繂顫愰崠锟�
      {
    	  //閸掓繂顫愰崠鏍寽閸栨瑤瑕�
    	  	privateKey=GeneratePrivateKey(privateKeyString);
    	  	for(int i=0;i<AllNum;i++)
    	  	{
    	  		if(!publicKeyString[i].isEmpty())
    	  			publicKey[i]=GeneratePublicKey(publicKeyString[i]);
    	  	}
    	  	flag=true;
      }
      //鐏忓摴ase64缂傛牜鐖滈崥搴ｆ畱缁変線鎸滅�涙顑佹稉鑼舵祮閹存�璾blicKey鐎圭偘绶� 
    private static PublicKey GeneratePublicKey(String publicKey) throws Exception{  
    		
        byte[ ] keyBytes=Base64.getDecoder().decode(publicKey.getBytes());  
        X509EncodedKeySpec keySpec=new X509EncodedKeySpec(keyBytes);  
        KeyFactory keyFactory=KeyFactory.getInstance("RSA");  
        return keyFactory.generatePublic(keySpec);    
    }  
      
    //鐏忓摴ase64缂傛牜鐖滈崥搴ｆ畱缁変線鎸滅�涙顑佹稉鑼舵祮閹存�璻ivateKey鐎圭偘绶�  
    private static PrivateKey GeneratePrivateKey(String privateKey) throws Exception{  
   
        byte[ ] keyBytes=Base64.getDecoder().decode(privateKey.getBytes());  
        PKCS8EncodedKeySpec keySpec=new PKCS8EncodedKeySpec(keyBytes);  
        KeyFactory keyFactory=KeyFactory.getInstance("RSA");  
        return keyFactory.generatePrivate(keySpec);  
    }  
     
    //閸忣剟鎸滈崝鐘茬槕  
    public static String PublicEncrypt(String content, PublicKey publicKey) throws Exception{  

    		byte[] ContentBytes=content.getBytes();
        Cipher cipher=Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);  
        byte[] EncryptedBytes= cipher.doFinal(ContentBytes);  
        return Base64.getEncoder().encodeToString(EncryptedBytes);
    }  
   //缁変線鎸滈崝鐘茬槕
     public static String PrivateEncrypt(String content,PrivateKey privatekey) throws Exception
     {
	    	 
     	    byte[] ContentBytes=content.getBytes();
    	 	Cipher cipher=Cipher.getInstance("RSA");
    	 	cipher.init(Cipher.ENCRYPT_MODE, privatekey);  
    	 	byte[] EncryptedBytes= cipher.doFinal(ContentBytes);  
            return Base64.getEncoder().encodeToString(EncryptedBytes);
     }
     //閸忣剟鎸滅憴锝呯槕
     public static String PublicDecrypt(String Encrypted, PublicKey publicKey) throws Exception{ 
    	 	
    	     Cipher cipher=Cipher.getInstance("RSA");  
         cipher.init(Cipher.DECRYPT_MODE, publicKey);
         byte[] DecryptedBytes=cipher.doFinal(Base64.getDecoder().decode(Encrypted));
         return new String(DecryptedBytes);
     }  
    //缁変線鎸滅憴锝呯槕  
    public static String PrivateDecrypt(String Encrypted, PrivateKey privateKey) throws Exception{ 

        Cipher cipher=Cipher.getInstance("RSA");  
        cipher.init(Cipher.DECRYPT_MODE, privateKey);  
        byte[] DecryptedBytes=cipher.doFinal(Base64.getDecoder().decode(Encrypted));
        return new String(DecryptedBytes);
    }  
    //閼惧嘲褰囬弮鍫曟？閹达拷
    public static String GettimeStamp()
    {
    		Date date=new Date();
    		SimpleDateFormat df=new SimpleDateFormat("yyyyMMddhh");
    		return df.format(date);
    }
    //缁涙儳鎮曢悽鐔稿灇
    public static String GetSig(String data,PrivateKey privatekey) throws Exception
    {
    		Signature SigFactory=Signature.getInstance("MD5withRSA");
    		SigFactory.initSign(privatekey);
    		SigFactory.update(data.getBytes());
    		byte[] signed=SigFactory.sign();
    		return new String(Base64.getEncoder().encode(signed));
    }
    //缁涙儳鎮曟宀冪槈
    public static boolean VerifySig(int Header,String Sign,PublicKey publicKey) throws Exception
    {
    		Signature SigFactory=Signature.getInstance("MD5withRSA");
    		SigFactory.initVerify(publicKey);
    		String TrueSig=NameTable.get(Header);
    		SigFactory.update(TrueSig.getBytes());
    		return SigFactory.verify(Base64.getDecoder().decode(Sign.getBytes()));
    	
    }
    /*
    //0婵夘偄鍘�
    public static String FullFill(String CipherText,int GapNum)
    {
    		if(CipherText.length()==70)
    			return CipherText;
    		int gap=70-CipherText.length();
    		Gap[GapNum]=gap;
    		for(int i=1;i<=gap;i++)
    		{
    			CipherText+="0";
    		}
    		
    		return CipherText;
    }*/
    
    //閻㈢喐鍨氱粔姗�鎸滅�电櫢绱濇径鍥╂暏
    public static void getKeyPair(int keyLength,int PublicKeyNum) throws Exception{  
        KeyPairGenerator keyPairGenerator=KeyPairGenerator.getInstance("RSA");  
        keyPairGenerator.initialize(keyLength);        
        KeyPair tmpKeyPair=keyPairGenerator.generateKeyPair();  
        publicKey[PublicKeyNum]=tmpKeyPair.getPublic();
        privateKey=tmpKeyPair.getPrivate();
    }  
    //閼惧嘲绶辩粔渚�鎸�
    public static PrivateKey getPrivateKey() throws Exception
    {
    		//if(flag!=false)
    			return privateKey;
    		//else
    		//{	
    		//	if(flag==false)
    			//	KeyInit();
    		//	return privateKey;
    		//}
    }
    //閼惧嘲绶遍崗顒勬寽
    public static PublicKey getPublicKey(int num) throws Exception
    {
    		if(num<AllNum&&publicKey[num]!=null)
    			return publicKey[num];
    		else 
    		{	
    			if(num>=AllNum)
    			{
    				System.out.println("Out of range!");
        			return null;
    			}
    				KeyInit();
    				return publicKey[num];   			
    		}
    }
    //鐠囦椒鍔熼惃鍕崣鐠囷拷
    public static boolean VerifyCert(String Cert,String Header) throws Exception
    {
    		String myCert=PublicDecrypt(Cert, getPublicKey(0));
    		
    		String time=GettimeStamp();
    		if(Header.equals(myCert.substring(0, 1))&&time.equals(myCert.substring(1,11)))
    			return true;
    		else 
    			return false;
    }
    //0閹搭亝鏌�
    /*public static String Truncate(String Originial,int Gap)
    {
    		return Originial.substring(0,Originial.length()-Gap);
    }*/
}
 
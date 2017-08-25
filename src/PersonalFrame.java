import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;


public class PersonalFrame extends JFrame implements ActionListener{
	private static final long serialVersionUID = 1L;
	//Frame Name
	private String From;
	private String name;
	public String myword;
	private JPanel PCenter = new JPanel();
	private JTextArea PShowMsg = new JTextArea(10,20);
	private JScrollPane PShowPane = new JScrollPane(PShowMsg);
	private JPanel PoperPane = new JPanel();
	private JLabel Pinput = new JLabel("请输入:");
	private JTextField PmsgInput = new JTextField(28);
	private JButton Psend = new JButton("send");	
	public PersonalFrame(String From,String name){

		this.From=From;
		this.name = name;
		setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
		initPersonalFrame();
		initEvent();
	}
	//字符串转换成二进制
   /* private String StrToBinstr(String str){
    	char[] strChar = str.toCharArray();
    	String result ="";
    	for(int i=0;i<strChar.length;i++){
    		result+=Integer.toBinaryString(strChar[i])+" ";
    	}
    	return result;
    }*/
	private void initPersonalFrame(){
		PmsgInput.setActionCommand("send");
		PShowMsg.setEditable(false);
		BorderLayout bl3 = new BorderLayout();
		PCenter.setLayout(bl3);
		FlowLayout fl = new FlowLayout(FlowLayout.LEFT);
		PoperPane.setLayout(fl);
		PoperPane.add(Pinput);
		PoperPane.add(PmsgInput);
		PoperPane.add(Psend);
		PCenter.add(PShowPane,BorderLayout.CENTER);
		PCenter.add(PoperPane,BorderLayout.SOUTH);
		add(PCenter,BorderLayout.CENTER);
		add(PCenter);
		setSize(450,300);
		setLocation(300,200);
		setResizable(false);
		//私聊 
		setTitle("与"+name+"单独聊天中.....");
		setVisible(true);
	}
	private void initEvent(){
		 Psend.addActionListener(this);
		 PmsgInput.addActionListener(this);
	}
	@Override
	//按键作用
	public void actionPerformed(ActionEvent e) {
		try{
			String cmd=e.getActionCommand();
			if(cmd.equals("send")){
				SendMessage();
			}
		}catch(Exception ex)
		{}
		
	}
	private void SendMessage()throws Exception{
		
		//判断是否连接了服务器
		if(Client.socket == null){
			JOptionPane.showMessageDialog(this, "没有连接服务器或已经断开服务器");
			return;
			
		}
		
		//发送消息
		String content = From+"说：\n"+ PmsgInput.getText();	
		myword = content;
		
		String old = PShowMsg.getText();
		if(old.isEmpty() || old.trim().equals("")){
			PShowMsg.setText(myword);
			
		}
		else{
			String temp = old+"\n"+myword;
			PShowMsg.setText(temp);
		}

		Client.SendNum=Integer.parseInt(name);
		content=PackageEva.CreatePackage(PmsgInput.getText(), Client.SendNum);
		
		if(content.isEmpty() || content.trim().equals("")){
			JOptionPane.showMessageDialog(this, "不能发送空字符串");
			return;
		}else{
			//清空文本输入框
			PmsgInput.setText("");
		}
		
		Message msg = new Message(From, content, MessageType.Chat, ChatState.Personal, name);
		Client.oos.writeObject(msg);
		Client.oos.flush();
	}
	public void showMsg(Message msg) throws Exception{		 
		
		String content = msg.getContent();
		content=PackageEva.DecreatePackage(content);
		PShowMsg.setText("发送者："+msg.getFrom()+"\n"+"接收者："+msg.getTo()+"\n"+content);
		
		System.out.println(content);

		PShowMsg.setCaretPosition(PShowMsg.getText().length());
	}
	public String getName(){
		return name;
	}
	public String getFrom(){
		return From;
	}
	@Override
	public void dispose(){
		Client.personalFrames.remove(this);
		super.dispose();
	}
	
}

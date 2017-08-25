import java.awt.*;
import java.awt.event.*;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.swing.*;
public class Client extends JFrame implements ActionListener {
	private static final long serialVersionUID = 1L;
	public static int SendNum=-1;
	//界面
	//north
	JMenuBar bar = new JMenuBar();
	JMenu m1 = new JMenu("连接服务器");
	JMenu m2 = new JMenu("关于");
	JMenuItem conServer = new JMenuItem("连接服务器");
	JMenuItem disServer = new JMenuItem("断开服务器");
    JMenuItem exit = new JMenuItem("退出");
    JMenuItem about = new JMenuItem("关于本软件");
	//ImageIcon img = new ImageIcon(Client.class.getResource("top.jpg"));
    //JLabel top = new JLabel(img);
    JPanel north = new JPanel();
    //west
    JButton Cert = new JButton("请求证书");
    JTextField wanted = new JTextField();
    
    
    JPanel west = new JPanel();
    //ImageIcon img2 = new ImageIcon(Client.class.getResource("left.jpg"));
    //JLabel left = new JLabel(img2);
    DefaultListModel dlm = new DefaultListModel();
    JList userList = new JList(dlm);
    JScrollPane listPane = new JScrollPane(userList);
    //center
    JPanel center = new JPanel();
    JTextArea showMsg = new JTextArea(10,20);
    JScrollPane showPane = new JScrollPane(showMsg);
    JPanel operPane = new JPanel();
    //JLabel input = new JLabel("请输入:");
    //JTextField msgInput = new JTextField(24);
    //JButton send = new JButton("send");
    //net
    static Socket socket;
    static String name;
    static ObjectOutputStream oos;
    static List<PersonalFrame> personalFrames = new ArrayList<PersonalFrame>();
	
    public Client() {
		init();
		addEvent();
		initFrame();
	}

    
    
	public void init(){
		//north
		m1.add(conServer);
		m1.add(disServer);
		m1.addSeparator();
		m1.add(exit);
		m2.add(about);
		bar.add(m1);
		bar.add(m2);
		BorderLayout bl = new BorderLayout();
		north.setLayout(bl);
		north.add(bar,BorderLayout.NORTH);
		//north.add(top,BorderLayout.SOUTH);
		add(north,BorderLayout.NORTH);
		//west
		Dimension dim = new Dimension(100,150);
		west.setPreferredSize(dim);
		Dimension dim2 = new Dimension(100,300);
		listPane.setPreferredSize(dim2);
		BorderLayout bl2 = new BorderLayout();
		west.setLayout(bl2);
		//west.add(left,BorderLayout.NORTH);
		west.add(listPane,BorderLayout.NORTH);
		west.add(wanted, BorderLayout.CENTER);
		west.add(Cert,BorderLayout.SOUTH);
		add(west,BorderLayout.EAST);
		userList.setFont(new Font("隶书",Font.BOLD,18));
		//center
		//showMsg.setFont(new Font("宋体",Font.BOLD,28));
		//msgInput.setActionCommand("enterKey");
		showMsg.setEditable(false);
		BorderLayout bl3 = new BorderLayout();
		center.setLayout(bl3);
		FlowLayout fl = new FlowLayout(FlowLayout.LEFT);
		operPane.setLayout(fl);
		//operPane.add(input);
		//operPane.add(msgInput);
		//operPane.add(send);
		center.add(showPane,BorderLayout.CENTER);
		center.add(operPane,BorderLayout.SOUTH);
		add(center,BorderLayout.CENTER);
		
	}
	public void addEvent(){
		//事件的绑定
		Cert.addActionListener(this);
		//send.addActionListener(this);
		//msgInput.addActionListener(this);
		conServer.addActionListener(this);
		disServer.addActionListener(this);
		exit.addActionListener(this);
		about.addActionListener(this);
		SymMouse   picker   =   new   SymMouse();
		userList.addMouseListener(picker);
	}
	public void initFrame(){
		setResizable(false);
		setTitle("即时通讯系统客户端");
		setSize(500,400);
		setLocation(200,50);
		setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
		setVisible(true);
	}
	@Override
	public void dispose(){
		try {
			ExitProgram();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	
	/*
	 * 发送给CA证书请求
	 * content为私聊对象的ID
	 */
	public void SendToCA()throws Exception{	
			//PersonalFrame myFrame=new PersonalFrame(name,userList.getSelectedValue().toString());
			//personalFrames.add(myFrame);
				String tmpcontent = wanted.getText();
				String content = PackageEva.CreatePackage(tmpcontent, 0);
				Message msg = new Message(name,content,MessageType.Chat,ChatState.Personal,"0");
				oos.writeObject(msg);
				oos.flush();
	}
	
	public void ConnectServer()throws Exception{
		//弹出输入框，提示用户输入服务器IP地址
		int cnt = 0;
		do{
			if(++cnt == 4){
				JOptionPane.showMessageDialog(this,"对不起，您的输入已经超出3次\n程序将自动退出！");
				System.exit(0);
			}
			
			String ip = JOptionPane.showInputDialog("请您输入服务器IP:");
			String portStr = JOptionPane.showInputDialog("请您输入服务器PORT:");
			
			System.out.println("程序接收到的信息有："+ip+" "+portStr);
			
		/* */	socket=new Socket(ip,Integer.parseInt(portStr));
			name = "1";
			/*if(name == null || name.trim().equals("")){
				name="游客";
			}*/
			
			OutputStream os = socket.getOutputStream();
			oos = new ObjectOutputStream(os);
			String content = "用户 "+name+" "+new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date())+"上线\n";

			
			Message msg = new Message(name,content,MessageType.Login);
			oos.writeObject(msg);
			oos.flush();
		    
		}while(socket == null);
//		成功创建连接后启动一个新线程接收消息
		new Thread(){
			@Override
			public void run() {
				try {
					boolean flag=true;
					while(flag){
						//获取对方发送过来的信息
						InputStream is = socket.getInputStream();
						ObjectInputStream ois = new ObjectInputStream(is);
						Message msg = (Message)(ois.readObject());																	
						MessageType type = msg.getMsgType();
						//登录状态
						if(type.equals(MessageType.Login)){	
							String content = msg.getContent();
							//System.out.println(content);
							String old = showMsg.getText();
							if(old.isEmpty()|| old.trim().equals("")){
								showMsg.setText(content);
							}else{
								String temp = old+"\n"+content;
								showMsg.setText(temp);
							}
							showMsg.setCaretPosition(showMsg.getText().length());
							if(dlm.size() == 0){
								List<String> names = msg.getNames();
								for(String s : names){
									
									if(!s.equals(name)){
										//添加name到列表中
										dlm.addElement(s);
										System.out.println(s+"添加成功");
									}
								}
							}else{
								if(!msg.getFrom().equals(name))
									dlm.addElement(msg.getFrom());
							}
						}
						
						//聊天状态
						else if(type.equals(MessageType.Chat)){
							//私聊
							
							
							if(msg.getChatState().equals(ChatState.Personal)){
								System.out.println(msg.getContent());
								System.out.println(msg.getContent().length());
								boolean FindIt=false;
								
								for(PersonalFrame pf:personalFrames){
									if(msg.getFrom().equals("0"))
									{
										
										//System.out.println("PK是："+RSACoder.getPublicKey(Integer.parseInt(wanted.getText()))+"\n");
										//System.out.println("证书是："+RSACoder.Certificate+"\n");
										//  System.out.println("成功创建！");
									}
									else if(pf.getName().equals(msg.getFrom())||pf.getName().equals(msg.getTo())){										
																	
										
										pf.showMsg(msg);
										
										
										FindIt=true;
										break;
									}									
								}
								//如果没找到 新建一个私聊
								if(FindIt==false){
								
									 PackageEva.DecreatePackage(msg.getContent());
									System.out.println("证书是："+RSACoder.Certificate+"\n");
									//System.out.println("PK是："+RSACoder.getPublicKey(Integer.parseInt(wanted.getText()))+"\n");
									//myFrame.showMsg(msg);
								}
							}/*else{
									
									String old = showMsg.getText();
									if(old.isEmpty()|| old.trim().equals("")){
										showMsg.setText(content);
									}else{
										String temp = old+"\n"+content;
										showMsg.setText(temp);
									}
									showMsg.setCaretPosition(showMsg.getText().length());
							}*/
						}else if(type.equals(MessageType.Logout)){
							String content = msg.getContent();
							String old = showMsg.getText();
							if(old.isEmpty()|| old.trim().equals("")){
								showMsg.setText(content);
								System.out.println(content);
							}else{
								String temp = old+"\n"+content;
								showMsg.setText(temp);
							}
							showMsg.setCaretPosition(showMsg.getText().length());
							if(!msg.getFrom().equals(name))
								dlm.removeElement(msg.getFrom());
							if(msg.getFrom().equals(name))
								flag=false;
						}
					}
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
			
		}.start();
		setTitle("即时通讯系统客户端---"+name);
	}
	public void BreakServer()throws Exception{
		if(socket!=null){
			String content = "用户 "+name+" "+new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date())+"已经下线"+"\n";
			Message msg=new Message(name, content, MessageType.Logout);
			System.out.println(content);
			oos.writeObject(msg);
			oos.flush();
			dlm.removeAllElements();
			socket=null;
			setTitle("即时通讯系统客户端---"+name+"已离线");
		}
	}
	public void ExitProgram()throws Exception{
		int flag;
		if(socket!=null){
			flag = JOptionPane.showConfirmDialog(this, "还没有注销，直接退出将自动注销连接！\n确定要退出吗？");
		}else{
			flag=0;
		}
		//System.out.println("flag : "+flag);
		if(flag == 0){
			if(socket!=null){
				String content = "用户 "+name+" "+new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date())+"已经下线"+"\n";
				Message msg=new Message(name, content, MessageType.Logout);
				oos.writeObject(msg);
				oos.flush();
				socket=null;
				dlm.removeAllElements();
			}
			System.exit(0);
		}
	}
	//Button对应事件
	public void actionPerformed(ActionEvent e) {
		try{
		String comm = e.getActionCommand();
		System.out.println(comm);
		//if(comm.equals("send") || comm.equals("enterKey")||comm.equals("sendPersonalMessage")){
			//SendMessage();
		//}
		 if(comm.equals("连接服务器")){
			ConnectServer();
		}else if(comm.equals("断开服务器")){
			BreakServer();
		}else if(comm.equals("退出")){
			ExitProgram();
		}else if(comm.equals("关于本软件")){
			JOptionPane.showMessageDialog(this, "客户端");
		}else if(comm.equals("请求证书")){	
			if(wanted.getText()==null||wanted.getText().equals(""))
				JOptionPane.showMessageDialog(this, "不能为空");
			else
				SendToCA();
		}
		else{
			System.out.println("不识别的事件");
		}
		}catch(Exception e1){
		
			//不作处理
		}
	}
	//内部类，用于响应双击JList中item的事件
	class   SymMouse   extends   java.awt.event.MouseAdapter 
    { 
        public   void   mouseClicked(java.awt.event.MouseEvent   e) 
        { 
            Object   object   =   e.getSource(); 
            if(object==userList)
				try {
					userList_mouseClicked(e);
				} catch (Exception e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} 
        } 
    } 

  void   userList_mouseClicked(java.awt.event.MouseEvent   event) throws Exception 
    { 
        if(event.getModifiers()==MouseEvent.BUTTON1_MASK&&event.getClickCount()==2) 
        { 
        	if(!userList.getSelectedValue().toString().equals("0"))
        		
        	{
        		System.out.println("选中客户端"+userList.getSelectedValue().toString());
        	//JOptionPane.showMessageDialog(this, userList.getSelectedValue().toString(), "警告 ",JOptionPane.WARNING_MESSAGE);
        		//SendNum=Integer.parseInt(userList.getSelectedValue().toString());
        		PersonalFrame myFrame=new PersonalFrame(name,userList.getSelectedValue().toString());
        		personalFrames.add(myFrame);
        		//System.out.println(SendNum);
        	}
        	if(userList.getSelectedValue().toString().equals("0"))
        		{
        			System.out.println("选中CA");
        		//SendToCA();
        		}
    		
        } 
    } 
	public static void main(String[] args) throws Exception {
		RSACoder.KeyInit();
		new Client();
	}
}

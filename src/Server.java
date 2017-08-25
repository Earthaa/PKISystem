import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.swing.*;


public class Server extends JFrame implements ActionListener {
	private static final long serialVersionUID = 1L;
	ServerSocket ss = null;
	
	
	
	List<UserInfo> users=new ArrayList<UserInfo>();
	List<String> names = new ArrayList<String>();
	static int count=0;
	private boolean run=true;
	//Design
	private JLabel portLabel=new JLabel("请输入端口号：");
	private JTextField textPort=new JTextField(5);
	private JLabel onlineNum=new JLabel("目前没有用户登录！");
	private DefaultListModel dlm = new DefaultListModel();
	private JList userList=new JList(dlm);
	private JButton Confirm=new JButton("启动");
	private JButton quit =new JButton("停止");

	private void InitFrame(){
		this.getContentPane().setLayout(new BorderLayout());
		JPanel pf=new JPanel(new FlowLayout());
		pf.add(portLabel);
		pf.add(textPort);
		JPanel p=new JPanel(new BorderLayout());
		p.add(pf,BorderLayout.NORTH);
		p.add(onlineNum,BorderLayout.SOUTH);
		add(p,BorderLayout.NORTH);
		add(userList,BorderLayout.CENTER);
		JPanel p2=new JPanel(new FlowLayout(FlowLayout.RIGHT));
		p2.add(quit);
		p2.add(Confirm);
		add(p2,BorderLayout.SOUTH);		
		setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
		setSize(300,500);
		quit.setEnabled(false);
		setVisible(true);
	}
	private void addEvent(){
		Confirm.addActionListener(this);
	}
	public Server() throws Exception{
		InitFrame();
		addEvent();
	}
	@Override
	public void dispose(){
		try {
			stop();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		System.exit(0);
	}
	private  void go() throws Exception{
		System.out.println("server start...");
		ss = new ServerSocket(Integer.parseInt(textPort.getText()));
		while(run){
				Socket socket = ss.accept();
				++count;
				onlineNum.setText("当前在线人数："+count);
				final Socket s = socket;
				new Thread(){
					UserInfo user=null;
					InputStream is=null;
					ObjectInputStream ois=null;
					@Override
					public void run() {
						try {
							boolean flag=true;
							is = s.getInputStream();
							ois = new ObjectInputStream(is);
							while(flag){
								Message msg = (Message)(ois.readObject());
								if(user==null){
									user=new UserInfo(s, msg.getFrom());
									System.out.println(msg.getFrom()+"登陆了！");
									System.out.println(s.getRemoteSocketAddress());
								}
								synchronized (this){
									if(!users.contains(user)){
										users.add(user);
										if(!names.contains(user.getName())){
											names.add(user.getName());
										}
									}
								}
								MessageType type = msg.getMsgType();
								System.out.println("Type: "+type);
								//上线提醒
								if(type.equals(MessageType.Login)){
									//xxx上线啦【2010-6-7 20：10：54】
									String content = msg.getContent();
									msg.setContent(content);
									msg.setNames(names);
									dlm.removeAllElements();
									for(String s:names){
										dlm.addElement(s);
									}
									SendMessageToAll(msg);//发送给所有人
								}else if(type.equals(MessageType.Chat)){
										//String content = msg.getContent();//msg.getFrom()+" "+new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date())+"\n"+msg.getContent();
										//msg.setContent(content);
										//转发给私人
										if(msg.getChatState().equals(ChatState.Personal)){
											SendToPersonal(msg);
										}else{
											SendMessageToAll(msg);
										}
								}else if(type.equals(MessageType.Logout)){
									synchronized (this) {
										names.remove(user.getName());
										users.remove(user);
										count--;
										onlineNum.setText("当前在线人数："+count);
										dlm.removeAllElements();
										for(String s:names){
											dlm.addElement(s);
										}
										String content = msg.getContent();//"【"+msg.getFrom()+"】  "+"下线啦.【"+new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date())+"】";
										msg.setContent(content);
										msg.setNames(names);
										SendMessageToAll(msg);
										flag=false;
									}					
								}
							}
							
						} catch (Exception e) {
							e.printStackTrace();
						}
					
					}

					private synchronized void SendMessageToAll(Message msg) throws Exception{
						for(UserInfo s : users){
								ObjectOutputStream oos = new ObjectOutputStream(s.getSocket().getOutputStream());
								oos.writeObject(msg);
								oos.flush();
						}
					}
					private synchronized void SendToPersonal(Message msg)throws Exception{
						int times=0;
						for(UserInfo s:users){
							if(s.getName().equals(msg.getTo())/*||s.getName().equals(msg.getFrom())*/){
								ObjectOutputStream oos = new ObjectOutputStream(s.getSocket().getOutputStream());
								oos.writeObject(msg);
								oos.flush();
								times++;
								if(times==2)break;
							}
						}
					}
					
				}.start();
		}
	}
	@Override
	public void actionPerformed(ActionEvent e) {
		try{
			String cmd=e.getActionCommand();
			System.out.println(cmd);
			if(cmd.equals("启动")){
				Confirm.setEnabled(false);
				quit.setEnabled(true);
				go();				
			}else if(cmd.equals("停止")){
				stop();
				quit.setEnabled(false);
				Confirm.setEnabled(true);
			}
		}catch(Exception ex){
			
		}
	}
	private void stop() throws Exception{
		if(ss!=null)
			if(!ss.isClosed())
				ss.close();
		run=false;
		String content = "服务器终止服务了.【"+new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date())+"】";
		Message stopMsg=new Message(null, content, MessageType.Logout);
		for(UserInfo s:users){
			stopMsg.setFrom(s.getName());
			ObjectOutputStream oos = new ObjectOutputStream(s.getSocket().getOutputStream());
			oos.writeObject(stopMsg);
			oos.flush();
		}
	}
	public static void main(String[] args) throws Exception {
		new Server();
	}
}
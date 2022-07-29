package com.heavylaw.Alice;

import com.heavylaw.utils.IOUtils;
import com.heavylaw.utils.RSAUtils;

import java.io.File;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.Date;


public class Host {
    private DatagramSocket socket = null;
    private int port = 8888;
    private DatagramPacket receivePacket;

    public Host() throws IOException {
        System.out.println("The server starts listening at port:" + port);
    }

    private void connectTest() throws IOException {
        receivePacket = udpReceive();
        InetAddress ipR = receivePacket.getAddress();
        int portR = receivePacket.getPort();
        System.out.println("Create connection：" + receivePacket.getSocketAddress());
        udpSend("True", ipR, portR);
    }

    private void userVerify() throws Exception {
        String msg, username, pubkey;
        receivePacket = udpReceive();
        InetAddress ipR = receivePacket.getAddress();
        int portR = receivePacket.getPort();
        msg = new String(receivePacket.getData(), 0, receivePacket.getLength(), "utf-8");

        String str = IOUtils.readFile(new File("src/com/heavylaw/Alice/password.txt"));
        String[] strs = str.split(",");
        username = strs[0];

        if (msg.equals(username)) {
            System.out.println("User successfully authenticated.");
            String key = IOUtils.readFile(new File("src/com/heavylaw/Alice/key.pem"));
            String[] keys = key.split("\n");
            pubkey = keys[0];
            System.out.println("Generate NA.");
            String NA = RSAUtils.getRandomString();
            System.out.println("Send public key and NA.");
            udpSend((pubkey + "," + NA), ipR, portR);
            decryptOTP(NA);
        } else {
            udpSend("False", ipR, portR);
        }
    }

    private void decryptOTP(String NA) throws Exception {
        String msg, prikey, otp, hashPW;
        receivePacket = udpReceive();
        InetAddress ipR = receivePacket.getAddress();
        int portR = receivePacket.getPort();
        msg = new String(receivePacket.getData(), 0, receivePacket.getLength(), "utf-8");

        System.out.println("Obtain RSA encryption result: " + msg);

        String key = IOUtils.readFile(new File("src/com/heavylaw/Alice/key.pem"));
        String[] keys = key.split("\n");
        prikey = keys[1];

        String str = IOUtils.readFile(new File("src/com/heavylaw/Alice/password.txt"));
        String[] strs = str.split(",");
        hashPW = strs[1];

        System.out.println("Start decrypt the OTP.");
        otp = RSAUtils.decrypt(msg, prikey);
        System.out.println("Verify the decryption value.");
        if (otp.equals(RSAUtils.sha1(hashPW + NA))){
            System.out.println("Verification succeeded.");
            udpSend("succeeded", ipR, portR);
        } else {
            System.out.println("Verification failed.");
            udpSend("failed", ipR, portR);
        }
        System.out.println("The client from " + receivePacket.getSocketAddress() + " leave.");
    }

    public void service() throws IOException {
        try {
            socket = new DatagramSocket(port);
            System.out.println("Successfully created server at port:" + socket.getLocalPort());

            while (true) {
                connectTest();
                userVerify();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public DatagramPacket udpReceive() throws IOException {
        DatagramPacket receive;
        byte[] dataR = new byte[1024];
        receive = new DatagramPacket(dataR, dataR.length);
        socket.receive(receive);
        return receive;
    }

    public void udpSend(String msg, InetAddress ipRemote, int portRemote) throws IOException {
        DatagramPacket sendPacket;
        byte[] dataSend = msg.getBytes();
        sendPacket = new DatagramPacket(dataSend, dataSend.length, ipRemote, portRemote);
        socket.send(sendPacket);
    }

    public static void main(String[] args) throws IOException {
        new Host().service();
    }
}

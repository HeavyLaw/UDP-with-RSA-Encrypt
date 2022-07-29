package com.heavylaw.Bob;

import com.heavylaw.utils.IOUtils;
import com.heavylaw.utils.RSAUtils;

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.SocketException;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;

import static com.heavylaw.utils.RSAUtils.sha1;

public class Client {
    private int remotePort = 8888;
    private InetAddress remoteIP = InetAddress.getByName("127.0.0.1");
    private DatagramSocket socket;

    private static final int MAX_PACKET_SIZE=65535;

    public Client() throws IOException {
        try {
            socket = new DatagramSocket();
        } catch (SocketException e) {
            e.printStackTrace();
        }

    }

    public void send(String msg) {
        try {
            byte[] outData = msg.getBytes("utf-8");
            DatagramPacket outPacket = new DatagramPacket(outData, outData.length, remoteIP, remotePort);
            socket.send(outPacket);
        }catch (IOException e){
            e.printStackTrace();
        }
    }

    public String receive() {
        String msg;
        DatagramPacket inPacket = new DatagramPacket(new byte[MAX_PACKET_SIZE], MAX_PACKET_SIZE);
        try {
            socket.receive(inPacket);
            msg = new String(inPacket.getData(),0,inPacket.getLength(),"utf-8");
        } catch (IOException e) {
            e.printStackTrace();
            msg = null;
        }
        return msg;
    }

    public void close() {
        if (socket!=null)
            socket.close();
    }

    private void connect() {
        send("connect");
        if (receive().equals("True")) {
            System.out.println("Successfully connect host!");
        } else {
            close();
        }
    }

    private String userVerify() {
        String username;
        Scanner scanner = new Scanner(System.in);
        System.out.println("Enter the username: ");
        username = scanner.nextLine();
        send(username);
        String check = receive();
        if (check.equals("False")) {
            System.out.println("User illegal.");
            System.exit(0);
            return null;
        } else {
            System.out.println("User successfully authenticated, the public key and NA are obtained.");
            return check;
        }
    }

    private String getOTP(String pkNA) throws IOException, NoSuchAlgorithmException {
        String otp, pubkey, NA, password;

        String hashPk = IOUtils.readFile(new File("src/com/heavylaw/Bob/key.pem"));
        String[] pkNAs = pkNA.split(",");
        pubkey = pkNAs[0];
        NA = pkNAs[1];

        System.out.println("Verify public key consistency.");
        if (hashPk.equals(sha1(pubkey))){
            System.out.println("Public key is consistent, generate one-time password.");

            Scanner scanner = new Scanner(System.in);
            System.out.println("Enter the password: ");
            password = scanner.nextLine();
            scanner.close();

            otp = sha1(sha1(password) + NA);
            return otp;
        } else {
            close();
            return null;
        }
    }

    private void sendRSA(String pkNA, String otp) throws Exception {
        String pubkey;
        String[] pkNAs = pkNA.split(",");
        pubkey = pkNAs[0];
        System.out.println("RSA encryption of one-time password with public key.");
        String otpEn = RSAUtils.encrypt(otp, pubkey);
        System.out.println("Send RSA encryption result: " + otpEn);
        send(otpEn);
        System.out.println("Host verification " + receive() + '.');
    }

    public static void main (String[] args) throws Exception {
        Client client = new Client();
        client.connect();
        String pkNA = client.userVerify();
        assert pkNA != null;
        String otp = client.getOTP(pkNA);
        client.sendRSA(pkNA, otp);
        System.out.println("Service finished.");
    }
}

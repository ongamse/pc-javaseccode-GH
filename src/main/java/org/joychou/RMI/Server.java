package org.joychou.RMI;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.RMIClientSocketFactory;
import java.rmi.server.RMIServerSocketFactory;
import java.rmi.server.RMISocketFactory;
import java.rmi.server.UnicastRemoteObject;



public class Server implements Hello {

    private static class LoopbackServerSocketFactory implements RMIServerSocketFactory {
        @Override
        public ServerSocket createServerSocket(int port) throws IOException {
            return new ServerSocket(port, 50, InetAddress.getLoopbackAddress());
        }
    }

    public String sayHello() {
        return "Hello Word!";
    }

    public static void main(String args[]) {

        try {
            Server obj = new Server();
            // Only accept connections on the loopback interface; do not expose RMI to the network.
            RMIClientSocketFactory csf = RMISocketFactory.getDefaultSocketFactory();
            RMIServerSocketFactory ssf = new LoopbackServerSocketFactory();
            Hello stub = (Hello) UnicastRemoteObject.exportObject(obj, 0, csf, ssf);
            Registry registry = LocateRegistry.createRegistry(1099, csf, ssf);
            registry.bind("Hello", stub);
            System.out.println("绑定1099端口成功");
        } catch (Exception e) {
            System.err.println("Server exception: " + e.toString());
            e.printStackTrace();
        }
    }
}


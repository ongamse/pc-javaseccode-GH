package org.joychou.RMI;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.RMIServerSocketFactory;
import java.rmi.server.UnicastRemoteObject;



public class Server implements Hello {

    private static class LoopbackServerSocketFactory implements RMIServerSocketFactory {
        @Override
        public ServerSocket createServerSocket(int port) throws IOException {
            return new ServerSocket(port, 0, InetAddress.getLoopbackAddress());
        }

        @Override
        public boolean equals(Object o) {
            return o instanceof LoopbackServerSocketFactory;
        }

        @Override
        public int hashCode() {
            return LoopbackServerSocketFactory.class.hashCode();
        }
    }

    public String sayHello() {
        return "Hello Word!";
    }

    public static void main(String args[]) {

        try {
            Server obj = new Server();
            // Listen on the loopback interface only so the registry (a JEP 290 deserialization
            // surface) is not reachable from the network.
            RMIServerSocketFactory loopbackOnly = new LoopbackServerSocketFactory();
            Hello stub = (Hello) UnicastRemoteObject.exportObject(obj, 0, null, loopbackOnly);
            LocateRegistry.createRegistry(1099, null, loopbackOnly);
            Registry registry = LocateRegistry.getRegistry();
            registry.bind("Hello", stub);
            System.out.println("绑定1099端口成功");
        } catch (Exception e) {
            System.err.println("Server exception: " + e.toString());
            e.printStackTrace();
        }
    }
}


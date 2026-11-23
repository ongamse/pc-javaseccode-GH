package org.joychou.RMI;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.RMIServerSocketFactory;
import java.rmi.server.UnicastRemoteObject;



public class Server implements Hello {

    public String sayHello() {
        return "Hello Word!";
    }

    public static void main(String args[]) {

        try {
            // Only accept the types needed to bind a Hello stub; reject every other class
            // during deserialization of registry calls (JEP 290 registry filter).
            System.setProperty("sun.rmi.registry.registryFilter",
                    "java.lang.String;java.lang.reflect.Proxy;java.rmi.**;org.joychou.RMI.Hello;!*");

            // Listen on the loopback interface only, so the registry is not reachable remotely.
            RMIServerSocketFactory loopbackFactory = new RMIServerSocketFactory() {
                @Override
                public ServerSocket createServerSocket(int port) throws IOException {
                    return new ServerSocket(port, 50, InetAddress.getLoopbackAddress());
                }
            };

            Server obj = new Server();
            Hello stub = (Hello) UnicastRemoteObject.exportObject(obj, 0, null, loopbackFactory);
            LocateRegistry.createRegistry(1099, null, loopbackFactory);
            Registry registry = LocateRegistry.getRegistry("127.0.0.1", 1099);
            registry.bind("Hello", stub);
            System.out.println("绑定1099端口成功");
        } catch (Exception e) {
            System.err.println("Server exception: " + e.toString());
            e.printStackTrace();
        }
    }
}


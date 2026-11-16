package org.joychou.RMI;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.RMIServerSocketFactory;
import java.rmi.server.UnicastRemoteObject;



public class Server implements Hello {

    private static final class LoopbackSocketFactory implements RMIServerSocketFactory {
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
            // Only accept the types a registry needs, reject any other class during deserialization.
            System.setProperty("sun.rmi.registry.registryFilter",
                    "java.lang.String;java.rmi.Remote;java.rmi.server.RemoteObject;"
                            + "java.rmi.server.RemoteRef;java.rmi.server.UnicastRemoteObject;"
                            + "sun.rmi.server.UnicastRef;sun.rmi.server.Activation*;"
                            + "sun.rmi.registry.RegistryImpl_Stub;org.joychou.RMI.Hello;!*");
            // Bind only to the loopback interface so the registry is not exposed to the network.
            RMIServerSocketFactory loopbackOnly = new LoopbackSocketFactory();
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


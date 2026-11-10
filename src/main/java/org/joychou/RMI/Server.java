package org.joychou.RMI;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.RMIServerSocketFactory;
import java.rmi.server.UnicastRemoteObject;



public class Server implements Hello {

    private static final int RMI_PORT = 1099;

    /**
     * Only accept the types needed to bind a Hello stub; everything else is rejected
     * by the registry deserialization filter (JDK 8u121+).
     */
    private static final String REGISTRY_FILTER =
            "java.lang.String;java.lang.reflect.Proxy;java.rmi.**;sun.rmi.server.**;"
                    + "sun.rmi.transport.**;org.joychou.RMI.*;!*";

    /** Listen on the loopback interface only. */
    private static class LoopbackSocketFactory implements RMIServerSocketFactory {
        @Override
        public ServerSocket createServerSocket(int port) throws IOException {
            return new ServerSocket(port, 0, InetAddress.getLoopbackAddress());
        }
    }

    public String sayHello() {
        return "Hello Word!";
    }

    public static void main(String args[]) {

        try {
            if (System.getProperty("sun.rmi.registry.registryFilter") == null) {
                System.setProperty("sun.rmi.registry.registryFilter", REGISTRY_FILTER);
            }
            RMIServerSocketFactory loopbackFactory = new LoopbackSocketFactory();
            Server obj = new Server();
            Hello stub = (Hello) UnicastRemoteObject.exportObject(obj, 0, null, loopbackFactory);
            Registry registry = LocateRegistry.createRegistry(RMI_PORT, null, loopbackFactory);
            registry.bind("Hello", stub);
            System.out.println("绑定1099端口成功");
        } catch (Exception e) {
            System.err.println("Server exception: " + e.toString());
            e.printStackTrace();
        }
    }
}


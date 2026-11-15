package org.joychou.RMI;

import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;



public class Server implements Hello {

    public String sayHello() {
        return "Hello Word!";
    }

    public static void main(String args[]) {

        try {
            // JEP 290 allowlist filters: reject deserialization of any class that is not needed by
            // the RMI registry / DGC protocol. Must be set before the registry is created.
            if (System.getProperty("sun.rmi.registry.registryFilter") == null) {
                System.setProperty("sun.rmi.registry.registryFilter",
                        "java.lang.String;java.lang.Number;java.rmi.Remote;java.lang.reflect.Proxy;"
                                + "java.rmi.server.UnicastRef;java.rmi.server.RMIClientSocketFactory;"
                                + "java.rmi.server.RMIServerSocketFactory;java.rmi.activation.ActivationID;"
                                + "java.rmi.server.UID;java.rmi.server.ObjID;"
                                + "java.rmi.server.RemoteObjectInvocationHandler;"
                                + "sun.rmi.server.UnicastRef;sun.rmi.transport.LiveRef;"
                                + "sun.rmi.transport.tcp.TCPEndpoint;maxdepth=10;!*");
            }
            if (System.getProperty("sun.rmi.transport.dgcFilter") == null) {
                System.setProperty("sun.rmi.transport.dgcFilter",
                        "java.rmi.server.ObjID;java.rmi.server.UID;java.rmi.dgc.VMID;java.rmi.dgc.Lease;"
                                + "maxdepth=5;!*");
            }
            Server obj = new Server();
            Hello stub = (Hello) UnicastRemoteObject.exportObject(obj, 0);
            LocateRegistry.createRegistry(1099);
            Registry registry = LocateRegistry.getRegistry();
            registry.bind("Hello", stub);
            System.out.println("绑定1099端口成功");
        } catch (Exception e) {
            System.err.println("Server exception: " + e.toString());
            e.printStackTrace();
        }
    }
}


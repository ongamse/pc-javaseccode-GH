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
            Server obj = new Server();
            Hello stub = (Hello) UnicastRemoteObject.exportObject(obj, 0);
            // Restrict what the registry will deserialize (JEP 290 registry filter, Java 8u121+):
            // only the types needed for bind/lookup are allowed, everything else is rejected.
            System.setProperty("sun.rmi.registry.registryFilter",
                    "java.rmi.Remote;java.rmi.server.RemoteObject;java.rmi.server.RemoteRef;"
                            + "java.rmi.server.UnicastRemoteObject;sun.rmi.server.UnicastRef;"
                            + "sun.rmi.transport.LiveRef;sun.rmi.transport.tcp.TCPEndpoint;"
                            + "java.lang.String;java.rmi.server.ObjID;java.rmi.server.UID;"
                            + "org.joychou.RMI.Hello;java.lang.reflect.Proxy;"
                            + "java.rmi.server.RemoteObjectInvocationHandler;!*");
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


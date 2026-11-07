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
            // JEP 290 registry deserialization allowlist (must be set before the registry class is initialised).
            // Only the types needed to bind/lookup the Hello stub are accepted; everything else ("!*") is rejected,
            // so a malicious bind()/rebind() cannot deserialize gadget chains into this JVM.
            System.setProperty("sun.rmi.registry.registryFilter",
                    "java.lang.String;java.lang.Number;java.rmi.Remote;java.lang.reflect.Proxy;"
                            + "java.rmi.server.UnicastRef;java.rmi.server.RMIClientSocketFactory;"
                            + "java.rmi.server.RemoteObject;java.rmi.server.RemoteObjectInvocationHandler;"
                            + "java.rmi.server.UID;java.rmi.activation.ActivationID;java.rmi.MarshalledObject;"
                            + "org.joychou.RMI.Hello;!*");
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


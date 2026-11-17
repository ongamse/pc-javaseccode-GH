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
            // Only allow the types a registry legitimately needs (String, Remote and proxies); reject everything
            // else so a crafted bind/rebind/lookup payload cannot trigger gadget-chain deserialization.
            System.setProperty("sun.rmi.registry.registryFilter",
                    "java.lang.String;java.lang.Number;java.rmi.Remote;java.lang.reflect.Proxy;"
                            + "java.rmi.server.UnicastRef;java.rmi.activation.ActivationId;"
                            + "java.rmi.server.UID;java.rmi.server.RMIClientSocketFactory;"
                            + "java.rmi.server.RemoteObject;sun.rmi.server.*;sun.rmi.transport.*;"
                            + "java.rmi.server.ObjID;"
                            + "org.joychou.RMI.*;!*");
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


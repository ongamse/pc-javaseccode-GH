package org.joychou.RMI;

import java.io.ObjectInputFilter;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;



public class Server implements Hello {

    public String sayHello() {
        return "Hello Word!";
    }

    public static void main(String args[]) {

        try {
            // Set a global deserialization filter to restrict RMI attack surface
            ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
                    "org.joychou.RMI.*;java.lang.*;java.rmi.**;!*"
            );
            ObjectInputFilter.Config.setSerialFilter(filter);

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


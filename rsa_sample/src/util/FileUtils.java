package util;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

public class FileUtils {
	 /** 
     * 将指定的对象写入指定的文件中 
     *  
     * @param file 
     *            指定写入的文件 
     * @param objs 
     *            要写入的对象 
     */  
    public static void doObjToFile(String file, Object[] objs) {  
        ObjectOutputStream oos = null;  
        try {  
            FileOutputStream fos = new FileOutputStream(file);  
            oos = new ObjectOutputStream(fos);  
            for (int i = 0; i < objs.length; i++) {  
                oos.writeObject(objs[i]);  
            }  
        } catch (Exception e) {  
            e.printStackTrace();  
        } finally {  
            try {  
                oos.close();  
            } catch (IOException e) {  
                e.printStackTrace();  
            }  
        }  
    } 
    
    /** 
     * 返回在文件中指定位置的对象 
     *  
     * @param file 
     *            指定的文件 
     * @param i 
     *            读取位置
     * @return 
     */  
    public static Object getObjFromFile(String file, int i) {  
        ObjectInputStream ois = null;  
        Object obj = null;  
        try {  
            FileInputStream fis = new FileInputStream(file);  
            ois = new ObjectInputStream(fis);  
            for (int j = 0; j < i; j++) {  
                obj = ois.readObject();  
            }  
        } catch (Exception e) {  
            e.printStackTrace();  
        } finally {  
            try {  
                ois.close();  
            } catch (IOException e) {  
                e.printStackTrace();  
            }  
        }  
        return obj;  
    }  
}

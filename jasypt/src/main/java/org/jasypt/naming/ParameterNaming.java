package org.jasypt.naming;

public class ParameterNaming {

    public static final String PBE_PASSWORD_SYSTEM_PROPERTY =
        "jasenc.pbe.password";
    public static final String PBE_PASSWORD_ENV_VARIABLE =
        "JASENC_PBE_PASSWORD";

    
    public static final String PBE_PASSWORD_SYSTEM_PROPERTY_PREFIX = "jasenc.";
    public static final String PBE_PASSWORD_ENV_VARIABLE_PREFIX = "JASENC_";
    
    public static final String PBE_PASSWORD_SYSTEM_PROPERTY_SUFFIX = 
        ".password";
    public static final String PBE_PASSWORD_ENV_VARIABLE_SUFFIX = 
        "_PASSWORD";
    
    
    private ParameterNaming() {}
    
}

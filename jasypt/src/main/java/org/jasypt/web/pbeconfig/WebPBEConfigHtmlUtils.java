/*
 * =============================================================================
 * 
 *   Copyright (c) 2007, The JASYPT team (http://www.jasypt.org)
 * 
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 * 
 *       http://www.apache.org/licenses/LICENSE-2.0
 * 
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 * 
 * =============================================================================
 */
package org.jasypt.web.pbeconfig;

import java.util.Iterator;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.jasypt.encryption.pbe.config.WebPBEConfig;
import org.jasypt.exceptions.EncryptionInitializationException;

/**
 * <p>
 *   HTML creation class for internal use of {@link WebPBEConfigServlet} and
 *   {@link WebPBEConfigFilter}.
 * </p>
 * 
 * @since 1.3
 * 
 * @author Daniel Fern&aacute;ndez Garrido
 *
 */
class WebPBEConfigHtmlUtils {
    
    public static final String PASSWORD_SETTING_FLAG = "jasyptPwSetting";
    public static final String VALIDATION_PREFIX = "jasyptVa";
    public static final String PASSWORD_PREFIX = "jasyptPw";
    public static final String PASSWORD_RETYPED_PREFIX = "jasyptRPw";
    
    private static final String HTTPS_SCHEME = "https";
    
    
    private WebPBEConfigHtmlUtils() {
        super();
    }
    
    
    
    public static String createConfigurationDoneHtml() {
        
        StringBuffer strBuff = new StringBuffer();
        addHeader(strBuff);
        strBuff.append("   <h2>All Configuration Done</h2>\n");
        addFoot(strBuff);
        return strBuff.toString();
        
    }
    
    

    
    
    public static String createInputFormHtml(
            HttpServletRequest request, boolean inputError) {

        WebPBEConfigRegistry registry = WebPBEConfigRegistry.getInstance();
        List configs = registry.getConfigs();
        
        StringBuffer strBuff = new StringBuffer();
        addHeader(strBuff);
        
        strBuff.append("   <h2>Please enter the PBE configuration parameters</h2>\n");

        if (!HTTPS_SCHEME.equals(request.getScheme().toLowerCase())) {
            strBuff.append("   <div class=\"warning\">WARNING: NOT IN SECURE MODE (HTTPS)</div>\n");
        }
        
        if (inputError) {
            strBuff.append("   <div class=\"warning\">Validation error!</div>\n");
        }
        
        strBuff.append("   <form action=\"" + request.getRequestURI() + "\" method=\"POST\">\n");
        strBuff.append("    <div>\n");
        
        Iterator configsIter = configs.iterator();
        int i = 0;
        while (configsIter.hasNext()) {
            
            WebPBEConfig config = 
                (WebPBEConfig) configsIter.next();
            
            if (!config.isComplete()) {
                throw new EncryptionInitializationException("Incomplete " +
                        "WebPBEConfig object: all configs must specify " +
                        "both a name and a validation word");
            }
            
            strBuff.append("     <fieldset>\n");
            strBuff.append("      <legend>" + config.getName() + "</legend>\n");
            strBuff.append("      <label for=\"" + VALIDATION_PREFIX + i + "\">Validation word</label>: <input type=\"password\" name=\"" + VALIDATION_PREFIX + i + "\" />\n");
            strBuff.append("      <br /><br />\n");
            strBuff.append("      <label for=\"" + PASSWORD_PREFIX + i + "\">Password</label>: <input type=\"password\" name=\"" + PASSWORD_PREFIX + i + "\" />\n");
            strBuff.append("      <br /><br />\n");
            strBuff.append("      <label for=\"" + PASSWORD_RETYPED_PREFIX + i + "\">Retype password</label>: <input type=\"password\" name=\"" + PASSWORD_RETYPED_PREFIX + i + "\" />\n");
            strBuff.append("     </fieldset>\n");
            i++;
            
        }
        
        strBuff.append("    </div>\n");
        strBuff.append("    <div id=\"button\">\n");
        strBuff.append("     <input type=\"hidden\" name=\"" + PASSWORD_SETTING_FLAG + "\" value=\"true\" />\n");
        strBuff.append("     <input type=\"submit\" value=\"Submit\" />\n");
        strBuff.append("    </div>\n");
        strBuff.append("   </form>\n");
        
        addFoot(strBuff);
        return strBuff.toString();
    }
    
    
    public static String createNotInitializedHtml() {
        
        StringBuffer strBuff = new StringBuffer();
        strBuff.append("<html>\n");
        strBuff.append(" <head>\n");
        strBuff.append("  <title>Forbidden</title>\n");
        strBuff.append(" </head>\n");
        strBuff.append(" <body>\n");
        strBuff.append("   <h1>Access Forbidden</h1>\n");
        strBuff.append(" </body>\n");
        strBuff.append("</html>\n");
        return strBuff.toString();
        
    }
    
    
    
    private static void addHeader(StringBuffer strBuff) {
        strBuff.append("<html>\n");
        strBuff.append(" <head>\n");
        strBuff.append("  <title>Web Password Based Encryption Configuration</title>\n");
        strBuff.append("  <style type=\"text/css\">");
        strBuff.append("   html { background-color: #ccc; text-align: center; margin: 0px; padding: 0px;} body {text-align:center;} #page { width: 700px; background-color: white; margin-top: 10px; margin-left: auto; margin-right: auto; padding: 10px; border: 1px solid #000; text-align: left;} h1 { text-weight: bold;} #button { text-align: center; margin-top: 20px; } fieldset { margin-bottom: 20px; } label { font-style: italic; } legend { font-weight: bold; } div.warning { border: 1px dotted #000; margin: 15px; padding: 5px; background-color: eee; font-weight: bold; }");
        strBuff.append("  </style>\n");
        strBuff.append(" </head>\n");
        strBuff.append(" <body>\n");
        strBuff.append("  <div id=\"page\">\n");
        strBuff.append("   <h1>Web PBE Configuration</h1>\n");
    }
    
    private static void addFoot(StringBuffer strBuff) {
        strBuff.append("  </div>\n");
        strBuff.append(" </body>\n");
        strBuff.append("</html>\n");
    }
    
}

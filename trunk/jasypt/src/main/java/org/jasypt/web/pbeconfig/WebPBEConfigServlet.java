/*
 * =============================================================================
 * 
 *   Copyright (c) 2007-2008, The JASYPT team (http://www.jasypt.org)
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

import java.io.IOException;
import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Iterator;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.jasypt.commons.CommonUtils;
import org.jasypt.encryption.pbe.config.WebPBEConfig;

/**
 * <p>
 *   Servlet for web PBE config processing.
 * </p>
 * <p>
 *   This servlet's URL should be called by the webapp administrator at deploy
 *   time, for setting the passwords of all the PBE encryptors which have
 *   been previously assigned a {@link WebPBEConfig} configuration object.
 * </p>
 * <p>
 *   If web PBE configuration has not been done yet, it will show the user a
 *   form containing two inputs for each encryptor: the <i>validation word</i>
 *   and the <i>password</i> (retyped).
 * </p>
 * <ul>
 *   <li>The <i>validation word</i> must be input to the value set on the 
 *       {@link WebPBEConfig} object with its <tt>setValidationWord(...)</tt>
 *       method. This will ensure that only an authorized person will set
 *       the encryption passwords.</li>.
 *   <li>The <i>password</i> (retyped) must be input to the value which is
 *       desired to be the encryption password for each specific encryptor.</li> 
 * </ul>
 * <p>
 *   An example <tt>web.xml</tt> fragment:
 * </p>
 * <pre>
 *  &lt;servlet>
 *    &lt;servlet-name>webPBEConfigServlet&lt;/servlet-name>
 *    &lt;servlet-class>
 *      org.jasypt.web.pbeconfig.WebPBEConfigServlet
 *    &lt;/servlet-class>
 *    &lt;load-on-startup>1&lt;/load-on-startup>
 *  &lt;/servlet>
 *
 *  &lt;servlet-mapping>
 *    &lt;servlet-name>webPBEConfigServlet&lt;/servlet-name>
 *    &lt;url-pattern>/webPBEConfig.do&lt;/url-pattern>
 *  &lt;/servlet-mapping>
 * </pre>
 * <p>
 *   If this servlet's context is set a logger, it will output messages for
 *   both successful and failed attempts to set passwords, including
 *   date, time and originating IP address. 
 * </p>
 * 
 * @since 1.3
 * 
 * @author Daniel Fern&aacute;ndez
 *
 */
public class WebPBEConfigServlet extends HttpServlet {

    private static final long serialVersionUID = -7201635392816652667L;

    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        execute(req, resp);
    }

    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        execute(req, resp);
    }

    private void execute(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {

        try {
            
            WebPBEConfigRegistry registry = WebPBEConfigRegistry.getInstance();

            if (registry.isWebConfigurationDone()) {
                
                // Configuration was already done, display an "Already done" page
                writeResponse(
                        WebPBEConfigHtmlUtils.createConfigurationDoneHtml(), 
                        resp);
                
            } else {
                
                String settingFlag = 
                    req.getParameter(WebPBEConfigHtmlUtils.PASSWORD_SETTING_FLAG);
                if (CommonUtils.isEmpty(settingFlag)) {

                    // We are first arriving at the form, just show it
                    writeResponse(
                            WebPBEConfigHtmlUtils.createInputFormHtml(req, false), 
                            resp);
                    
                } else {

                    /*
                     * The form was already shown and submitted, so we must
                     * process the results.
                     */
                    
                    List configs = registry.getConfigs();
                    Iterator configsIter = configs.iterator();
                    int i = 0;
                    int valid = 0;
                    while (configsIter.hasNext()) {

                        WebPBEConfig config = (WebPBEConfig) configsIter.next();
                        
                        String validation = 
                            req.getParameter(WebPBEConfigHtmlUtils.VALIDATION_PREFIX + i);
                        String password = 
                            req.getParameter(WebPBEConfigHtmlUtils.PASSWORD_PREFIX + i);
                        String retypedPassword = 
                            req.getParameter(WebPBEConfigHtmlUtils.PASSWORD_RETYPED_PREFIX + i);
                        
                        if (!CommonUtils.isEmpty(validation) &&
                            !CommonUtils.isEmpty(password)   &&
                            password.equals(retypedPassword)   &&
                            (config.getValidationWord().equals(validation))) {
                            /*
                             * Passwords will not be set here, instead, we will
                             * wait until ALL the passwords are set correctly,
                             * to avoid a partial initialization.
                             */
                            valid++;
                        }
                    
                        i++;
                        
                    }

                    SimpleDateFormat dateFormat = new SimpleDateFormat();
                    Calendar now = Calendar.getInstance();
                    
                    if (valid < configs.size()) {

                        /*
                         * Bad attempt: log and show error.
                         */
                        
                        this.getServletContext().log(
                                "Failed attempt to set PBE Configuration from " +
                                req.getRemoteAddr() + 
                                " [" + dateFormat.format(now.getTime()) + "]");
                        
                        writeResponse(
                                WebPBEConfigHtmlUtils.createInputFormHtml(req, true), 
                                resp);
                        
                    } else {

                        /*
                         * Success: log, set passwords and show success page.
                         */
                        
                        configsIter = configs.iterator();
                        i = 0;
                        while (configsIter.hasNext()) {
                            WebPBEConfig config = (WebPBEConfig) configsIter.next();
                            String password = 
                                req.getParameter(WebPBEConfigHtmlUtils.PASSWORD_PREFIX + i);
                            config.setPassword(password);
                            i++;
                        }
                        
                        registry.setWebConfigurationDone(true);

                        this.getServletContext().log(
                                "PBE Configuration succesfully set from " +
                                req.getRemoteAddr() + 
                                " [" + dateFormat.format(now.getTime()) + "]");
                        
                        writeResponse(
                                WebPBEConfigHtmlUtils.createConfigurationDoneHtml(), 
                                resp);
                        
                    }
                    
                }
                
            }
            
        } catch (IOException e) {
            this.getServletContext().log(
                    "Exception raised during servlet execution", e);
            throw e;
        } catch (Throwable t) {
            this.getServletContext().log(
                    "Exception raised during servlet execution", t);
            throw new ServletException(t);
        }

    }

    
    
    private void writeResponse(String html, HttpServletResponse response)
            throws IOException {
        PrintWriter printWriter = response.getWriter();
        printWriter.write(html);
        printWriter.flush();
    }
    
}

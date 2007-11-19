@ECHO OFF
IF "%OS%" == "Windows_NT" setlocal

set SCRIPT_NAME=decrypt
set EXECUTABLE_CLASS=org.jasypt.intf.cli.JasyptPBEStringDecryptionCLI
set CURRENT_DIR=%cd%
set CLASSPATH=%CURRENT_DIR%\jasypt-cli-bundle.jar

set JAVA_EXECUTABLE=java
if "%JAVA_HOME%" == "" goto execute
set JAVA_EXECUTABLE="%JAVA_HOME%\bin\java"

:execute
%JAVA_EXECUTABLE% %EXECUTABLE_CLASS% %SCRIPT_NAME% %*


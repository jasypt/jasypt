@ECHO OFF
IF "%OS%" == "Windows_NT" setlocal ENABLEDELAYEDEXPANSION

set SCRIPT_NAME=digest.bat
cd %0\..
cd ..
set EXECUTABLE_CLASS=org.jasypt.intf.cli.JasyptStringDigestCLI
set EXEC_CLASSPATH=.
FOR %%c in (.\lib\*.jar) DO set EXEC_CLASSPATH=!EXEC_CLASSPATH!;%%c

echo USING CLASSPATH: %EXEC_CLASSPATH%

set JAVA_EXECUTABLE=java
if "%JAVA_HOME%" == "" goto execute
set JAVA_EXECUTABLE="%JAVA_HOME%\bin\java"

:execute
%JAVA_EXECUTABLE% -classpath %EXEC_CLASSPATH% %EXECUTABLE_CLASS% %SCRIPT_NAME% %*

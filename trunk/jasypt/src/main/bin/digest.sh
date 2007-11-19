#/bin/sh


SCRIPT_NAME=digest
EXECUTABLE_CLASS=org.jasypt.intf.cli.JasyptStringDigestCLI
CURRENT_DIR=$cd
CLASSPATH=$CURRENT_DIR\jasypt-cli-bundle.jar

JAVA_EXECUTABLE=java
if "%JAVA_HOME%" == "" goto execute
set JAVA_EXECUTABLE="%JAVA_HOME%\bin\java"

$JAVA_EXECUTABLE $EXECUTABLE_CLASS $SCRIPT_NAME $*


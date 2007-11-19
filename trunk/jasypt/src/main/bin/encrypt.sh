#!/bin/sh

SCRIPT_NAME=encrypt
EXECUTABLE_CLASS=org.jasypt.intf.cli.JasyptPBEStringEncryptionCLI
CURRENT_DIR=$PWD
CLASSPATH=.:$CLASSPATH:$CURRENT_DIR/jasypt-cli-bundle.jar

JAVA_EXECUTABLE=java
if [ "$JAVA_HOME" != "" ]
then
  $JAVA_EXECUTABLE=$JAVA_HOME/bin/java
fi

$JAVA_EXECUTABLE -classpath $CLASSPATH $EXECUTABLE_CLASS $SCRIPT_NAME $@


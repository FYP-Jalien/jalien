#!/bin/bash

export PATH="$PATH:$HOME/alien/bin:$HOME/alien/api/bin"
export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:$HOME/alien/lib:$HOME/alien/api/lib"

CLASSPATH=bin:build_eclipse

for jar in lib/*.jar; do
    CLASSPATH="$CLASSPATH:$jar"
done

export CLASSPATH

java \
	-server \
	-Xms1G -Xmx1G \
	-XX:+UseG1GC \
	-XX:+DisableExplicitGC \
	-XX:+AggressiveOpts \
	-XX:+OptimizeStringConcat \
	-XX:MaxTrivialSize=1K \
	-XX:CompileThreshold=20000 \
	-Duserid=$(id -u) \
	-Dcom.sun.jndi.ldap.connect.pool=false \
	"$@"

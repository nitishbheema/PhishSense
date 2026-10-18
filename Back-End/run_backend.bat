@echo off
set "JAVA_HOME=C:\Users\Nitish\.jdks\jbr-17.0.14"
set "PATH=%JAVA_HOME%\bin;C:\maven\bin;%PATH%"
cd /d "d:\MAJOR\Back-End"
echo [Spring Boot] Launching with Java 17...
call C:\maven\bin\mvn.cmd spring-boot:run

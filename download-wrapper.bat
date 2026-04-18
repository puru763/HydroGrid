@echo off
echo Downloading Maven Wrapper JAR...

powershell -Command "&{$webclient = new-object System.Net.WebClient; $webclient.DownloadFile('https://repo.maven.apache.org/maven2/org/apache/maven/wrapper/maven-wrapper/3.1.0/maven-wrapper-3.1.0.jar', '.mvn\wrapper\maven-wrapper.jar')}"

if exist ".mvn\wrapper\maven-wrapper.jar" (
    echo Download completed successfully!
    echo You can now run: mvnw.cmd spring-boot:run -pl hydrogrid-gateway
) else (
    echo Download failed. Please check your internet connection.
)

pause

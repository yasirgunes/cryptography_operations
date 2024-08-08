FROM openjdk:17
WORKDIR /app
COPY /target/eCardProject-1.0-SNAPSHOT-jar-with-dependencies.jar app.jar
EXPOSE 8080
CMD ["java", "-jar", "app.jar"]
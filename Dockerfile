# Use an official Maven image to build the project
FROM maven:3.8.5-openjdk-17-slim AS build

# Set the working directory in the container
WORKDIR /app

# Copy the pom.xml file and the source code to the container
COPY pom.xml .
COPY src ./src

# Build the project
RUN mvn clean package -DskipTests

# Use an official OpenJDK runtime as a parent image
FROM openjdk:17-jdk-slim

# Set the working directory in the container
WORKDIR /app

# Copy the JAR file from the build stage (use the correct name of your shaded JAR file)
COPY --from=build /app/target/eCardProject-1.0-SNAPSHOT-shaded.jar /app/eCardProject.jar

# Expose the port your application runs on (if applicable)
EXPOSE 8080

# Run the JAR file
ENTRYPOINT ["java", "-jar", "eCardProject.jar"]

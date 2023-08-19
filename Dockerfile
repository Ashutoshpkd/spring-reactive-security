# Stage 1: Build Maven artifacts
FROM maven:3.8.4-openjdk-17 as builder

# Set the working directory inside the container
WORKDIR /app

# Copy the pom.xml to take advantage of Docker caching for dependencies
COPY pom.xml .

# Download the Maven dependencies for faster rebuilds
RUN mvn dependency:go-offline

# Copy the rest of the source code
COPY src/ src/

# Build the application
RUN mvn clean install -DskipTests

# Stage 2: Create the final Docker image
FROM openjdk:17-jdk-slim

# Set the working directory inside the container
WORKDIR /app

# Copy the Spring Reactive application JAR from the previous stage
COPY --from=builder /app/target/*.jar /app/app.jar

# Expose the port that your Spring Reactive application uses
EXPOSE 8080

# Command to run your Spring Reactive application using the JAR file
CMD ["java", "-jar", "app.jar"]

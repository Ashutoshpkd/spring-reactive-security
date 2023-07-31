FROM openjdk:20-ea-4-jdk
# Use the official OpenJDK base image
# Set the working directory inside the container
WORKDIR /app

# Copy the Spring Reactive application JAR file to the container
COPY target/*.jar /app/app.jar

# Expose the port that your Spring Reactive application uses
EXPOSE 8080

# Command to run your Spring Reactive application using the JAR file
CMD ["java", "-jar", "/app/app.jar"]

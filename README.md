## Run locally

### Prerequisites
Local installation of: 
- Java 21
- Maven
- Docker

Start Redis with Bloom Filter Extension:
1. `docker run --name redis-bloom -p 6380:6379 -d redislabs/rebloom:latest`

Start Spring Boot
1. `mvn clean install`
2. `mvn spring-boot:run`

Run unit tests:
1. `mvn test`
2. generated coverage report: `target/site/jacoco/index.html`

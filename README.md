# Known keys
According to https://certificate.transparency.dev/, 11 billion certificates have been registered in the Certificate Transparency initiative. 

## Run locally

### Prerequisites
Local installation of: 
- Java 21
- Maven
- Docker

### Start Redis with Bloom Filter Extension:
1. `docker run --name redis-bloom -p 6380:6379 -d redislabs/rebloom:latest`

### Start Spring Boot
1. `mvn clean install`
2. `mvn spring-boot:run`

### Run unit tests:
1. `mvn test`
2. generated coverage report: `target/site/jacoco/index.html`

### Swagger UI:
http://localhost:8080/swagger-ui/

Insert a large amount of keys:
1. `git clone git@github.com:badkeys/debianopenssl.git <directory>` 
2. `/bin/bash insert_keys.sh`

### Test with SSH
- ssh-keygen -t rsa -b 2048 -m PEM

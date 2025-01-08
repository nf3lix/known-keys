# Known keys
According to https://certificate.transparency.dev/, 11 billion certificates have been registered in the Certificate Transparency initiative. 

## Run locally
Requires local installation of Docker.

### Run with docker compose
1. `docker-compose up -d`
2. Access [Swagger UI](http://localhost:8080/swagger-ui/)

### Run with docker and maven (optional)
1. `docker run --name redis-bloom -p 6380:6379 -d redislabs/rebloom:latest`
2. `mvn clean install`
3. `mvn spring-boot:run`
4. Access [Swagger UI](http://localhost:8080/swagger-ui/)

Run unit tests:
1. `mvn test`
2. generated coverage report: `target/site/jacoco/index.html`

Insert a large amount of keys:
1. `git clone git@github.com:badkeys/debianopenssl.git <directory>` 
2. `/bin/bash insert_keys.sh`

### Test with SSH
- ssh-keygen -t rsa -b 2048 -m PEM

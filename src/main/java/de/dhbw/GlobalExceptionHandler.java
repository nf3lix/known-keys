package de.dhbw;

import org.bouncycastle.openssl.PEMException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.multipart.support.MissingServletRequestPartException;

@ControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    /*
    @ExceptionHandler(PEMException.class)
    public ResponseEntity<String> handlePEMException(final PEMException e) {
        logger.error(e.getMessage());
        return ResponseEntity.badRequest().body("Invalid key file provided.");
    }

    @ExceptionHandler(MissingServletRequestPartException.class)
    public ResponseEntity<String> handleMissingServletRequestPartException(final MissingServletRequestPartException e) {
        logger.error(e.getMessage());
        return ResponseEntity.badRequest().body("Invalid key file provided.");
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<String> handleException(final Exception e) {
        logger.error(e.getMessage());
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("An unexpected error occurred.");
    }*/

}

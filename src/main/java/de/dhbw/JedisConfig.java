package de.dhbw;

import io.rebloom.client.Client;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;
import redis.clients.jedis.JedisPoolConfig;

@Configuration
public class JedisConfig {

    private static final Logger logger = LoggerFactory.getLogger(JedisConfig.class);

    @Bean
    public JedisPool jedisPool(@Value("${redis.host}") String redisHost,
                               @Value("${redis.port}") int redisPort) {
        JedisPoolConfig conf = new JedisPoolConfig();
        conf.setMaxTotal(100);
        conf.setTestOnBorrow(false);
        conf.setTestOnReturn(false);
        conf.setTestOnCreate(false);
        conf.setTestWhileIdle(false);
        conf.setNumTestsPerEvictionRun(-1);
        conf.setFairness(true);
        conf.setJmxEnabled(false);
        return new JedisPool(conf, redisHost, redisPort, 30000);
    }

    @Bean
    public Client bloomFilterClient(JedisPool jedisPool) {
        return new Client(jedisPool);
    }

    @Bean
    public ApplicationRunner jedisPoolChecker(JedisPool jedisPool) {
        return args -> {
            try (Jedis jedis = jedisPool.getResource()) {
                if (jedis.ping().equalsIgnoreCase("PONG")) {
                    logger.info("Redis available");
                } else {
                    throw new RuntimeException("Failed to connect to Redis.");
                }
            } catch (Exception e) {
                throw new RuntimeException("Failed to connect to Redis.", e);
            }
        };
    }

}

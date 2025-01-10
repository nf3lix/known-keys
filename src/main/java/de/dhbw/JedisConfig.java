package de.dhbw;

import io.rebloom.client.Client;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import redis.clients.jedis.JedisPool;
import redis.clients.jedis.JedisPoolConfig;

@Configuration
public class JedisConfig {

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

}

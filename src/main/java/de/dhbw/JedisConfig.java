package de.dhbw;

import io.rebloom.client.Client;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import redis.clients.jedis.JedisPool;
import redis.clients.jedis.JedisPoolConfig;

@Configuration
public class JedisConfig {

    public final static String RSA_BLOOM_FILTER_NAME = "rsa_modulus";
    public final static String EC_BLOOM_FILTER_NAME = "ec_public_point";
    public final static String EDEC_BLOOM_FILTER_NAME = "edec_public_point";

    @Value("${redis.host}")
    private String redisHost;

    @Value("${redis.port}")
    private int redisPort;

    @Bean
    public JedisPool jedisPool() {
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
        final Client bloomFilterClient = new Client(jedisPool);
        try {
            bloomFilterClient.createFilter(RSA_BLOOM_FILTER_NAME, 1_000_000_000L, 0.01);
            bloomFilterClient.createFilter(EC_BLOOM_FILTER_NAME, 1_000_000_000L, 0.01);
            bloomFilterClient.createFilter(EDEC_BLOOM_FILTER_NAME, 1_000_000_000L, 0.01);
        } catch (Exception e) {
            System.out.println("Bloom filter already exists");
        }
        return bloomFilterClient;
    }

}

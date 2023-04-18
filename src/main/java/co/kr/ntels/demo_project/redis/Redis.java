package co.kr.ntels.demo_project.redis;

import co.kr.ntels.demo_project.security.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import java.util.concurrent.TimeUnit;

@Component
@RequiredArgsConstructor
public class Redis {
    private final RedisTemplate<String, Object> redisTemplate;

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    public String getValueByKey(String key){
        return (String) redisTemplate.opsForValue().get(key);
    }

    public boolean setRedis(String key, String value, int timeOut ){
        try {
            redisTemplate.opsForValue().set(key, value, timeOut, TimeUnit.MILLISECONDS);
            return true;
        } catch (Exception e){
            logger.error("Redis Set Faile!");
            return false;
        }
    }

    public boolean deleteByKey(String key){
        try{
            redisTemplate.delete(key);
            return true;
        } catch (Exception e){
            logger.error("Redis delete Faile!");
            return false;
        }
    }
}


package co.kr.ntels.demo_project.aop;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Pointcut;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component
@Aspect
public class LoggingAspect {

    private static final Logger log = LoggerFactory.getLogger(LoggingAspect.class);

    @Pointcut("execution(public * co.kr.ntels..*Controller.*(..))")
    public void onRequest() {}

    @Around("onRequest()")
    public Object doLogging(ProceedingJoinPoint pjp) throws Throwable{
        String methodName = pjp.getSignature().getName();
        String className = pjp.getTarget().getClass().getName();
        log.info("Method {} in class {} is invoked.", methodName, className);

        Object result = pjp.proceed();

        log.info("Method {} in class {} has finished executing with result {}.", methodName, className, result);
        return result;
    }

}

